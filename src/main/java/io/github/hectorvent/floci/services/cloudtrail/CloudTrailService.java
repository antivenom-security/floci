package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsEndpoints;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsRegions;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.RequestIdFilter;
import io.github.hectorvent.floci.core.common.ServiceCallAuthorizer;
import io.github.hectorvent.floci.core.common.ServicePrincipals;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.cloudtrail.model.AdvancedEventSelector;
import io.github.hectorvent.floci.services.cloudtrail.model.AdvancedFieldSelector;
import io.github.hectorvent.floci.services.cloudtrail.model.DataResource;
import io.github.hectorvent.floci.services.cloudtrail.model.EventSelector;
import io.github.hectorvent.floci.services.cloudtrail.model.Trail;
import io.github.hectorvent.floci.services.cloudtrail.record.CloudTrailEvent;
import io.github.hectorvent.floci.services.cloudtrail.record.CloudTrailRecordBuilder;
import io.github.hectorvent.floci.services.cloudtrail.record.TlsDetails;
import io.github.hectorvent.floci.services.cloudtrail.record.UserIdentityBuilder;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.quarkus.runtime.annotations.RegisterForReflection;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

@ApplicationScoped
public class CloudTrailService {

    private static final Logger LOG = Logger.getLogger(CloudTrailService.class);

    private static final String S3_EVENT_SOURCE = ServicePrincipals.of("s3");
    static final int MAX_PENDING_RECORDS_PER_TRAIL = 1024;
    static final long MAX_PENDING_BYTES_PER_TRAIL = 4L * 1024L * 1024L;
    static final long MAX_LOG_FILE_BYTES = 50L * 1024L * 1024L;
    private static final int LOG_FILE_ENVELOPE_BYTES = 64;

    private final AccountAwareStorageBackend<CloudTrailEntry> store;
    private final RegionResolver regionResolver;
    private final ObjectMapper mapper;
    private final CloudTrailRecordBuilder recordBuilder;
    private final UserIdentityBuilder userIdentityBuilder;
    private final ServiceCallAuthorizer serviceCallAuthorizer;
    private volatile Runnable bufferFullListener = () -> { };
    private final CloudTrailEventBridgeForwarder eventBridge;

    /** Per-trail pending record buffers: ephemeral, never persisted. */
    private final ConcurrentHashMap<PendingTrailKey, PendingRecordBuffer> pendingRecordsByTrail =
            new ConcurrentHashMap<>();

    /**
     * Backs {@link #withTrailLock}: serializes read-modify-write mutations to the same trail. A
     * plain {@code get} then {@code put} on the store is not atomic across the pair, so two
     * overlapping mutations of the same trail, even from different actions, e.g. AddTags racing
     * StartLogging, can interleave such that the second {@code put} replaces the whole entry the
     * first read, silently discarding whatever the first call changed.
     */
    private final ConcurrentHashMap<String, Object> trailLocks = new ConcurrentHashMap<>();

    CloudTrailService(StorageFactory storageFactory, RegionResolver regionResolver,
                      IamService iamService, ObjectMapper mapper, CloudTrailEventBridgeForwarder eventBridge) {
        this(storageFactory, regionResolver, mapper, new CloudTrailRecordBuilder(mapper),
                new UserIdentityBuilder(iamService, regionResolver, mapper), eventBridge, null);
    }

    @Inject
    public CloudTrailService(StorageFactory storageFactory, RegionResolver regionResolver, ObjectMapper mapper,
                             CloudTrailRecordBuilder recordBuilder, UserIdentityBuilder userIdentityBuilder,
                             CloudTrailEventBridgeForwarder eventBridge, ServiceCallAuthorizer serviceCallAuthorizer) {
        this.store = storageFactory.create("cloudtrail", "cloudtrail-trails.json",
                new TypeReference<Map<String, CloudTrailEntry>>() {});
        this.regionResolver = regionResolver;
        this.mapper = mapper;
        this.recordBuilder = recordBuilder;
        this.userIdentityBuilder = userIdentityBuilder;
        this.eventBridge = eventBridge;
        this.serviceCallAuthorizer = serviceCallAuthorizer;
    }

    // --- Control plane ---

    public Trail createTrail(String region, String name, String s3BucketName, String s3KeyPrefix,
                             String snsTopicArn, boolean includeGlobalServiceEvents,
                             boolean isMultiRegionTrail, boolean enableLogFileValidation,
                             boolean isOrganizationTrail) {
        return createTrail(region, name, s3BucketName, s3KeyPrefix, snsTopicArn,
                includeGlobalServiceEvents, isMultiRegionTrail, enableLogFileValidation,
                isOrganizationTrail, Map.of());
    }

    /**
     * Creates a trail, optionally tagged from the outset. CreateTrail carries a {@code TagsList}
     * on the wire, and the Terraform AWS provider always sends the resource's tags there rather
     * than through a follow-up AddTags, then reads them back with ListTags on every refresh, so
     * tags dropped here would surface as a perpetual diff on {@code aws_cloudtrail}.
     */
    public Trail createTrail(String region, String name, String s3BucketName, String s3KeyPrefix,
                             String snsTopicArn, boolean includeGlobalServiceEvents,
                             boolean isMultiRegionTrail, boolean enableLogFileValidation,
                             boolean isOrganizationTrail, Map<String, String> tags) {
        return createTrail(region, name, s3BucketName, s3KeyPrefix, snsTopicArn, includeGlobalServiceEvents,
                isMultiRegionTrail, enableLogFileValidation, isOrganizationTrail, tags, null, null);
    }

    public Trail createTrail(String region, String name, String s3BucketName, String s3KeyPrefix,
                             String snsTopicArn, boolean includeGlobalServiceEvents,
                             boolean isMultiRegionTrail, boolean enableLogFileValidation,
                             boolean isOrganizationTrail, Map<String, String> tags,
                             String cloudWatchLogsLogGroupArn, String cloudWatchLogsRoleArn) {
        validateTrailName(name);
        if (s3BucketName == null || s3BucketName.isEmpty()) {
            throw new AwsException("S3BucketDoesNotExistException", "S3 bucket name is required.", 400);
        }
        Map<String, String> initialTags = tags == null ? Map.of() : tags;
        if (initialTags.size() > MAX_TAGS_PER_RESOURCE) {
            throw new AwsException("TagsLimitExceededException",
                    "Tag limit exceeded for trail " + name
                            + ". Maximum allowed: " + MAX_TAGS_PER_RESOURCE + ".", 400);
        }
        String key = regionKey(region, name);
        if (store.get(key).isPresent()) {
            throw new AwsException("TrailAlreadyExistsException",
                    "Trail " + name + " already exists.", 400);
        }
        String arn = AwsArnUtils.Arn.of("cloudtrail", region, regionResolver.getAccountId(),
                "trail/" + name).toString();
        String topicArn = topicArn(region, snsTopicArn);
        validateCloudWatchLogs(cloudWatchLogsLogGroupArn, cloudWatchLogsRoleArn);
        checkDestinationPolicies(region, arn, s3BucketName, s3KeyPrefix, topicArn);
        Trail trail = new Trail(
                name, arn, s3BucketName, s3KeyPrefix, topicArn,
                includeGlobalServiceEvents, isMultiRegionTrail, region,
                enableLogFileValidation, false, false, isOrganizationTrail,
                cloudWatchLogsLogGroupArn, cloudWatchLogsRoleArn);
        store.put(key, new CloudTrailEntry(trail, List.of(), List.of(), false, null, null,
                initialTags, null, null, null));
        return trail;
    }

    public void deleteTrail(String region, String trailNameOrArn) {
        Trail trail = findTrailOrThrow(region, trailNameOrArn);
        String key = regionKey(trail.homeRegion(), trail.name());
        withTrailLock(key, () -> store.delete(key));
        String accountId = regionResolver.getAccountId();
        pendingRecordsByTrail.keySet().removeIf(k -> k.accountId().equals(accountId)
                && k.trailName().equals(trail.name()));
    }

    public Trail updateTrail(String region, String trailNameOrArn,
                             String s3BucketName, String s3KeyPrefix, String snsTopicArn,
                             Boolean includeGlobalServiceEvents, Boolean isMultiRegionTrail,
                             Boolean enableLogFileValidation, Boolean isOrganizationTrail) {
        return updateTrail(region, trailNameOrArn, s3BucketName, s3KeyPrefix, snsTopicArn, includeGlobalServiceEvents,
                isMultiRegionTrail, enableLogFileValidation, isOrganizationTrail, null, null);
    }

    /** A null argument keeps the trail's value; an empty CloudWatch Logs ARN removes the delivery. */
    public Trail updateTrail(String region, String trailNameOrArn,
                             String s3BucketName, String s3KeyPrefix, String snsTopicArn,
                             Boolean includeGlobalServiceEvents, Boolean isMultiRegionTrail,
                             Boolean enableLogFileValidation, Boolean isOrganizationTrail,
                             String cloudWatchLogsLogGroupArn, String cloudWatchLogsRoleArn) {
        Trail resolved = findTrailOrThrow(region, trailNameOrArn);
        String key = regionKey(resolved.homeRegion(), resolved.name());
        return withTrailLock(key, () -> {
            CloudTrailEntry entry = store.get(key).orElseThrow(() -> new AwsException(
                    "TrailNotFoundException", "Unknown trail: " + trailNameOrArn, 400));
            Trail existing = entry.trail();
            String logGroupArn = cloudWatchLogsLogGroupArn == null ? existing.cloudWatchLogsLogGroupArn()
                    : cloudWatchLogsLogGroupArn.isEmpty() ? null : cloudWatchLogsLogGroupArn;
            String logsRoleArn = cloudWatchLogsRoleArn == null ? existing.cloudWatchLogsRoleArn()
                    : cloudWatchLogsRoleArn.isEmpty() ? null : cloudWatchLogsRoleArn;
            validateCloudWatchLogs(logGroupArn, logsRoleArn);
            if (s3BucketName != null || s3KeyPrefix != null || snsTopicArn != null) {
                checkDestinationPolicies(existing.homeRegion(), existing.trailArn(),
                        s3BucketName != null ? s3BucketName : existing.s3BucketName(),
                        s3KeyPrefix != null ? s3KeyPrefix : existing.s3KeyPrefix(),
                        snsTopicArn != null ? topicArn(existing.homeRegion(), snsTopicArn) : existing.snsTopicArn());
            }
            Trail updated = new Trail(
                    existing.name(),
                    existing.trailArn(),
                    s3BucketName != null ? s3BucketName : existing.s3BucketName(),
                    s3KeyPrefix != null ? s3KeyPrefix : existing.s3KeyPrefix(),
                    snsTopicArn != null ? topicArn(existing.homeRegion(), snsTopicArn) : existing.snsTopicArn(),
                    includeGlobalServiceEvents != null ? includeGlobalServiceEvents : existing.includeGlobalServiceEvents(),
                    isMultiRegionTrail != null ? isMultiRegionTrail : existing.isMultiRegionTrail(),
                    existing.homeRegion(),
                    enableLogFileValidation != null ? enableLogFileValidation : existing.logFileValidationEnabled(),
                    existing.hasCustomEventSelectors(),
                    existing.hasInsightSelectors(),
                    isOrganizationTrail != null ? isOrganizationTrail : existing.isOrganizationTrail(),
                    logGroupArn, logsRoleArn);
            store.put(key, entry.withTrail(updated));
            return updated;
        });
    }

    public List<Trail> describeTrails(String region, List<String> trailNameOrArnList) {
        if (trailNameOrArnList == null || trailNameOrArnList.isEmpty()) {
            List<Trail> results = new ArrayList<>();
            for (String k : store.keys()) {
                String trailRegion = regionFromKey(k);
                CloudTrailEntry entry = store.get(k).orElse(null);
                if (entry == null) continue;
                Trail t = entry.trail();
                if (trailRegion.equals(region) || t.isMultiRegionTrail()) {
                    results.add(t);
                }
            }
            return results;
        }
        List<Trail> results = new ArrayList<>();
        for (String nameOrArn : trailNameOrArnList) {
            Trail t = findTrail(region, nameOrArn);
            if (t != null) results.add(t);
        }
        return results;
    }

    public List<EventSelector> putEventSelectors(String region, String trailNameOrArn, List<EventSelector> selectors) {
        Trail trail = findTrailOrThrow(region, trailNameOrArn);
        List<EventSelector> normalized = selectors == null ? List.of() : List.copyOf(selectors);
        String key = regionKey(trail.homeRegion(), trail.name());
        withTrailLock(key, () -> store.get(key).ifPresent(entry -> store.put(key, entry.withSelectors(normalized, true))));
        return normalized;
    }

    public List<EventSelector> getEventSelectors(String region, String trailNameOrArn) {
        Trail trail = findTrailOrThrow(region, trailNameOrArn);
        return store.get(regionKey(trail.homeRegion(), trail.name()))
                .map(e -> e.selectors() != null ? e.selectors() : List.<EventSelector>of())
                .orElse(List.of());
    }

    public List<AdvancedEventSelector> putAdvancedEventSelectors(
            String region, String trailNameOrArn, List<AdvancedEventSelector> selectors) {
        Trail trail = findTrailOrThrow(region, trailNameOrArn);
        List<AdvancedEventSelector> normalized = selectors == null ? List.of() : List.copyOf(selectors);
        String key = regionKey(trail.homeRegion(), trail.name());
        withTrailLock(key, () -> store.get(key).ifPresent(entry -> store.put(key, entry.withAdvancedSelectors(normalized, true))));
        return normalized;
    }

    public List<AdvancedEventSelector> getAdvancedEventSelectors(String region, String trailNameOrArn) {
        Trail trail = findTrailOrThrow(region, trailNameOrArn);
        return store.get(regionKey(trail.homeRegion(), trail.name()))
                .map(e -> e.advancedSelectors() != null ? e.advancedSelectors() : List.<AdvancedEventSelector>of())
                .orElse(List.of());
    }

    public List<TrailInfo> listTrails(String region) {
        List<TrailInfo> result = new ArrayList<>();
        for (String k : store.keys()) {
            CloudTrailEntry entry = store.get(k).orElse(null);
            if (entry == null) {
                continue;
            }
            Trail t = entry.trail();
            if (regionFromKey(k).equals(region) || t.isMultiRegionTrail()) {
                result.add(new TrailInfo(t.name(), t.trailArn(), t.homeRegion()));
            }
        }
        return result;
    }

    @RegisterForReflection
    public record TrailInfo(
            @JsonProperty("Name") String name,
            @JsonProperty("TrailARN") String trailArn,
            @JsonProperty("HomeRegion") String homeRegion) {
    }

    public void startLogging(String region, String trailNameOrArn) {
        Trail trail = findTrailOrThrow(region, trailNameOrArn);
        String key = regionKey(trail.homeRegion(), trail.name());
        withTrailLock(key, () -> store.get(key).ifPresent(entry -> store.put(key, entry.startLogging(System.currentTimeMillis()))));
    }

    public void stopLogging(String region, String trailNameOrArn) {
        Trail trail = findTrailOrThrow(region, trailNameOrArn);
        String key = regionKey(trail.homeRegion(), trail.name());
        withTrailLock(key, () -> store.get(key).ifPresent(entry -> store.put(key, entry.stopLogging(System.currentTimeMillis()))));
    }

    public TrailStatus getTrailStatus(String region, String trailNameOrArn) {
        Trail trail = findTrailOrThrow(region, trailNameOrArn);
        return store.get(regionKey(trail.homeRegion(), trail.name()))
                .map(e -> new TrailStatus(e.logging(), e.startLoggingTime(), e.stopLoggingTime(),
                        e.latestDeliveryTime(), e.latestDeliveryError(), e.channels()))
                .orElse(new TrailStatus(false, null, null, null, null, null));
    }

    /** Every trail that is logging, in every account, with the time it started. */
    public List<AccountAwareStorageBackend.AccountEntry<CloudTrailEntry>> loggingTrails() {
        return store.scanAllAccountEntries(k -> true).stream().filter(e -> e.value().logging()).toList();
    }

    public void updateChannels(String accountId, String trailRegion, String trailName,
                               UnaryOperator<CloudTrailEntry.ChannelStatus> update) {
        updateEntry(accountId, trailRegion, trailName, entry -> entry.withChannels(update.apply(entry.channels())));
    }

    private void updateEntry(String accountId, String trailRegion, String trailName,
                             UnaryOperator<CloudTrailEntry> update) {
        String storeKey = regionKey(trailRegion, trailName);
        withTrailLock(storeKey, () -> store.getForAccount(accountId, storeKey)
                .ifPresent(entry -> store.putForAccount(accountId, storeKey, update.apply(entry))));
    }

    void onBufferFull(Runnable listener) {
        bufferFullListener = listener;
    }

    private String topicArn(String region, String topic) {
        if (topic == null || topic.isEmpty()) {
            return null;
        }
        return AwsArnUtils.isArn(topic) ? topic
                : AwsArnUtils.Arn.of("sns", region, regionResolver.getAccountId(), topic).toString();
    }

    private static void validateCloudWatchLogs(String logGroupArn, String roleArn) {
        if (logGroupArn != null && roleArn == null) {
            throw new AwsException("InvalidCloudWatchLogsRoleArnException",
                    "You must specify a role ARN along with a CloudWatch Logs log group ARN.", 400);
        }
        if (roleArn != null && logGroupArn == null) {
            throw new AwsException("InvalidCloudWatchLogsLogGroupArnException",
                    "You must specify a CloudWatch Logs log group ARN along with a role ARN.", 400);
        }
    }

    /**
     * CreateTrail's check that the bucket policy lets CloudTrail read the bucket ACL and write its logs,
     * and that the topic policy lets it publish, under the conditions AWS's documented policies set.
     */
    private void checkDestinationPolicies(String region, String trailArn, String bucket, String prefix,
                                          String topicArn) {
        if (serviceCallAuthorizer == null) {
            return;
        }
        String account = regionResolver.getAccountId();
        String bucketArn = AwsArnUtils.Arn.global(AwsRegions.partitionFor(region), "s3", "", bucket).toString();
        String logsArn = bucketArn + "/" + keyPrefix(prefix) + "AWSLogs/" + account + "/CloudTrail";
        if (serviceCallAuthorizer.authorize("cloudtrail", "s3:GetBucketAcl", bucketArn, trailArn, account)
                != IamPolicyEvaluator.Decision.ALLOW
                || serviceCallAuthorizer.authorize("cloudtrail", "s3:PutObject", logsArn, trailArn, account,
                Map.of("s3:x-amz-acl", List.of("bucket-owner-full-control"))) != IamPolicyEvaluator.Decision.ALLOW) {
            throw new AwsException("InsufficientS3BucketPolicyException",
                    "Incorrect S3 bucket policy is detected for bucket: " + bucket, 400);
        }
        if (topicArn != null && serviceCallAuthorizer.authorize("cloudtrail", "sns:Publish", topicArn, trailArn,
                account) != IamPolicyEvaluator.Decision.ALLOW) {
            throw new AwsException("InsufficientSnsTopicPolicyException",
                    "Incorrect SNS topic policy is detected for topic: " + topicArn, 400);
        }
    }

    static String keyPrefix(String prefix) {
        return prefix == null || prefix.isEmpty() ? "" : prefix + (prefix.endsWith("/") ? "" : "/");
    }

    // --- Tagging ---
    //
    // AddTags/RemoveTags/ListTags identify the trail solely by ARN (ResourceId /
    // ResourceIdList), unlike every other CloudTrail action here which also accepts a
    // bare trail name, so these do not take a `region` parameter.

    private static final int MAX_TAGS_PER_RESOURCE = 50;

    public void addTags(String resourceId, Map<String, String> tagsToAdd) {
        String key = findKeyByArnOrThrow(resourceId);
        withTrailLock(key, () -> {
            CloudTrailEntry entry = store.get(key).orElseThrow(() -> new AwsException(
                    "ResourceNotFoundException", "Resource not found: " + resourceId, 400));
            Map<String, String> merged = entry.mutableTags();
            merged.putAll(tagsToAdd);
            if (merged.size() > MAX_TAGS_PER_RESOURCE) {
                throw new AwsException("TagsLimitExceededException",
                        "Tag limit exceeded for resource " + resourceId
                                + ". Maximum allowed: " + MAX_TAGS_PER_RESOURCE + ".", 400);
            }
            store.put(key, entry.withTags(merged));
        });
    }

    public void removeTags(String resourceId, List<String> tagKeys) {
        String key = findKeyByArnOrThrow(resourceId);
        withTrailLock(key, () -> {
            CloudTrailEntry entry = store.get(key).orElseThrow(() -> new AwsException(
                    "ResourceNotFoundException", "Resource not found: " + resourceId, 400));
            Map<String, String> remaining = entry.mutableTags();
            tagKeys.forEach(remaining::remove);
            store.put(key, entry.withTags(remaining));
        });
    }

    public Map<String, String> listTags(String resourceId) {
        return findEntryByArnOrThrow(resourceId).tags();
    }

    private CloudTrailEntry findEntryByArnOrThrow(String resourceId) {
        String key = findKeyByArnOrThrow(resourceId);
        return store.get(key).orElseThrow(() -> new AwsException(
                "ResourceNotFoundException", "Resource not found: " + resourceId, 400));
    }

    /** Validates {@code resourceId} as a trail ARN and resolves it to a storage key, without
     *  reading the entry itself. Callers that go on to mutate the entry must re-read it inside
     *  {@link #withTrailLock} rather than reuse a value read here. */
    private String findKeyByArnOrThrow(String resourceId) {
        AwsArnUtils.Arn arn;
        try {
            arn = AwsArnUtils.parse(resourceId);
        } catch (IllegalArgumentException e) {
            throw new AwsException("CloudTrailARNInvalidException",
                    resourceId + " is not a valid ARN.", 400);
        }
        if (!"cloudtrail".equals(arn.service()) || !arn.resource().startsWith("trail/")) {
            throw new AwsException("CloudTrailARNInvalidException",
                    resourceId + " is not a valid trail ARN.", 400);
        }
        for (String k : store.keys()) {
            CloudTrailEntry entry = store.get(k).orElse(null);
            if (entry != null && resourceId.equals(entry.trail().trailArn())) {
                return k;
            }
        }
        throw new AwsException("ResourceNotFoundException",
                "Resource not found: " + resourceId, 400);
    }

    /**
     * Runs {@code action} with exclusive access to trail {@code key}, so overlapping mutations of
     * the same trail (even from different actions) can't interleave and clobber one another.
     * Piggybacks on {@link ConcurrentHashMap#compute}'s documented per-key atomicity as the
     * mutex, rather than a plain lock-object map: returning null from the remapping function
     * drops the bookkeeping entry the instant the call finishes, so {@code trailLocks} never
     * accumulates one entry per trail ever mutated, unlike a map of retained lock objects would.
     */
    private <T> T withTrailLock(String key, Supplier<T> action) {
        Object[] box = new Object[1];
        trailLocks.compute(key, (k, v) -> {
            box[0] = action.get();
            return null;
        });
        @SuppressWarnings("unchecked")
        T result = (T) box[0];
        return result;
    }

    private void withTrailLock(String key, Runnable action) {
        withTrailLock(key, () -> {
            action.run();
            return null;
        });
    }

    // --- Data plane: called by S3 (and other services) when an op happens ---

    public void emitS3DataEvent(S3EventInput in) {
        try {
            String region = in.region() != null ? in.region() : regionResolver.getDefaultRegion();
            String accountId = in.accountId() != null ? in.accountId() : regionResolver.getAccountId();
            List<MatchedTrail> matched = trailsMatching(accountId, region, in);
            if (matched.isEmpty()) {
                return;
            }
            ObjectNode record = buildS3Record(in, region, accountId);
            eventBridge.forward(record);
            for (MatchedTrail mt : matched) {
                ObjectNode copy = record.deepCopy();
                boolean accepted = append(new TrailKey(accountId, mt.region(), mt.trail().name(), region), copy);
                if (accepted) {
                    LOG.tracev("Emitted CloudTrail event {0} for trail {1}", in.eventName(), mt.trail().name());
                } else {
                    LOG.debugv("Dropped CloudTrail event {0} for trail {1}: delivery is failing and the buffer is full",
                            in.eventName(), mt.trail().name());
                }
            }
        } catch (Exception e) {
            // Never let emission take down an S3 op.
            LOG.warnv(e, "Failed to emit CloudTrail event for {0} {1}/{2}",
                    in.eventName(), in.bucketName(), in.key());
        }
    }

    /**
     * Appends a management event record to every logging trail of its recipient account whose region,
     * global-service setting and selectors cover it, returning whether any trail did.
     */
    public boolean routeManagementEvent(ObjectNode record) {
        String accountId = record.path("recipientAccountId").asText();
        String eventRegion = record.path("awsRegion").asText();
        String eventSource = record.path("eventSource").asText();
        boolean readOnly = record.path("readOnly").asBoolean();
        boolean global = TrailRouter.globalSigningRegion(eventSource, eventRegion) != null;
        boolean covered = false;
        for (AccountAwareStorageBackend.AccountEntry<CloudTrailEntry> stored : store.scanAllAccountEntries(k -> true)) {
            CloudTrailEntry entry = stored.value();
            String trailRegion = regionFromKey(stored.key());
            if (!stored.accountId().equals(accountId) || !entry.logging()
                    || (!trailRegion.equals(eventRegion) && !entry.trail().isMultiRegionTrail())
                    || (global && !entry.trail().includeGlobalServiceEvents())
                    || !TrailRouter.logsManagementEvent(entry.selectors(), entry.advancedSelectors(),
                    eventSource, readOnly)) {
                continue;
            }
            covered = true;
            if (!append(new TrailKey(accountId, trailRegion, entry.trail().name(), eventRegion), record.deepCopy())) {
                LOG.debugv("Dropped CloudTrail event {0} for trail {1}: delivery is failing and the buffer is full",
                        record.path("eventName").asText(), entry.trail().name());
            }
        }
        return covered;
    }

    public void requeueRecords(TrailKey key, List<ObjectNode> records) {
        if (!records.isEmpty()) {
            List<PendingRecord> pending = records.stream()
                    .map(record -> new PendingRecord(record, estimatedRecordBytes(record)))
                    .toList();
            pendingRecordsByTrail.compute(pendingTrailKey(key), (ignored, buffer) -> {
                PendingRecordBuffer updated = buffer == null ? new PendingRecordBuffer() : buffer;
                updated.requeueFront(key.eventRegion(), pending);
                return updated.isEmpty() ? null : updated;
            });
        }
    }

    public void completeDelivery(TrailKey key) {
        pendingRecordsByTrail.computeIfPresent(pendingTrailKey(key), (ignored, buffer) -> {
            buffer.completeDelivery(key.eventRegion());
            return buffer.isEmpty() ? null : buffer;
        });
    }

    public void discardPendingRecords(TrailKey key) {
        pendingRecordsByTrail.computeIfPresent(pendingTrailKey(key), (ignored, buffer) -> {
            buffer.discard(key.eventRegion());
            return buffer.isEmpty() ? null : buffer;
        });
    }

    public List<ObjectNode> drainPendingRecords(TrailKey key) {
        return drainPendingRecords(key, Integer.MAX_VALUE);
    }

    public List<ObjectNode> drainPendingRecords(TrailKey key, int maxRecords) {
        if (maxRecords <= 0) {
            return List.of();
        }
        List<ObjectNode> drained = new ArrayList<>();
        pendingRecordsByTrail.compute(pendingTrailKey(key), (ignored, buffer) -> {
            if (buffer == null) {
                return null;
            }
            drained.addAll(buffer.drain(key.eventRegion(), maxRecords));
            return buffer.isEmpty() ? null : buffer;
        });
        return drained.isEmpty() ? List.of() : drained;
    }

    public List<TrailKey> trailsWithPendingRecords() {
        List<TrailKey> result = new ArrayList<>();
        for (Map.Entry<PendingTrailKey, PendingRecordBuffer> e : pendingRecordsByTrail.entrySet()) {
            for (String eventRegion : e.getValue().eventRegions()) {
                result.add(new TrailKey(e.getKey().accountId(), e.getKey().region(), e.getKey().trailName(),
                        eventRegion));
            }
        }
        return result;
    }

    public int pendingRecordCount(TrailKey key) {
        PendingRecordBuffer buffer = pendingRecordsByTrail.get(pendingTrailKey(key));
        return buffer == null ? 0 : buffer.pendingCount(key.eventRegion());
    }

    public Trail getTrail(TrailKey key) {
        return store.getForAccount(key.accountId(), regionKey(key.region(), key.trailName()))
                .map(CloudTrailEntry::trail)
                .orElse(null);
    }

    public void recordDeliveryFailure(TrailKey key, String error) {
        updateDeliveryStatus(key, entry -> entry.withDeliveryFailure(error));
    }

    public void recordDeliverySuccess(TrailKey key, long time) {
        updateDeliveryStatus(key, entry -> entry.withDeliverySuccess(time));
    }

    private void updateDeliveryStatus(TrailKey key, UnaryOperator<CloudTrailEntry> update) {
        updateEntry(key.accountId(), key.region(), key.trailName(), update);
    }

    /**
     * Queues a record for delivery. A full buffer asks the writer for an early delivery instead of
     * dropping; only while the trail's last delivery failed does a full buffer refuse records, which
     * {@code GetTrailStatus.LatestDeliveryError} reports.
     */
    private boolean append(TrailKey key, ObjectNode record) {
        long recordBytes = estimatedRecordBytes(record);
        boolean[] accepted = {false};
        boolean[] full = {false};
        pendingRecordsByTrail.compute(pendingTrailKey(key), (ignored, buffer) -> {
            PendingRecordBuffer updated = buffer == null ? new PendingRecordBuffer() : buffer;
            accepted[0] = updated.append(key.eventRegion(), record, recordBytes);
            full[0] = updated.full(0);
            return updated.isEmpty() ? null : updated;
        });
        if (accepted[0] && full[0]) {
            bufferFullListener.run();
        }
        return accepted[0];
    }

    private long estimatedRecordBytes(ObjectNode record) {
        try {
            return mapper.writeValueAsBytes(record).length;
        } catch (Exception e) {
            return record.toString().getBytes(StandardCharsets.UTF_8).length;
        }
    }

    /**
     * Identifies a pending-records queue.
     * {@code region} is the trail's home region (used for trail store lookups).
     * {@code eventRegion} is the region where the event occurred (used for the S3 delivery path).
     * For single-region trails these are the same; for multi-region trails they differ.
     */
    public record TrailKey(String accountId, String region, String trailName, String eventRegion) {}

    private record PendingTrailKey(String accountId, String region, String trailName) {}

    private record PendingRecord(ObjectNode record, long byteCount) {}

    private final class PendingRecordBuffer {
        private final Map<String, ArrayDeque<PendingRecord>> recordsByRegion = new ConcurrentHashMap<>();
        private final Map<String, List<PendingRecord>> inFlightByRegion = new ConcurrentHashMap<>();
        private int recordCount;
        private long byteCount;
        private boolean failing;

        synchronized boolean full(long recordBytes) {
            return recordCount >= MAX_PENDING_RECORDS_PER_TRAIL
                    || byteCount + recordBytes > MAX_PENDING_BYTES_PER_TRAIL;
        }

        synchronized boolean append(String eventRegion, ObjectNode record, long recordBytes) {
            if (failing && full(recordBytes)) {
                return false;
            }
            recordsByRegion.computeIfAbsent(eventRegion, ignored -> new ArrayDeque<>())
                    .addLast(new PendingRecord(record, recordBytes));
            recordCount++;
            byteCount += recordBytes;
            return true;
        }

        synchronized void requeueFront(String eventRegion, List<PendingRecord> drained) {
            ArrayDeque<PendingRecord> records = recordsByRegion.computeIfAbsent(
                    eventRegion, ignored -> new ArrayDeque<>());
            boolean wasInFlight = inFlightByRegion.remove(eventRegion) != null;
            failing = true;
            for (int i = drained.size() - 1; i >= 0; i--) {
                PendingRecord pending = drained.get(i);
                records.addFirst(pending);
                if (!wasInFlight) {
                    recordCount++;
                    byteCount += pending.byteCount();
                }
            }
            trimTailToLimit(eventRegion);
        }

        synchronized List<ObjectNode> drain(String eventRegion) {
            return drain(eventRegion, Integer.MAX_VALUE);
        }

        synchronized List<ObjectNode> drain(String eventRegion, int maxRecords) {
            ArrayDeque<PendingRecord> records = recordsByRegion.remove(eventRegion);
            if (records == null || records.isEmpty()) {
                return List.of();
            }
            List<PendingRecord> selected = new ArrayList<>(Math.min(records.size(), maxRecords));
            long fileBytes = LOG_FILE_ENVELOPE_BYTES;
            while (selected.size() < maxRecords && !records.isEmpty()
                    && (selected.isEmpty() || fileBytes + records.peekFirst().byteCount() + 1 <= MAX_LOG_FILE_BYTES)) {
                fileBytes += records.peekFirst().byteCount() + 1;
                selected.add(records.removeFirst());
            }
            if (!records.isEmpty()) {
                recordsByRegion.put(eventRegion, records);
            }
            inFlightByRegion.put(eventRegion, selected);
            List<ObjectNode> drained = new ArrayList<>(selected.size());
            for (PendingRecord pending : selected) {
                drained.add(pending.record());
            }
            return drained;
        }

        synchronized void completeDelivery(String eventRegion) {
            List<PendingRecord> inFlight = inFlightByRegion.remove(eventRegion);
            if (inFlight == null) {
                return;
            }
            failing = false;
            for (PendingRecord pending : inFlight) {
                recordCount--;
                byteCount -= pending.byteCount();
            }
        }

        synchronized void discard(String eventRegion) {
            ArrayDeque<PendingRecord> queued = recordsByRegion.remove(eventRegion);
            if (queued != null) {
                for (PendingRecord pending : queued) {
                    recordCount--;
                    byteCount -= pending.byteCount();
                }
            }
            List<PendingRecord> inFlight = inFlightByRegion.remove(eventRegion);
            if (inFlight != null) {
                for (PendingRecord pending : inFlight) {
                    recordCount--;
                    byteCount -= pending.byteCount();
                }
            }
        }

        synchronized boolean isEmpty() {
            return recordCount == 0 && inFlightByRegion.isEmpty();
        }

        synchronized int pendingCount(String eventRegion) {
            ArrayDeque<PendingRecord> records = recordsByRegion.get(eventRegion);
            List<PendingRecord> inFlight = inFlightByRegion.get(eventRegion);
            return (records == null ? 0 : records.size()) + (inFlight == null ? 0 : inFlight.size());
        }

        synchronized List<String> eventRegions() {
            return java.util.stream.Stream.concat(recordsByRegion.keySet().stream(), inFlightByRegion.keySet().stream())
                    .distinct()
                    .filter(eventRegion -> {
                        ArrayDeque<PendingRecord> records = recordsByRegion.get(eventRegion);
                        return (records != null && !records.isEmpty()) || inFlightByRegion.containsKey(eventRegion);
                    })
                    .toList();
        }

        private void trimTailToLimit(String preferredRegion) {
            while (recordCount > MAX_PENDING_RECORDS_PER_TRAIL
                    || byteCount > MAX_PENDING_BYTES_PER_TRAIL) {
                ArrayDeque<PendingRecord> records = recordsByRegion.get(preferredRegion);
                if (records == null || records.isEmpty()) {
                    records = recordsByRegion.values().stream()
                            .filter(queue -> !queue.isEmpty())
                            .findFirst()
                            .orElseThrow();
                }
                PendingRecord dropped = records.removeLast();
                recordCount--;
                byteCount -= dropped.byteCount();
            }
        }
    }

    private static PendingTrailKey pendingTrailKey(TrailKey key) {
        return new PendingTrailKey(key.accountId(), key.region(), key.trailName());
    }

    // --- Helpers ---

    private List<MatchedTrail> trailsMatching(String accountId, String region, S3EventInput in) {
        List<MatchedTrail> result = new ArrayList<>();
        for (AccountAwareStorageBackend.AccountEntry<CloudTrailEntry> stored : store.scanAllAccountEntries(k -> true)) {
            if (!stored.accountId().equals(accountId)) {
                continue;
            }
            String trailRegion = regionFromKey(stored.key());
            boolean sameRegion = trailRegion.equals(region);
            CloudTrailEntry entry = stored.value();
            Trail trail = entry.trail();
            if (!sameRegion && !trail.isMultiRegionTrail()) {
                continue;
            }
            if (!entry.logging()) {
                continue;
            }
            List<AdvancedEventSelector> advancedSelectors =
                    entry.advancedSelectors() != null ? entry.advancedSelectors() : List.of();
            boolean matched;
            if (!advancedSelectors.isEmpty()) {
                matched = matchesAnyAdvancedSelector(advancedSelectors, in);
            } else {
                List<EventSelector> selectors = entry.selectors() != null ? entry.selectors() : List.of();
                matched = matchesAnySelector(selectors, in);
            }
            if (matched) {
                result.add(new MatchedTrail(trail, trailRegion));
            }
        }
        return result;
    }

    private boolean matchesAnySelector(List<EventSelector> selectors, S3EventInput in) {
        if (selectors.isEmpty()) {
            return false;
        }
        boolean isRead = isReadOnlyEvent(in.eventName());
        for (EventSelector sel : selectors) {
            String rwt = sel.readWriteType() == null ? "All" : sel.readWriteType();
            if ("ReadOnly".equalsIgnoreCase(rwt) && !isRead) continue;
            if ("WriteOnly".equalsIgnoreCase(rwt) && isRead) continue;

            List<DataResource> dataResources = sel.dataResources();
            if (dataResources == null || dataResources.isEmpty()) {
                continue;
            }
            for (DataResource dr : dataResources) {
                if (!"AWS::S3::Object".equals(dr.type())) continue;
                if (dr.values() == null) continue;
                for (String v : dr.values()) {
                    if (matchesS3DataResourceArn(v, in.bucketName(), in.key())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean matchesAnyAdvancedSelector(List<AdvancedEventSelector> selectors, S3EventInput in) {
        String arn = regionResolver.buildGlobalArn("s3", "", in.bucketName() + (in.key() != null ? "/" + in.key() : ""));
        // Bucket-level operations (e.g. ListObjects) have no object key and are reported
        // by CloudTrail as AWS::S3::Bucket resources, not AWS::S3::Object: matching real
        // AWS behavior, an AWS::S3::Object DataResource selector must never match them.
        String resourceType = in.key() != null ? "AWS::S3::Object" : "AWS::S3::Bucket";
        for (AdvancedEventSelector sel : selectors) {
            if (matchesAdvancedSelector(sel, arn, resourceType)) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesAdvancedSelector(AdvancedEventSelector selector, String s3ObjectArn, String resourceType) {
        List<AdvancedFieldSelector> fieldSelectors = selector.fieldSelectors();
        if (fieldSelectors == null || fieldSelectors.isEmpty()) {
            return false;
        }
        for (AdvancedFieldSelector fs : fieldSelectors) {
            if (!matchesAdvancedFieldSelector(fs, s3ObjectArn, resourceType)) {
                return false;
            }
        }
        return true;
    }

    // Package-private for unit testing. Only the fields CloudTrail evaluates for S3 data events
    // are supported: eventCategory, resources.type, resources.ARN.
    static boolean matchesAdvancedFieldSelector(AdvancedFieldSelector fs, String s3ObjectArn, String resourceType) {
        String value = switch (fs.field()) {
            case "eventCategory" -> "Data";
            case "resources.type" -> resourceType;
            case "resources.ARN" -> s3ObjectArn;
            default -> null;
        };
        return value != null && matchesFieldValue(fs, value);
    }

    /** Whether {@code value} passes every operator of {@code fs}. */
    static boolean matchesFieldValue(AdvancedFieldSelector fs, String value) {
        if (!isEmpty(fs.equalsValues()) && fs.equalsValues().stream().noneMatch(value::equals)) {
            return false;
        }
        if (!isEmpty(fs.notEquals()) && fs.notEquals().stream().anyMatch(value::equals)) {
            return false;
        }
        if (!isEmpty(fs.startsWith()) && fs.startsWith().stream().noneMatch(value::startsWith)) {
            return false;
        }
        if (!isEmpty(fs.notStartsWith()) && fs.notStartsWith().stream().anyMatch(value::startsWith)) {
            return false;
        }
        if (!isEmpty(fs.endsWith()) && fs.endsWith().stream().noneMatch(value::endsWith)) {
            return false;
        }
        if (!isEmpty(fs.notEndsWith()) && fs.notEndsWith().stream().anyMatch(value::endsWith)) {
            return false;
        }
        return true;
    }

    private static boolean isEmpty(List<String> values) {
        return values == null || values.isEmpty();
    }

    private static final Pattern BARE_S3_ARN = Pattern.compile("arn:" + AwsArnUtils.PARTITION_REGEX + ":s3");

    // Package-private for unit testing.
    static boolean matchesS3DataResourceArn(String configured, String bucketName, String key) {
        if (configured == null) return false;
        // "arn:<partition>:s3" (bare, no ":::") is shorthand for all buckets + all objects.
        if (BARE_S3_ARN.matcher(configured).matches()) return true;
        // Forms accepted, in any partition:
        //   arn:aws:s3:::                    → all buckets, all keys
        //   arn:aws:s3:::*                   → all buckets (wildcard)
        //   arn:aws:s3:::bucket/             → all keys in bucket
        //   arn:aws:s3:::bucket/prefix       → keys with the given prefix in bucket
        //   arn:aws:s3:::*/*                 → all objects (wildcard bucket + any key)
        String tail = AwsArnUtils.resourceIfArnFor(configured, "s3").orElse(null);
        if (tail == null) return false;
        if (tail.isEmpty() || tail.equals("/")) {
            return true;
        }
        int slash = tail.indexOf('/');
        if (slash < 0) {
            return tail.equals("*") || tail.equals(bucketName);
        }
        String configBucket = tail.substring(0, slash);
        if (!configBucket.equals("*") && !configBucket.equals(bucketName)) return false;
        String configKeyPart = tail.substring(slash + 1);
        if (configKeyPart.isEmpty()) {
            return true;
        }
        if (configKeyPart.equals("*") || configKeyPart.equals("*/*")) {
            return key != null;
        }
        if (key == null) return false;
        return key.startsWith(configKeyPart);
    }

    // Package-private for unit testing. A read-only event is one that doesn't change a resource, so
    // SelectObjectContent is one although it is sent as a POST.
    static boolean isReadOnlyEvent(String eventName) {
        return eventName == null || CloudTrailRecordBuilder.isReadOnly(S3_EVENT_SOURCE, eventName);
    }

    /**
     * {@code region} is the event's region, resolved by the caller. Hosts and ARNs are built from it
     * rather than from the request scope, because the log writer emits its own deliveries from the
     * flush thread, where the request region falls back to the deployment default.
     */
    private ObjectNode buildS3Record(S3EventInput in, String region, String accountId) {
        String s3Host = in.bucketName() == null
                ? "s3." + AwsRegions.dnsSuffixFor(region)
                : AwsEndpoints.s3Host(in.bucketName(), region);
        String partition = AwsRegions.partitionFor(region);

        ObjectNode reqParams = mapper.createObjectNode();
        if (in.bucketName() != null) reqParams.put("bucketName", in.bucketName());
        reqParams.put("Host", s3Host);
        if (in.key() != null) reqParams.put("key", in.key());

        ObjectNode addl = mapper.createObjectNode();
        addl.put("SignatureVersion", "SigV4");
        if (in.tlsDetails() != null) {
            addl.put("CipherSuite", in.tlsDetails().cipherSuite());
        }
        addl.put("bytesTransferredIn", in.bytesIn());
        addl.put("AuthenticationMethod", "AuthHeader");
        addl.put("bytesTransferredOut", in.bytesOut());

        ArrayNode resources = null;
        if (in.bucketName() != null) {
            resources = mapper.createArrayNode();
            ObjectNode bucketRes = mapper.createObjectNode();
            bucketRes.put("accountId", accountId);
            bucketRes.put("type", "AWS::S3::Bucket");
            bucketRes.put("ARN", AwsArnUtils.Arn.global(partition, "s3", "", in.bucketName()).toString());
            resources.add(bucketRes);
            if (in.key() != null) {
                ObjectNode objRes = mapper.createObjectNode();
                objRes.put("type", "AWS::S3::Object");
                objRes.put("ARN",
                        AwsArnUtils.Arn.global(partition, "s3", "", in.bucketName() + "/" + in.key()).toString());
                resources.add(objRes);
            }
        }

        boolean service = in.invokedBy() != null;
        return recordBuilder.build(CloudTrailEvent.builder()
                .eventSource(S3_EVENT_SOURCE)
                .eventName(in.eventName())
                .awsRegion(region)
                .eventTime(Instant.ofEpochMilli(in.eventTimeMillis() == 0L
                        ? System.currentTimeMillis() : in.eventTimeMillis()))
                .userIdentity(service ? userIdentityBuilder.forService(in.invokedBy())
                        : userIdentityBuilder.forAccessKey(in.accessKeyId()))
                .sourceIPAddress(service ? in.invokedBy() : in.sourceIp() == null ? "127.0.0.1" : in.sourceIp())
                .userAgent(service ? in.invokedBy() : in.userAgent())
                .errorCode(in.errorCode())
                .errorMessage(in.errorMessage())
                .requestParameters(reqParams)
                .additionalEventData(addl)
                .requestId(in.requestId() != null ? in.requestId() : RequestIdFilter.s3RequestId())
                .resources(resources)
                .tlsDetails(in.tlsDetails())
                .recipientAccountId(accountId)
                .build());
    }

    private Trail findTrail(String region, String nameOrArn) {
        // ARN → cross-region scan is valid (callers use ARN to target another Region)
        if (nameOrArn != null && nameOrArn.startsWith("arn:")) {
            for (String k : store.keys()) {
                CloudTrailEntry entry = store.get(k).orElse(null);
                if (entry == null) continue;
                if (nameOrArn.equals(entry.trail().trailArn())) {
                    return entry.trail();
                }
            }
            return null;
        }
        // Name → region-scoped only (AWS resolves a name only in the current Region)
        return store.get(regionKey(region, nameOrArn))
                .map(CloudTrailEntry::trail)
                .orElse(null);
    }

    private Trail findTrailOrThrow(String region, String nameOrArn) {
        Trail t = findTrail(region, nameOrArn);
        if (t == null) {
            throw new AwsException("TrailNotFoundException",
                    "Unknown trail: " + nameOrArn, 400);
        }
        return t;
    }

    private static void validateTrailName(String name) {
        if (name == null || name.isEmpty()) {
            throw new AwsException("InvalidTrailNameException", "Trail name is required.", 400);
        }
        if (name.length() < 3) {
            throw new AwsException("InvalidTrailNameException",
                    "Trail name too short. Minimum allowed length: 3 characters.", 400);
        }
        if (name.length() > 128) {
            throw new AwsException("InvalidTrailNameException",
                    "Trail name too long. Maximum allowed length: 128 characters.", 400);
        }
        if (!Character.isLetterOrDigit(name.charAt(0))) {
            throw new AwsException("InvalidTrailNameException",
                    "Trail name must starts with a letter or number.", 400);
        }
        if (!Character.isLetterOrDigit(name.charAt(name.length() - 1))) {
            throw new AwsException("InvalidTrailNameException",
                    "Trail name must end with a letter or number.", 400);
        }
        for (char c : name.toCharArray()) {
            if (!Character.isLetterOrDigit(c) && c != '.' && c != '_' && c != '-') {
                throw new AwsException("InvalidTrailNameException",
                        "Trail name must only contain letters, numbers, periods, underscores, and hyphens.", 400);
            }
        }
    }

    private static String regionKey(String region, String name) {
        return region + ":" + name;
    }

    private static String regionFromKey(String key) {
        int colon = key.indexOf(':');
        return colon < 0 ? key : key.substring(0, colon);
    }

    public record TrailStatus(boolean logging, Long startLoggingTime, Long stopLoggingTime,
                              Long latestDeliveryTime, String latestDeliveryError,
                              CloudTrailEntry.ChannelStatus channels) {
        public TrailStatus {
            channels = channels == null ? CloudTrailEntry.ChannelStatus.NONE : channels;
        }
    }

    private record MatchedTrail(Trail trail, String region) {}

    /** Input describing a single S3 op for emission. Use the builder for clarity. */
    public record S3EventInput(
            String region,
            String eventName,
            String bucketName,
            String key,
            String accessKeyId,
            String sourceIp,
            String userAgent,
            long bytesIn,
            long bytesOut,
            String errorCode,
            String errorMessage,
            long eventTimeMillis,
            String requestId,
            TlsDetails tlsDetails,
            String invokedBy,
            String accountId) {

        public static Builder builder() { return new Builder(); }

        public static final class Builder {
            private String region;
            private String eventName;
            private String bucketName;
            private String key;
            private String accessKeyId;
            private String sourceIp;
            private String userAgent;
            private long bytesIn;
            private long bytesOut;
            private String errorCode;
            private String errorMessage;
            private long eventTimeMillis;
            private String requestId;
            private TlsDetails tlsDetails;
            private String invokedBy;
            private String accountId;

            public Builder region(String v) { this.region = v; return this; }
            public Builder eventName(String v) { this.eventName = v; return this; }
            public Builder bucketName(String v) { this.bucketName = v; return this; }
            public Builder key(String v) { this.key = v; return this; }
            public Builder accessKeyId(String v) { this.accessKeyId = v; return this; }
            public Builder sourceIp(String v) { this.sourceIp = v; return this; }
            public Builder userAgent(String v) { this.userAgent = v; return this; }
            public Builder bytesIn(long v) { this.bytesIn = v; return this; }
            public Builder bytesOut(long v) { this.bytesOut = v; return this; }
            public Builder errorCode(String v) { this.errorCode = v; return this; }
            public Builder errorMessage(String v) { this.errorMessage = v; return this; }
            public Builder eventTimeMillis(long v) { this.eventTimeMillis = v; return this; }
            public Builder requestId(String v) { this.requestId = v; return this; }
            public Builder tlsDetails(TlsDetails v) { this.tlsDetails = v; return this; }
            /** The service principal of an action an AWS service took on its own. */
            public Builder invokedBy(String v) { this.invokedBy = v; return this; }
            /** The account whose trails see the event, when not the request's, as for CloudTrail's own writes. */
            public Builder accountId(String v) { this.accountId = v; return this; }

            public S3EventInput build() {
                return new S3EventInput(region, eventName, bucketName, key, accessKeyId,
                        sourceIp, userAgent, bytesIn, bytesOut,
                        errorCode, errorMessage, eventTimeMillis, requestId, tlsDetails, invokedBy, accountId);
            }
        }
    }
}
