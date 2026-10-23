package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.core.storage.WriteProfile;
import io.github.hectorvent.floci.services.cloudtrail.model.HistoryEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * CloudTrail event history: every management event of the last {@code retention-days}, per account
 * and region, whether or not a trail covers it, as LookupEvents serves it newest first.
 * Past {@code max-events} the oldest events are evicted.
 */
@ApplicationScoped
public class EventHistoryStore {

    static final int MAX_RESULTS = 50;
    private static final Set<String> ATTRIBUTE_KEYS = Set.of("EventId", "EventName", "ReadOnly", "Username",
            "ResourceType", "ResourceName", "EventSource", "AccessKeyId");
    private static final Pattern KEY = Pattern.compile("\\d{13}-\\d{12}");

    private record Indexed(String key, String accountId, long eventTimeMillis) {
    }

    /** One LookupEvents page; {@code nextToken} is null on the last one. */
    public record Page(List<HistoryEvent> events, String nextToken) {
    }

    private final AccountAwareStorageBackend<HistoryEvent> store;
    private final NavigableSet<Indexed> index = new TreeSet<>(
            Comparator.comparing(Indexed::key).thenComparing(Indexed::accountId));
    private final Map<String, Deque<Long>> lookupTimes = new HashMap<>();
    private final Duration retention;
    private final int maxEvents;
    private final int lookupRateLimit;
    private long sequence;

    @Inject
    public EventHistoryStore(StorageFactory storageFactory, EmulatorConfig config) {
        this.store = storageFactory.create("cloudtrail", "cloudtrail-event-history.json",
                new TypeReference<Map<String, HistoryEvent>>() {}, WriteProfile.APPEND_HEAVY);
        EmulatorConfig.CloudTrailServiceConfig cloudtrail = config.services().cloudtrail();
        this.retention = Duration.ofDays(cloudtrail.eventHistory().retentionDays());
        this.maxEvents = cloudtrail.eventHistory().maxEvents();
        this.lookupRateLimit = cloudtrail.lookupRateLimitPerSecond();
        store.scanAllAccountEntries(key -> true).forEach(entry ->
                index.add(new Indexed(entry.key(), entry.accountId(), entry.value().eventTimeMillis())));
    }

    public synchronized void append(ObjectNode record) {
        long now = System.currentTimeMillis();
        String key = String.format("%013d-%012d", now, sequence++ % 1_000_000_000_000L);
        String accountId = record.path("recipientAccountId").asText();
        HistoryEvent event = new HistoryEvent(record.path("eventID").asText(), record.path("eventName").asText(),
                record.path("eventSource").asText(), record.path("awsRegion").asText(),
                Instant.parse(record.path("eventTime").asText()).toEpochMilli(), record.path("readOnly").asBoolean(),
                record.path("userIdentity").path("accessKeyId").asText(null), username(record.path("userIdentity")),
                resources(record), record.toString());
        store.putForAccount(accountId, key, event);
        index.add(new Indexed(key, accountId, event.eventTimeMillis()));
        long cutoff = now - retention.toMillis();
        while (!index.isEmpty() && (index.size() > maxEvents || index.first().eventTimeMillis() < cutoff)) {
            Indexed oldest = index.pollFirst();
            store.deleteForAccount(oldest.accountId(), oldest.key());
        }
    }

    public synchronized Page lookup(String accountId, String region, String attributeKey, String attributeValue,
                                    Instant startTime, Instant endTime, Integer maxResults, String nextToken) {
        throttle(accountId, region);
        if (attributeKey != null && !ATTRIBUTE_KEYS.contains(attributeKey)) {
            throw new AwsException("InvalidLookupAttributesException",
                    "Invalid attribute key: " + attributeKey, 400);
        }
        if (maxResults != null && (maxResults < 1 || maxResults > MAX_RESULTS)) {
            throw new AwsException("InvalidMaxResultsException",
                    "MaxResults must be between 1 and " + MAX_RESULTS + ".", 400);
        }
        if (startTime != null && endTime != null && startTime.isAfter(endTime)) {
            throw new AwsException("InvalidTimeRangeException", "Start time must be before end time.", 400);
        }
        if (nextToken != null && !KEY.matcher(nextToken).matches()) {
            throw new AwsException("InvalidNextTokenException", "Invalid NextToken.", 400);
        }
        int limit = maxResults == null ? MAX_RESULTS : maxResults;
        NavigableSet<Indexed> newestFirst = nextToken == null ? index.descendingSet()
                : index.headSet(new Indexed(nextToken, "", 0L), false).descendingSet();
        List<HistoryEvent> events = new ArrayList<>();
        String lastKey = null;
        for (Indexed indexed : newestFirst) {
            if (!indexed.accountId().equals(accountId)) {
                continue;
            }
            HistoryEvent event = store.getForAccount(accountId, indexed.key()).orElse(null);
            if (event == null || !event.region().equals(region)
                    || (startTime != null && event.eventTimeMillis() < startTime.toEpochMilli())
                    || (endTime != null && event.eventTimeMillis() > endTime.toEpochMilli())
                    || (attributeKey != null && !matches(event, attributeKey, attributeValue))) {
                continue;
            }
            if (events.size() == limit) {
                return new Page(events, lastKey);
            }
            events.add(event);
            lastKey = indexed.key();
        }
        return new Page(events, null);
    }

    private void throttle(String accountId, String region) {
        long now = System.currentTimeMillis();
        Deque<Long> times = lookupTimes.computeIfAbsent(accountId + "/" + region, k -> new ArrayDeque<>());
        while (!times.isEmpty() && times.peekFirst() <= now - 1000) {
            times.pollFirst();
        }
        if (times.size() >= lookupRateLimit) {
            throw new AwsException("ThrottlingException", "Rate exceeded", 400);
        }
        times.addLast(now);
    }

    private static boolean matches(HistoryEvent event, String key, String value) {
        return switch (key) {
            case "EventId" -> event.eventId().equals(value);
            case "EventName" -> event.eventName().equals(value);
            case "EventSource" -> event.eventSource().equals(value);
            case "ReadOnly" -> String.valueOf(event.readOnly()).equals(value);
            case "Username" -> value != null && value.equals(event.username());
            case "AccessKeyId" -> value != null && value.equals(event.accessKeyId());
            case "ResourceType" -> event.resources().stream().anyMatch(r -> r.resourceType().equals(value));
            case "ResourceName" -> event.resources().stream().anyMatch(r -> r.resourceName().equals(value));
            default -> false;
        };
    }

    private static String username(JsonNode identity) {
        String arn = identity.path("arn").asText("");
        return switch (identity.path("type").asText()) {
            case "Root" -> "root";
            case "IAMUser" -> identity.path("userName").asText(null);
            case "AssumedRole", "FederatedUser" -> arn.substring(arn.lastIndexOf('/') + 1);
            default -> null;
        };
    }

    private static List<HistoryEvent.Resource> resources(JsonNode record) {
        List<HistoryEvent.Resource> resources = new ArrayList<>();
        record.path("resources").forEach(resource -> resources.add(
                new HistoryEvent.Resource(resource.path("type").asText(), resource.path("ARN").asText())));
        return resources;
    }
}
