package io.github.hectorvent.floci.services.ec2;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AvailabilityZoneIds;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.ec2.model.FlowLog;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.InstanceNetworkInterface;
import io.github.hectorvent.floci.services.ec2.model.NetworkInterface;
import io.github.hectorvent.floci.services.ec2.model.Reservation;
import io.github.hectorvent.floci.services.ec2.model.VpcEndpoint;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;

/**
 * VPC Flow Logs: the CreateFlowLogs/DescribeFlowLogs/DeleteFlowLogs state and record delivery.
 *
 * <p>In {@code observed} mode {@link FlowCaptureService} feeds real per-ENI observations into
 * {@link #ingest}, which aggregates them per window and writes S3 files and CloudWatch Logs
 * events in AWS's layouts. In {@code synthetic} mode a background generator fabricates records
 * from the EC2 inventory instead, and in {@code off} mode nothing is delivered.</p>
 */
@ApplicationScoped
public class FlowLogService {

    private static final Logger LOG = Logger.getLogger(FlowLogService.class);

    /**
     * The format a flow log is created with when CreateFlowLogs omits LogFormat, which
     * DescribeFlowLogs reports for it thereafter. Version 2 fields in the order AWS documents.
     */
    public static final String DEFAULT_LOG_FORMAT =
            "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} "
            + "${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}";

    /**
     * Every field a flow log record can carry, against the format version that introduced it.
     *
     * <p>The version a record reports is the highest of the versions its selected fields belong
     * to, which is how AWS numbers a format. A record of version 2 fields alone reports 2, and one
     * naming any version 5 field reports 5.
     */
    private static final Map<String, Integer> FIELD_VERSIONS = Map.ofEntries(
            Map.entry("version", 2), Map.entry("account-id", 2), Map.entry("interface-id", 2),
            Map.entry("srcaddr", 2), Map.entry("dstaddr", 2), Map.entry("srcport", 2),
            Map.entry("dstport", 2), Map.entry("protocol", 2), Map.entry("packets", 2),
            Map.entry("bytes", 2), Map.entry("start", 2), Map.entry("end", 2),
            Map.entry("action", 2), Map.entry("log-status", 2),
            Map.entry("vpc-id", 3), Map.entry("subnet-id", 3), Map.entry("instance-id", 3),
            Map.entry("tcp-flags", 3), Map.entry("type", 3), Map.entry("pkt-srcaddr", 3),
            Map.entry("pkt-dstaddr", 3),
            Map.entry("region", 4), Map.entry("az-id", 4), Map.entry("sublocation-type", 4),
            Map.entry("sublocation-id", 4),
            Map.entry("pkt-src-aws-service", 5), Map.entry("pkt-dst-aws-service", 5),
            Map.entry("flow-direction", 5), Map.entry("traffic-path", 5),
            Map.entry("ecs-cluster-arn", 7), Map.entry("ecs-cluster-name", 7),
            Map.entry("ecs-container-instance-arn", 7), Map.entry("ecs-container-instance-id", 7),
            Map.entry("ecs-container-id", 7), Map.entry("ecs-second-container-id", 7),
            Map.entry("ecs-service-name", 7), Map.entry("ecs-task-definition-arn", 7),
            Map.entry("ecs-task-arn", 7), Map.entry("ecs-task-id", 7),
            Map.entry("reject-reason", 8));

    /** One ${field-name} token of a LogFormat, validated against {@link #FIELD_VERSIONS} on create. */
    private static final Pattern FIELD_TOKEN = Pattern.compile("\\$\\{([^}\\s]+)\\}");

    /**
     * The fields a flow log created without a LogFormat delivers, read from the same constant the
     * describe reports rather than repeated, so the two cannot drift apart.
     */
    static final List<String> DEFAULT_FIELDS = tokensOf(DEFAULT_LOG_FORMAT);

    private static final DateTimeFormatter DATE_FMT =
            DateTimeFormatter.ofPattern("yyyy/MM/dd").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter HIVE_DATE_FMT =
            DateTimeFormatter.ofPattern("'year='yyyy/'month='MM/'day='dd").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter HOUR_FMT =
            DateTimeFormatter.ofPattern("HH").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter FILE_TS_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmm'Z'").withZone(ZoneOffset.UTC);

    // flowLogId -> FlowLog (persisted via StorageFactory so flow logs survive a
    // restart in persistent/hybrid/wal modes and generation resumes)
    private final StorageBackend<String, FlowLog> flowLogs;

    private final Ec2Service ec2Service;
    private final S3Service s3Service;
    private final CloudWatchLogsService logsService;
    private final String mode;
    private final int s3PublishIntervalSeconds;
    private final Map<String, Window> windows = new HashMap<>();
    private final Map<String, List<String>> pendingS3 = new HashMap<>();
    private final Map<String, Instant> lastS3Publish = new HashMap<>();
    private ScheduledExecutorService scheduler;

    @Inject
    public FlowLogService(Ec2Service ec2Service, S3Service s3Service, CloudWatchLogsService logsService,
                          StorageFactory storageFactory, EmulatorConfig config) {
        this(ec2Service, s3Service, logsService,
                storageFactory.create("ec2", "ec2-flow-logs.json", new TypeReference<Map<String, FlowLog>>() {}),
                config.services().ec2().flowLogs().mode()
                        .orElse(config.network().securityGroupEnforcement().enabled() ? "observed" : "synthetic"),
                config.services().ec2().flowLogs().s3PublishIntervalSeconds());
    }

    // Package-private for hermetic tests (pass an in-memory StorageBackend directly).
    FlowLogService(Ec2Service ec2Service, S3Service s3Service, CloudWatchLogsService logsService,
                   StorageBackend<String, FlowLog> flowLogs, String mode, int s3PublishIntervalSeconds) {
        this.ec2Service = ec2Service;
        this.s3Service = s3Service;
        this.logsService = logsService;
        this.flowLogs = flowLogs;
        this.mode = mode;
        this.s3PublishIntervalSeconds = s3PublishIntervalSeconds;
    }

    /** observed, synthetic or off. */
    public String mode() {
        return mode;
    }

    void onStart(@Observes StartupEvent ev) {
        if (!"synthetic".equals(mode)) {
            LOG.infov("Flow logs mode: {0}", mode);
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "floci-flowlog-generator");
            t.setDaemon(true);
            return t;
        });
        // Periodically deliver a fresh batch for every active flow log so the
        // emulated environment shows continuous traffic. Interval kept short
        // (60s) so consumers see flows quickly; AWS real interval is 60/600s.
        scheduler.scheduleAtFixedRate(this::generateForAll, 60, 60, TimeUnit.SECONDS);
        LOG.info("FlowLog generator scheduled (every 60s)");
    }

    void onStop(@Observes ShutdownEvent ev) {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    // ─── CRUD ───────────────────────────────────────────────────────────────

    public FlowLog createFlowLog(String region, String resourceId, String resourceType,
                                 String trafficType, String logDestinationType,
                                 String logDestination, String deliverLogsPermissionArn,
                                 String logFormat, int maxAggregationInterval) {
        return createFlowLog(region, resourceId, resourceType, trafficType, logDestinationType, logDestination,
                null, deliverLogsPermissionArn, logFormat, maxAggregationInterval, null, false, false);
    }

    public FlowLog createFlowLog(String region, String resourceId, String resourceType,
                                 String trafficType, String logDestinationType,
                                 String logDestination, String logGroupName, String deliverLogsPermissionArn,
                                 String logFormat, int maxAggregationInterval, String fileFormat,
                                 boolean hiveCompatiblePartitions, boolean perHourPartition) {
        if (resourceType == null) {
            throw new AwsException("MissingParameter", "The request must contain the parameter ResourceType.", 400);
        }
        if (!Set.of("VPC", "Subnet", "NetworkInterface").contains(resourceType)) {
            throw new AwsException("InvalidParameterValue",
                    "Value (" + resourceType + ") for parameter ResourceType is invalid.", 400);
        }
        String traffic = trafficType != null ? trafficType : "ALL";
        if (!Set.of("ALL", "ACCEPT", "REJECT").contains(traffic)) {
            throw new AwsException("InvalidParameterValue",
                    "Value (" + traffic + ") for parameter TrafficType is invalid.", 400);
        }
        String destinationType = logDestinationType != null ? logDestinationType : "cloud-watch-logs";
        if ("kinesis-data-firehose".equals(destinationType)) {
            throw new AwsException("UnsupportedOperation",
                    "The log destination type kinesis-data-firehose is not supported.", 400);
        }
        if (maxAggregationInterval != 60 && maxAggregationInterval != 600) {
            throw new AwsException("InvalidParameterValue", "Value (" + maxAggregationInterval
                    + ") for parameter MaxAggregationInterval is invalid. Valid values are 60 and 600.", 400);
        }
        String format = fileFormat != null ? fileFormat : "plain-text";
        if ("parquet".equals(format)) {
            throw new AwsException("UnsupportedOperation", "The file format parquet is not supported.", 400);
        }
        if (!"plain-text".equals(format)) {
            throw new AwsException("InvalidParameterValue",
                    "Value (" + format + ") for parameter FileFormat is invalid.", 400);
        }
        String groupName = logGroupName;
        switch (destinationType) {
            case "s3" -> {
                if (logDestination == null || logDestination.isBlank()) {
                    throw new AwsException("InvalidParameter", "LogDestination is required for an s3 destination.", 400);
                }
            }
            case "cloud-watch-logs" -> {
                if (groupName == null && logDestination != null) {
                    groupName = logGroupFromArn(logDestination);
                }
                if (groupName == null || groupName.isBlank()) {
                    throw new AwsException("InvalidParameter",
                            "LogGroupName or LogDestination is required for a cloud-watch-logs destination.", 400);
                }
                if (deliverLogsPermissionArn == null || deliverLogsPermissionArn.isBlank()) {
                    throw new AwsException("InvalidParameter",
                            "DeliverLogsPermissionArn is required for a cloud-watch-logs destination.", 400);
                }
            }
            default -> throw new AwsException("InvalidParameterValue",
                    "Value (" + destinationType + ") for parameter LogDestinationType is invalid.", 400);
        }
        if (logFormat != null && !logFormat.isBlank()) {
            List<String> unknown = tokensOf(logFormat).stream().filter(f -> !FIELD_VERSIONS.containsKey(f)).toList();
            if (!unknown.isEmpty()) {
                throw new AwsException("InvalidParameter", "Unknown fields provided: ${"
                        + String.join("}, ${", unknown) + "}", 400);
            }
        }

        FlowLog fl = new FlowLog();
        fl.setFlowLogId("fl-" + randomHex(17));
        fl.setResourceId(resourceId);
        fl.setResourceType(resourceType);
        fl.setTrafficType(traffic);
        fl.setLogDestinationType(destinationType);
        fl.setLogDestination(logDestination);
        fl.setLogGroupName(groupName);
        fl.setDeliverLogsPermissionArn(deliverLogsPermissionArn);
        fl.setBucketName("s3".equals(destinationType) ? bucketFromArn(logDestination) : null);
        fl.setLogFormat(logFormat);
        fl.setMaxAggregationInterval(maxAggregationInterval);
        fl.setFileFormat(format);
        fl.setHiveCompatiblePartitions(hiveCompatiblePartitions);
        fl.setPerHourPartition(perHourPartition);
        fl.setRegion(region);
        fl.setAccountId(ec2Service.callerAccountId());
        flowLogs.put(fl.getFlowLogId(), fl);
        LOG.infov("Created flow log {0} for {1} {2} -> {3}",
                fl.getFlowLogId(), fl.getResourceType(), resourceId, destinationType);

        // Deliver an initial batch right away so flows are visible without
        // waiting for the first scheduled tick.
        if ("synthetic".equals(mode) && "s3".equals(fl.getLogDestinationType()) && fl.getBucketName() != null) {
            try {
                generateAndDeliver(fl);
            } catch (Exception e) {
                LOG.warnv("Initial flow-log delivery failed for {0}: {1}", fl.getFlowLogId(), e.getMessage());
            }
        }
        return fl;
    }

    public List<FlowLog> describeFlowLogs(String region, List<String> flowLogIds) {
        List<FlowLog> result = new ArrayList<>();
        for (FlowLog fl : flowLogs.scan(k -> true)) {
            if (region != null && fl.getRegion() != null && !region.equals(fl.getRegion())) {
                continue;
            }
            if (flowLogIds != null && !flowLogIds.isEmpty() && !flowLogIds.contains(fl.getFlowLogId())) {
                continue;
            }
            result.add(fl);
        }
        return result;
    }

    public List<String> deleteFlowLogs(String region, List<String> flowLogIds) {
        List<String> deleted = new ArrayList<>();
        if (flowLogIds == null) {
            return deleted;
        }
        for (String id : flowLogIds) {
            FlowLog fl = flowLogs.get(id).orElse(null);
            if (fl == null) {
                continue;
            }
            if (region != null && fl.getRegion() != null && !region.equals(fl.getRegion())) {
                continue;
            }
            flowLogs.delete(id);
            deleted.add(id);
        }
        return deleted;
    }

    // ─── Observed delivery ──────────────────────────────────────────────────────

    /** One managed ENI as a flow record describes it. {@code ecs} holds the v7 fields of a task ENI. */
    public record FlowEni(String eniId, String accountId, String region, String vpcId, String subnetId,
                          String instanceId, String availabilityZone, Map<String, String> ecs) {}

    /** What identifies one record: an ENI, a 5-tuple, a direction and an action. */
    public record FlowKey(String eniId, String srcAddr, String dstAddr, int srcPort, int dstPort,
                          int protocol, String direction, String action, String peerService,
                          String trafficPath) {}

    /** Packets and bytes one tick observed for a key, with the TCP flags seen. */
    public record FlowObservation(FlowKey key, long packets, long bytes, int tcpFlags) {}

    /**
     * Adds one capture tick: the managed ENIs that exist now and the traffic they carried since
     * the previous tick. Closes every aggregation window that has run its interval, and writes S3
     * files on the publish interval.
     */
    public synchronized void ingest(Instant now, List<FlowEni> enis, List<FlowObservation> observations) {
        Set<String> ids = new HashSet<>();
        for (FlowLog fl : flowLogs.scan(k -> true)) {
            String id = fl.getFlowLogId();
            ids.add(id);
            Window window = windows.computeIfAbsent(id, k -> new Window(now.getEpochSecond()));
            lastS3Publish.putIfAbsent(id, now);
            Map<String, FlowEni> covered = new HashMap<>();
            for (FlowEni eni : enis) {
                if (covers(fl, eni)) {
                    covered.put(eni.eniId(), eni);
                }
            }
            window.members.putAll(covered);
            for (FlowObservation observation : observations) {
                FlowKey key = observation.key();
                if (covered.containsKey(key.eniId())
                        && ("ALL".equals(fl.getTrafficType()) || fl.getTrafficType().equals(key.action()))) {
                    window.add(observation, now.getEpochSecond());
                }
            }
            if (now.getEpochSecond() >= window.start + fl.getMaxAggregationInterval()) {
                deliver(fl, window, now.getEpochSecond());
                windows.put(id, new Window(now.getEpochSecond()));
            }
            List<String> pending = pendingS3.get(id);
            if (pending != null && !pending.isEmpty()
                    && !now.isBefore(lastS3Publish.get(id).plusSeconds(s3PublishIntervalSeconds))) {
                writeS3(fl, pending, now);
                pending.clear();
                lastS3Publish.put(id, now);
            }
        }
        windows.keySet().retainAll(ids);
        pendingS3.keySet().retainAll(ids);
        lastS3Publish.keySet().retainAll(ids);
    }

    private static boolean covers(FlowLog fl, FlowEni eni) {
        if (!eni.accountId().equals(fl.getAccountId()) || !eni.region().equals(fl.getRegion())) {
            return false;
        }
        String rid = fl.getResourceId();
        return switch (fl.getResourceType()) {
            case "VPC" -> rid.equals(eni.vpcId());
            case "Subnet" -> rid.equals(eni.subnetId());
            case "NetworkInterface" -> rid.equals(eni.eniId());
            default -> false;
        };
    }

    /** Renders a closed window, one NODATA record for each covered ENI that carried nothing. */
    private void deliver(FlowLog fl, Window window, long end) {
        List<String> fields = fieldsOf(fl);
        String version = formatVersion(fields);
        Map<String, List<Long>> startsByEni = new LinkedHashMap<>();
        Map<String, List<String>> rowsByEni = new LinkedHashMap<>();
        List<Map.Entry<FlowKey, Aggregate>> flows = new ArrayList<>(window.flows.entrySet());
        flows.sort(Comparator.comparingLong(e -> e.getValue().first));
        for (Map.Entry<FlowKey, Aggregate> flow : flows) {
            FlowKey key = flow.getKey();
            Aggregate agg = flow.getValue();
            FlowEni eni = window.members.get(key.eniId());
            Map<String, String> values = new HashMap<>(eni.ecs());
            values.put("version", version);
            values.put("account-id", eni.accountId());
            values.put("interface-id", eni.eniId());
            values.put("srcaddr", key.srcAddr());
            values.put("dstaddr", key.dstAddr());
            values.put("srcport", String.valueOf(key.srcPort()));
            values.put("dstport", String.valueOf(key.dstPort()));
            values.put("protocol", String.valueOf(key.protocol()));
            values.put("packets", String.valueOf(agg.packets));
            values.put("bytes", String.valueOf(agg.bytes));
            values.put("start", String.valueOf(agg.first));
            values.put("end", String.valueOf(agg.last));
            values.put("action", key.action());
            values.put("log-status", "OK");
            values.put("vpc-id", nz(eni.vpcId()));
            values.put("subnet-id", nz(eni.subnetId()));
            values.put("instance-id", nz(eni.instanceId()));
            values.put("tcp-flags", String.valueOf(agg.tcpFlags));
            values.put("type", key.srcAddr().contains(":") ? "IPv6" : "IPv4");
            values.put("pkt-srcaddr", key.srcAddr());
            values.put("pkt-dstaddr", key.dstAddr());
            values.put("region", eni.region());
            values.put("az-id", nz(azId(eni.region(), eni.availabilityZone())));
            boolean egress = "egress".equals(key.direction());
            values.put("pkt-src-aws-service", !egress ? nz(key.peerService()) : "-");
            values.put("pkt-dst-aws-service", egress ? nz(key.peerService()) : "-");
            values.put("flow-direction", key.direction());
            values.put("traffic-path", nz(key.trafficPath()));
            rowsByEni.computeIfAbsent(eni.eniId(), k -> new ArrayList<>()).add(render(fields, values));
            startsByEni.computeIfAbsent(eni.eniId(), k -> new ArrayList<>()).add(agg.first);
        }
        for (FlowEni eni : window.members.values()) {
            if (rowsByEni.containsKey(eni.eniId())) {
                continue;
            }
            rowsByEni.put(eni.eniId(), List.of(render(fields, Map.of(
                    "version", version, "account-id", eni.accountId(), "interface-id", eni.eniId(),
                    "start", String.valueOf(window.start), "end", String.valueOf(end), "log-status", "NODATA"))));
            startsByEni.put(eni.eniId(), List.of(window.start));
        }
        if (rowsByEni.isEmpty()) {
            return;
        }
        if ("s3".equals(fl.getLogDestinationType())) {
            List<String> pending = pendingS3.computeIfAbsent(fl.getFlowLogId(), k -> new ArrayList<>());
            rowsByEni.values().forEach(pending::addAll);
        } else {
            rowsByEni.forEach((eniId, rows) -> writeCloudWatch(fl, eniId, rows, startsByEni.get(eniId)));
        }
    }

    private void writeS3(FlowLog fl, List<String> rows, Instant now) {
        String key = s3Key(fl, now);
        try {
            s3Service.putObject(fl.getBucketName(), key,
                    gzip(String.join(" ", fieldsOf(fl)) + "\n" + String.join("\n", rows) + "\n"),
                    "application/octet-stream", Map.of("content-encoding", "gzip"));
            LOG.debugv("Delivered {0} flow records to s3://{1}/{2}", rows.size(), fl.getBucketName(), key);
        } catch (RuntimeException e) {
            LOG.warnv("Flow log {0} could not deliver {1} records to s3://{2}/{3}: {4}",
                    fl.getFlowLogId(), rows.size(), fl.getBucketName(), key, e.getMessage());
        }
    }

    /** One stream per ENI, named for the traffic type, each record an event stamped with its start. */
    private void writeCloudWatch(FlowLog fl, String eniId, List<String> rows, List<Long> starts) {
        String group = fl.getLogGroupName();
        String stream = eniId + "-" + fl.getTrafficType().toLowerCase(Locale.ROOT);
        try {
            if (!logsService.logGroupExists(group, fl.getRegion())) {
                logsService.createLogGroupForAccount(fl.getAccountId(), group, null, Map.of(), fl.getRegion());
            }
            try {
                logsService.createLogStreamForAccount(fl.getAccountId(), group, stream, fl.getRegion());
            } catch (AwsException e) {
                if (!"ResourceAlreadyExistsException".equals(e.getErrorCode())) {
                    throw e;
                }
            }
            List<Map<String, Object>> events = new ArrayList<>();
            for (int i = 0; i < rows.size(); i++) {
                events.add(Map.of("timestamp", starts.get(i) * 1000, "message", rows.get(i)));
            }
            events.sort(Comparator.comparingLong(e -> (Long) e.get("timestamp")));
            logsService.putLogEventsForAccount(fl.getAccountId(), group, stream, events, fl.getRegion());
        } catch (RuntimeException e) {
            LOG.warnv("Flow log {0} could not deliver {1} records to {2}/{3}: {4}",
                    fl.getFlowLogId(), rows.size(), group, stream, e.getMessage());
        }
    }

    private static final class Window {
        final long start;
        final Map<String, FlowEni> members = new HashMap<>();
        final Map<FlowKey, Aggregate> flows = new HashMap<>();

        Window(long start) {
            this.start = start;
        }

        void add(FlowObservation observation, long tick) {
            Aggregate agg = flows.computeIfAbsent(observation.key(), k -> new Aggregate(tick));
            agg.packets += observation.packets();
            agg.bytes += observation.bytes();
            agg.tcpFlags |= observation.tcpFlags();
            agg.last = tick;
        }
    }

    private static final class Aggregate {
        final long first;
        long last;
        long packets;
        long bytes;
        int tcpFlags;

        Aggregate(long first) {
            this.first = first;
            this.last = first;
        }
    }

    // ─── Generation ───────────────────────────────────────────────────────────

    private void generateForAll() {
        for (FlowLog fl : flowLogs.scan(k -> true)) {
            if (!"s3".equals(fl.getLogDestinationType()) || fl.getBucketName() == null) {
                continue;
            }
            try {
                generateAndDeliver(fl);
            } catch (Exception e) {
                LOG.warnv("Scheduled flow-log delivery failed for {0}: {1}", fl.getFlowLogId(), e.getMessage());
            }
        }
    }

    /**
     * Synthesize one flow-log file for the given flow log and write it to S3
     * at the AWS-native key prefix. Records are derived from the live EC2
     * inventory of the flow log's resource (its instances/ENIs).
     */
    void generateAndDeliver(FlowLog fl) {
        List<Eni> enis = resolveEnis(fl);
        if (enis.isEmpty()) {
            LOG.debugv("No ENIs found for flow log {0} resource {1}; skipping",
                    fl.getFlowLogId(), fl.getResourceId());
            return;
        }

        Instant now = Instant.now();
        long endEpoch = now.getEpochSecond();
        long startEpoch = endEpoch - fl.getMaxAggregationInterval();

        List<String> fields = fieldsOf(fl);
        StringBuilder sb = new StringBuilder();
        sb.append(String.join(" ", fields)).append('\n');

        // Collect the private IPs of all sibling ENIs in this flow log's resource
        // so instances in the same VPC actually talk to EACH OTHER (not just to
        // random external peers). This yields realistic intra-VPC conversations
        // between the resources that exist in the account.
        List<String> siblingIps = new ArrayList<>();
        for (Eni e : enis) {
            if (e.privateIp != null && !e.privateIp.isBlank()) {
                siblingIps.add(e.privateIp);
            }
        }

        // Interface VPC endpoints (e.g. S3 PrivateLink) have an ENI with a private
        // IP in this VPC. Treat those as peers so instances send flows to the
        // endpoint — which is how traffic to an AWS service over PrivateLink shows
        // up in flow logs. The endpoint's service is recorded in pkt-dst-aws-service.
        List<String> endpointIps = new ArrayList<>();
        Map<String, String> endpointService = new HashMap<>(); // ip -> service short name (e.g. S3)
        String resourceVpc = vpcOfFlowLogResource(fl);
        for (NetworkInterface ni : ec2Service.endpointNetworkInterfaces(fl.getRegion())) {
            if (ni.getPrivateIpAddress() == null || ni.getPrivateIpAddress().isBlank()) {
                continue;
            }
            // Only endpoints in the same VPC this flow log covers.
            if (resourceVpc != null && ni.getVpcId() != null && !resourceVpc.equals(ni.getVpcId())) {
                continue;
            }
            endpointIps.add(ni.getPrivateIpAddress());
            endpointService.put(ni.getPrivateIpAddress(), awsServiceFromEndpoint(ni, fl.getRegion()));
        }

        int recordCount = 0;
        for (Eni eni : enis) {
            // Peers this ENI should talk to: every OTHER sibling VM in the VPC
            // (guaranteed intra-VPC edges), every interface endpoint (VM -> S3),
            // plus a couple of random external peers.
            List<String> peers = new ArrayList<>();
            for (String ip : siblingIps) {
                if (!ip.equals(eni.privateIp)) {
                    peers.add(ip); // intra-VPC: app-01 <-> web-01
                }
            }
            peers.addAll(endpointIps); // VM -> S3 endpoint
            int externals = 2 + ThreadLocalRandom.current().nextInt(2); // 2-3 external conversations
            for (int i = 0; i < externals; i++) {
                peers.add(randomPeer(eni.privateIp));
            }

            for (String peer : peers) {
                int dstPort = pickServicePort();
                int srcPortEph = 32768 + ThreadLocalRandom.current().nextInt(28000);
                String svc = endpointService.get(peer); // non-null only for endpoint peers
                // egress: eni -> peer
                sb.append(record(fl, fields, eni, eni.privateIp, peer, srcPortEph, dstPort,
                        "egress", startEpoch, endEpoch, svc)).append('\n');
                // ingress: peer -> eni (response)
                sb.append(record(fl, fields, eni, peer, eni.privateIp, dstPort, srcPortEph,
                        "ingress", startEpoch, endEpoch, svc)).append('\n');
                recordCount += 2;
            }
        }

        byte[] gz = gzip(sb.toString());
        String key = s3Key(fl, now);
        try {
            s3Service.putObject(fl.getBucketName(), key, gz, "application/octet-stream",
                    Map.of("content-encoding", "gzip"));
            LOG.infov("Delivered {0} flow records to s3://{1}/{2}", recordCount, fl.getBucketName(), key);
        } catch (RuntimeException e) {
            // Bucket may not exist yet (e.g. flow log created before the bucket).
            // Skip this delivery; the next scheduled tick will retry once it exists.
            LOG.debugv("Flow-log delivery skipped for {0} (bucket {1}): {2}",
                    fl.getFlowLogId(), fl.getBucketName(), e.getMessage());
        }
    }

    /**
     * Build one space-delimited default-format flow record line.
     *
     * @param svc AWS service short-name (e.g. "S3") when the peer is an interface
     *            VPC endpoint, else null. Sets pkt-dst-aws-service (egress) or
     *            pkt-src-aws-service (ingress) so the record looks like real
     *            AWS-service traffic.
     */
    /**
     * The fields this flow log delivers, taken from its LogFormat.
     *
     * <p>A token naming a field this emulator has no value for is kept rather than dropped, so the
     * record still has one column per token the caller asked for, carrying "-" as AWS does for a
     * field that does not apply.
     */
    static List<String> fieldsOf(FlowLog fl) {
        String format = fl.getLogFormat();
        if (format == null || format.isBlank()) {
            return DEFAULT_FIELDS;
        }
        List<String> fields = tokensOf(format);
        return fields.isEmpty() ? DEFAULT_FIELDS : fields;
    }

    /** The field names a LogFormat string names, in the order it names them. */
    private static List<String> tokensOf(String format) {
        List<String> fields = new ArrayList<>();
        Matcher matcher = FIELD_TOKEN.matcher(format);
        while (matcher.find()) {
            fields.add(matcher.group(1));
        }
        return List.copyOf(fields);
    }

    /** The version AWS numbers a format by, which is the highest any of its fields belongs to. */
    private static String formatVersion(List<String> fields) {
        int version = 2;
        for (String field : fields) {
            version = Math.max(version, FIELD_VERSIONS.getOrDefault(field, 2));
        }
        return String.valueOf(version);
    }

    private static String render(List<String> fields, Map<String, String> values) {
        StringBuilder row = new StringBuilder();
        for (String field : fields) {
            if (row.length() > 0) {
                row.append(' ');
            }
            row.append(values.getOrDefault(field, "-"));
        }
        return row.toString();
    }

    private String record(FlowLog fl, List<String> fields, Eni eni, String src, String dst,
                          int srcPort, int dstPort, String direction, long start, long end,
                          String svc) {
        int bytes = 200 + ThreadLocalRandom.current().nextInt(40000);
        int packets = 1 + ThreadLocalRandom.current().nextInt(60);
        int protocol = 6; // TCP
        String action = "ACCEPT";
        String azId = azId(fl.getRegion(), eni.az);
        int tcpFlags = "egress".equals(direction) ? 2 : 18; // SYN / SYN-ACK-ish
        boolean egress = "egress".equals(direction);
        // For endpoint traffic, the AWS service tags the side that is the endpoint:
        // egress (eni->endpoint) => dst is the service; ingress (endpoint->eni) => src.
        String pktDstSvc = (svc != null && egress) ? svc : "-";
        String pktSrcSvc = (svc != null && !egress) ? svc : "-";
        Map<String, String> values = Map.ofEntries(
                Map.entry("version", formatVersion(fields)),
                Map.entry("account-id", nz(fl.getAccountId())),
                Map.entry("interface-id", nz(eni.eniId)),
                Map.entry("srcaddr", nz(src)),
                Map.entry("dstaddr", nz(dst)),
                Map.entry("srcport", String.valueOf(srcPort)),
                Map.entry("dstport", String.valueOf(dstPort)),
                Map.entry("protocol", String.valueOf(protocol)),
                Map.entry("packets", String.valueOf(packets)),
                Map.entry("bytes", String.valueOf(bytes)),
                Map.entry("start", String.valueOf(start)),
                Map.entry("end", String.valueOf(end)),
                Map.entry("action", action),
                Map.entry("log-status", "OK"),
                Map.entry("vpc-id", nz(eni.vpcId)),
                Map.entry("subnet-id", nz(eni.subnetId)),
                Map.entry("instance-id", nz(eni.instanceId)),
                Map.entry("tcp-flags", String.valueOf(tcpFlags)),
                Map.entry("type", "IPv4"),
                Map.entry("pkt-srcaddr", nz(src)),
                Map.entry("pkt-dstaddr", nz(dst)),
                Map.entry("region", nz(fl.getRegion())),
                Map.entry("az-id", nz(azId)),
                Map.entry("sublocation-type", "-"),
                Map.entry("sublocation-id", "-"),
                Map.entry("pkt-src-aws-service", pktSrcSvc),
                Map.entry("pkt-dst-aws-service", pktDstSvc),
                Map.entry("flow-direction", direction),
                Map.entry("traffic-path", egress ? "1" : "-"));
        return render(fields, values);
    }

    // ─── Inventory correlation ─────────────────────────────────────────────────

    /** The VPC id a flow log covers (its resource is a VPC, or a subnet/eni in one). */
    private String vpcOfFlowLogResource(FlowLog fl) {
        String rid = fl.getResourceId();
        if (rid == null) {
            return null;
        }
        if (rid.startsWith("vpc-")) {
            return rid;
        }
        // subnet/eni: find the owning VPC from a matching instance ENI.
        List<Reservation> reservations = ec2Service.describeInstances(fl.getRegion(), List.of(), Map.of());
        for (Reservation res : reservations) {
            for (Instance inst : res.getInstances()) {
                if (rid.equals(inst.getSubnetId())) {
                    return inst.getVpcId();
                }
                List<InstanceNetworkInterface> nis = inst.getNetworkInterfaces();
                if (nis != null) {
                    for (InstanceNetworkInterface ni : nis) {
                        if (rid.equals(ni.getNetworkInterfaceId()) || rid.equals(ni.getSubnetId())) {
                            return ni.getVpcId() != null ? ni.getVpcId() : inst.getVpcId();
                        }
                    }
                }
            }
        }
        return null;
    }

    /** Map an endpoint ENI to its service short tag (com.amazonaws.us-east-1.s3 -> S3). */
    private String awsServiceFromEndpoint(NetworkInterface eni, String region) {
        String desc = eni.getDescription(); // "VPC Endpoint Interface vpce-..."
        int marker = desc != null ? desc.indexOf("vpce-") : -1;
        if (marker >= 0) {
            String endpointId = desc.substring(marker).trim();
            try {
                for (VpcEndpoint endpoint : ec2Service.describeVpcEndpoints(region, List.of(endpointId), Map.of())) {
                    String serviceName = endpoint.getServiceName();
                    if (serviceName != null && serviceName.contains(".")) {
                        return serviceName.substring(serviceName.lastIndexOf('.') + 1).toUpperCase();
                    }
                }
            } catch (AwsException e) {
                LOG.debugv("Endpoint {0} not resolvable for service tagging: {1}", endpointId, e.getMessage());
            }
        }
        return "S3";
    }

    /** Resolve the ENIs to attribute flows to, based on the flow log's resource. */
    private List<Eni> resolveEnis(FlowLog fl) {
        List<Eni> enis = new ArrayList<>();
        String region = fl.getRegion();
        String resourceId = fl.getResourceId();
        String resourceType = fl.getResourceType();

        List<Reservation> reservations = ec2Service.describeInstances(region, List.of(), Map.of());
        for (Reservation res : reservations) {
            for (Instance inst : res.getInstances()) {
                boolean match = switch (resourceType) {
                    case "VPC" -> resourceId == null || resourceId.equals(inst.getVpcId());
                    case "Subnet" -> resourceId == null || resourceId.equals(inst.getSubnetId());
                    case "NetworkInterface" -> hasEni(inst, resourceId);
                    default -> true;
                };
                if (!match) {
                    continue;
                }
                String az = inst.getPlacement() != null ? inst.getPlacement().getAvailabilityZone() : region + "a";
                List<InstanceNetworkInterface> nis = inst.getNetworkInterfaces();
                if (nis != null && !nis.isEmpty()) {
                    for (InstanceNetworkInterface ni : nis) {
                        if ("NetworkInterface".equals(resourceType) && resourceId != null
                                && !resourceId.equals(ni.getNetworkInterfaceId())) {
                            continue;
                        }
                        Eni e = new Eni();
                        e.eniId = ni.getNetworkInterfaceId();
                        e.privateIp = ni.getPrivateIpAddress() != null ? ni.getPrivateIpAddress() : inst.getPrivateIpAddress();
                        e.instanceId = inst.getInstanceId();
                        e.subnetId = ni.getSubnetId() != null ? ni.getSubnetId() : inst.getSubnetId();
                        e.vpcId = ni.getVpcId() != null ? ni.getVpcId() : inst.getVpcId();
                        e.az = az;
                        enis.add(e);
                    }
                } else {
                    // Fall back to a synthetic ENI from instance fields.
                    Eni e = new Eni();
                    e.eniId = "eni-" + randomHex(17);
                    e.privateIp = inst.getPrivateIpAddress();
                    e.instanceId = inst.getInstanceId();
                    e.subnetId = inst.getSubnetId();
                    e.vpcId = inst.getVpcId();
                    e.az = az;
                    enis.add(e);
                }
            }
        }
        return enis;
    }

    private boolean hasEni(Instance inst, String eniId) {
        if (eniId == null || inst.getNetworkInterfaces() == null) {
            return false;
        }
        return inst.getNetworkInterfaces().stream()
                .anyMatch(ni -> eniId.equals(ni.getNetworkInterfaceId()));
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    /** The VPC-S3PATH key: optional prefix, plain or Hive partitions, optional hour partition. */
    String s3Key(FlowLog fl, Instant when) {
        String name = AwsArnUtils.resourceIfArnFor(fl.getLogDestination(), "s3").orElse(fl.getLogDestination());
        int slash = name.indexOf('/');
        String prefix = slash >= 0 && slash < name.length() - 1 ? name.substring(slash + 1) : "";
        if (!prefix.isEmpty() && !prefix.endsWith("/")) {
            prefix += "/";
        }
        String partitions = fl.isHiveCompatiblePartitions()
                ? "AWSLogs/aws-account-id=" + fl.getAccountId() + "/aws-service=vpcflowlogs/aws-region="
                        + fl.getRegion() + "/" + HIVE_DATE_FMT.format(when) + "/"
                        + (fl.isPerHourPartition() ? "hour=" + HOUR_FMT.format(when) + "/" : "")
                : "AWSLogs/" + fl.getAccountId() + "/vpcflowlogs/" + fl.getRegion() + "/" + DATE_FMT.format(when) + "/"
                        + (fl.isPerHourPartition() ? HOUR_FMT.format(when) + "/" : "");
        return prefix + partitions + fl.getAccountId() + "_vpcflowlogs_" + fl.getRegion() + "_" + fl.getFlowLogId()
                + "_" + FILE_TS_FMT.format(when) + "_" + randomHex(8) + ".log.gz";
    }

    static String logGroupFromArn(String arn) {
        String resource = AwsArnUtils.resourceIfArnFor(arn, "logs").orElse(null);
        if (resource == null || !resource.startsWith("log-group:")) {
            return arn.contains(":") ? null : arn;
        }
        String name = resource.substring("log-group:".length());
        return name.endsWith(":*") ? name.substring(0, name.length() - 2) : name;
    }

    private static byte[] gzip(String content) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
                gz.write(content.getBytes(StandardCharsets.UTF_8));
            }
            return bos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("gzip failed", e);
        }
    }

    static String bucketFromArn(String arn) {
        if (arn == null) {
            return null;
        }
        // arn:aws:s3:::bucket-name[/optional/prefix] OR a bare bucket name. The prefix may itself
        // contain ':', so the resource is everything after the ARN's fifth ':', not its last.
        String name = AwsArnUtils.resourceIfArnFor(arn, "s3").orElse(arn);
        int slash = name.indexOf('/');
        return slash >= 0 ? name.substring(0, slash) : name;
    }

    /** Random peer IP: ~half inside the same /16 (intra-VPC), half "external". */
    private static String randomPeer(String selfIp) {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        if (selfIp != null && selfIp.contains(".") && r.nextBoolean()) {
            String[] o = selfIp.split("\\.");
            if (o.length == 4) {
                return o[0] + "." + o[1] + "." + r.nextInt(256) + "." + (1 + r.nextInt(254));
            }
        }
        return "10." + r.nextInt(256) + "." + r.nextInt(256) + "." + (1 + r.nextInt(254));
    }

    private static int pickServicePort() {
        int[] ports = {443, 80, 53, 5432, 3306, 6379, 8080, 22};
        return ports[ThreadLocalRandom.current().nextInt(ports.length)];
    }

    /**
     * The zone id of the ENI's zone, derived exactly as subnets and DescribeAvailabilityZones
     * derive it ({@link AvailabilityZoneIds}), so a record's {@code az-id} matches the
     * {@code AvailabilityZoneId} of the subnet it came from, in every region and partition.
     */
    private static String azId(String region, String az) {
        return region == null ? null : AvailabilityZoneIds.forZoneName(region, az);
    }

    private static String nz(String s) {
        return (s == null || s.isEmpty()) ? "-" : s;
    }

    private static String randomHex(int len) {
        String chars = "0123456789abcdef";
        StringBuilder sb = new StringBuilder(len);
        ThreadLocalRandom r = ThreadLocalRandom.current();
        for (int i = 0; i < len; i++) {
            sb.append(chars.charAt(r.nextInt(chars.length())));
        }
        return sb.toString();
    }

    /** Lightweight holder for the ENI fields a flow record needs. */
    private static final class Eni {
        String eniId;
        String privateIp;
        String instanceId;
        String subnetId;
        String vpcId;
        String az;
    }
}
