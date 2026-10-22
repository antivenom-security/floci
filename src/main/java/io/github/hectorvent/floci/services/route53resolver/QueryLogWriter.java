package io.github.hectorvent.floci.services.route53resolver;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.dns.DnsQueryObserver;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.SecurityGroupFirewallManager;
import io.github.hectorvent.floci.services.ec2.SecurityGroupNftCompiler;
import io.github.hectorvent.floci.services.ec2.model.NetworkInterface;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.Startup;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

/**
 * Route 53 Resolver query logging. Each query the embedded DNS server answers is traced from its
 * source address to the managed ENI whose namespace sent it, and from there to its VPC; when that
 * VPC is associated with a query logging configuration, the query is buffered as an AWS query-log
 * record and written to the configuration's S3 bucket or CloudWatch Logs group on its cadence.
 *
 * <p>Only ENIs with a security-group namespace have a source address Floci can recognise, so query
 * logs need {@code floci.network.security-group-enforcement.enabled}. Floci's DNS server has no
 * cache, so every query is logged, where AWS logs only the ones its resolver did not answer from cache.
 */
@Startup
@ApplicationScoped
public class QueryLogWriter implements DnsQueryObserver {

    private static final Logger LOG = Logger.getLogger(QueryLogWriter.class);
    private static final DateTimeFormatter SLOT = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmm'Z'")
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy/MM/dd").withZone(ZoneOffset.UTC);

    record S3Target(String bucket, String prefix, String accountId, String vpcId) {}

    record LogsTarget(String accountId, String region, String logGroup, String vpcId, String sourceId) {}

    private final EmulatorConfig config;
    private final Route53ResolverService resolverService;
    private final SecurityGroupFirewallManager firewallManager;
    private final Ec2Service ec2Service;
    private final S3Service s3Service;
    private final CloudWatchLogsService logsService;
    private final ObjectMapper mapper;
    private Map<S3Target, List<String>> s3Pending = new HashMap<>();
    private Map<LogsTarget, List<Map<String, Object>>> logsPending = new HashMap<>();
    private ScheduledExecutorService executor;

    @Inject
    public QueryLogWriter(EmulatorConfig config, Route53ResolverService resolverService,
                          SecurityGroupFirewallManager firewallManager, Ec2Service ec2Service,
                          S3Service s3Service,
                          CloudWatchLogsService logsService, ObjectMapper mapper) {
        this.config = config;
        this.resolverService = resolverService;
        this.firewallManager = firewallManager;
        this.ec2Service = ec2Service;
        this.s3Service = s3Service;
        this.logsService = logsService;
        this.mapper = mapper;
    }

    @PostConstruct
    void start() {
        if (!config.services().route53resolver().enabled()) {
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "route53resolver-query-log-writer");
            t.setDaemon(true);
            return t;
        });
        int s3Interval = Math.max(1, config.services().route53resolver().queryLogS3IntervalSeconds());
        int logsInterval = Math.max(1, config.services().route53resolver().queryLogCloudwatchIntervalSeconds());
        executor.scheduleAtFixedRate(this::flushS3, s3Interval, s3Interval, TimeUnit.SECONDS);
        executor.scheduleAtFixedRate(this::flushLogs, logsInterval, logsInterval, TimeUnit.SECONDS);
    }

    void stop(@Observes ShutdownEvent event) {
        if (executor != null) {
            flushNow();
            executor.shutdownNow();
            executor = null;
        }
    }

    public void flushNow() {
        flushS3();
        flushLogs();
    }

    @Override
    public void observe(DnsQueryObserver.Query query) {
        if (!config.services().route53resolver().enabled() || !firewallManager.enabled()) {
            return;
        }
        Optional<SecurityGroupNftCompiler.Endpoint> source = firewallManager.endpointAt(query.sourceAddress());
        if (source.isEmpty()) {
            return;
        }
        SecurityGroupNftCompiler.Endpoint eni = source.orElseThrow();
        List<String> destinations = resolverService.queryLogDestinationsFor(eni.accountId(), eni.region(),
                eni.vpcId());
        if (destinations.isEmpty()) {
            return;
        }
        String instanceId = instanceOf(eni);
        String line = record(query, eni, instanceId).toString();
        synchronized (this) {
            for (String destination : destinations) {
                Optional<String> bucketPath = AwsArnUtils.resourceIfArnFor(destination, "s3");
                if (bucketPath.isPresent()) {
                    String[] parts = bucketPath.orElseThrow().split("/", 2);
                    s3Pending.computeIfAbsent(new S3Target(parts[0], parts.length > 1 ? parts[1] : "",
                            eni.accountId(), eni.vpcId()), k -> new ArrayList<>()).add(line);
                    continue;
                }
                AwsArnUtils.Arn group = AwsArnUtils.parse(destination);
                String groupName = group.resource().replaceFirst("^log-group:", "").replaceFirst(":\\*$", "");
                logsPending.computeIfAbsent(new LogsTarget(group.accountId(), group.region(), groupName,
                                eni.vpcId(), instanceId != null ? instanceId : eni.eniId()),
                        k -> new ArrayList<>())
                        .add(Map.of("timestamp", query.timestamp().toEpochMilli(), "message", line));
            }
        }
    }

    /** R53-EX key order; {@code srcids} names the instance for EC2 and is empty for a task ENI. */
    ObjectNode record(DnsQueryObserver.Query query, SecurityGroupNftCompiler.Endpoint eni, String instanceId) {
        ObjectNode record = mapper.createObjectNode();
        record.put("version", "1.100000");
        record.put("account_id", eni.accountId());
        record.put("region", eni.region());
        record.put("vpc_id", eni.vpcId());
        record.put("query_timestamp", query.timestamp().truncatedTo(ChronoUnit.SECONDS).toString());
        record.put("query_name", query.name().endsWith(".") ? query.name() : query.name() + ".");
        record.put("query_type", typeName(query.type()));
        record.put("query_class", className(query.queryClass()));
        record.put("rcode", rcodeName(query.responseCode()));
        ArrayNode answers = record.putArray("answers");
        for (DnsQueryObserver.Answer answer : query.answers()) {
            answers.addObject()
                    .put("Rdata", answer.data())
                    .put("Type", typeName(answer.type()))
                    .put("Class", className(answer.answerClass()));
        }
        record.put("srcaddr", eni.logicalAddress());
        record.put("srcport", String.valueOf(query.sourcePort()));
        record.put("transport", "UDP");
        ObjectNode srcids = record.putObject("srcids");
        if (instanceId != null) {
            srcids.put("instance", instanceId);
        }
        return record;
    }

    private String instanceOf(SecurityGroupNftCompiler.Endpoint eni) {
        try {
            List<NetworkInterface> found = ec2Service.describeNetworkInterfaces(eni.accountId(), eni.region(),
                    List.of(eni.eniId()), Map.of()).networkInterfaces();
            return found.isEmpty() || found.getFirst().getAttachment() == null ? null
                    : found.getFirst().getAttachment().getInstanceId();
        } catch (AwsException e) {
            LOG.debugv("Could not look up the attachment of {0}: {1}", eni.eniId(), e.getMessage());
            return null;
        }
    }

    private void flushS3() {
        Map<S3Target, List<String>> batch;
        synchronized (this) {
            batch = s3Pending;
            s3Pending = new HashMap<>();
        }
        Instant slot = Instant.ofEpochSecond(Instant.now().getEpochSecond() / 300 * 300);
        for (Map.Entry<S3Target, List<String>> entry : batch.entrySet()) {
            S3Target target = entry.getKey();
            String key = s3Key(target, slot);
            try {
                s3Service.putObject(target.bucket(), key, gzip(String.join("\n", entry.getValue()) + "\n"),
                        "application/octet-stream", Map.of());
            } catch (RuntimeException e) {
                LOG.warnv("Dropped {0} query-log records for s3://{1}/{2}: {3}",
                        entry.getValue().size(), target.bucket(), key, e.getMessage());
            }
        }
    }

    static String s3Key(S3Target target, Instant slot) {
        String prefix = target.prefix().isEmpty() || target.prefix().endsWith("/") ? target.prefix()
                : target.prefix() + "/";
        return prefix + "AWSLogs/" + target.accountId() + "/vpcdnsquerylogs/" + target.vpcId() + "/"
                + DAY.format(slot) + "/" + target.vpcId() + "_vpcdnsquerylogs_" + target.accountId() + "_"
                + SLOT.format(slot) + "_" + HexFormat.of().toHexDigits(ThreadLocalRandom.current().nextInt())
                + ".log.gz";
    }

    private void flushLogs() {
        Map<LogsTarget, List<Map<String, Object>>> batch;
        synchronized (this) {
            batch = logsPending;
            logsPending = new HashMap<>();
        }
        String slot = SLOT.format(Instant.now());
        for (Map.Entry<LogsTarget, List<Map<String, Object>>> entry : batch.entrySet()) {
            LogsTarget target = entry.getKey();
            String stream = target.vpcId() + "_" + slot + "_" + target.sourceId();
            try {
                try {
                    logsService.createLogStreamForAccount(target.accountId(), target.logGroup(), stream,
                            target.region());
                } catch (AwsException e) {
                    if (!"ResourceAlreadyExistsException".equals(e.getErrorCode())) {
                        throw e;
                    }
                }
                logsService.putLogEventsForAccount(target.accountId(), target.logGroup(), stream,
                        entry.getValue(), target.region());
            } catch (RuntimeException e) {
                LOG.warnv("Dropped {0} query-log records for log group {1}: {2}",
                        entry.getValue().size(), target.logGroup(), e.getMessage());
            }
        }
    }

    private static byte[] gzip(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return out.toByteArray();
    }

    static String typeName(int type) {
        return switch (type) {
            case 1 -> "A";
            case 2 -> "NS";
            case 5 -> "CNAME";
            case 6 -> "SOA";
            case 12 -> "PTR";
            case 15 -> "MX";
            case 16 -> "TXT";
            case 28 -> "AAAA";
            case 33 -> "SRV";
            case 64 -> "SVCB";
            case 65 -> "HTTPS";
            case 255 -> "ANY";
            default -> "TYPE" + type;
        };
    }

    private static String className(int queryClass) {
        return queryClass == 1 ? "IN" : "CLASS" + queryClass;
    }

    static String rcodeName(int rcode) {
        return switch (rcode) {
            case 0 -> "NOERROR";
            case 1 -> "FORMERR";
            case 2 -> "SERVFAIL";
            case 3 -> "NXDOMAIN";
            case 4 -> "NOTIMP";
            case 5 -> "REFUSED";
            default -> "RCODE" + rcode;
        };
    }
}
