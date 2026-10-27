package io.github.hectorvent.floci.services.wafv2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.wafv2.model.WebAcl;
import io.quarkus.runtime.ShutdownEvent;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.interceptor.Interceptor;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

/**
 * Web ACL traffic logs, delivered to the {@code aws-waf-logs-*} S3 bucket or CloudWatch Logs group a
 * logging configuration names, after its logging filter and redacted fields. S3 files cover one
 * interval each and are written when it ends; CloudWatch Logs events go to the
 * {@code <region>_<web-acl-name>_0} stream on the same tick.
 */
@ApplicationScoped
public class WafV2LogWriter {

    private static final Logger LOG = Logger.getLogger(WafV2LogWriter.class);
    private static final String PREFIX = "aws-waf-logs-";
    static final int MAX_PENDING = 100_000;
    private static final DateTimeFormatter FOLDER = DateTimeFormatter.ofPattern("yyyy/MM/dd/HH/mm")
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmm'Z'")
            .withZone(ZoneOffset.UTC);

    record S3File(String bucket, String prefix, String accountId, String region, String webAclName, Instant slot) {}

    record Stream(String accountId, String region, String logGroup, String name) {}

    private final EmulatorConfig config;
    private final S3Service s3Service;
    private final CloudWatchLogsService logsService;
    private final Map<S3File, List<String>> s3Pending = new HashMap<>();
    private final Map<Stream, List<Map<String, Object>>> logsPending = new HashMap<>();
    private ScheduledExecutorService executor;

    @Inject
    public WafV2LogWriter(EmulatorConfig config, S3Service s3Service, CloudWatchLogsService logsService) {
        this.config = config;
        this.s3Service = s3Service;
        this.logsService = logsService;
    }

    @PostConstruct
    void start() {
        if (!config.services().wafv2().enabled()) {
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "wafv2-log-writer");
            t.setDaemon(true);
            return t;
        });
        int interval = interval();
        executor.scheduleAtFixedRate(() -> flush(false), interval, interval, TimeUnit.SECONDS);
    }

    void stop(@Observes @Priority(Interceptor.Priority.APPLICATION) ShutdownEvent event) {
        if (executor != null) {
            flushNow();
            executor.shutdownNow();
            executor = null;
        }
    }

    /** Writes every pending record, including the S3 files whose interval has not ended yet. */
    public void flushNow() {
        flush(true);
    }

    /** Buffers {@code record} for each of the configuration's destinations, unless its filter drops it. */
    void record(WebAcl acl, JsonNode logging, ObjectNode record) {
        if (!kept(logging.path("LoggingFilter"), record)) {
            return;
        }
        redact(logging.path("RedactedFields"), (ObjectNode) record.get("httpRequest"));
        String line = record.toString();
        long timestamp = record.path("timestamp").asLong();
        long interval = interval();
        Instant slot = Instant.ofEpochSecond(timestamp / 1000 / interval * interval);
        String account = AwsArnUtils.parse(acl.getArn()).accountId();
        for (JsonNode destination : logging.path("LogDestinationConfigs")) {
            String arn = destination.asText();
            Optional<String> bucketPath = AwsArnUtils.resourceIfArnFor(arn, "s3");
            if (bucketPath.isPresent()) {
                String[] parts = bucketPath.orElseThrow().split("/", 2);
                if (parts[0].startsWith(PREFIX)) {
                    enqueue(s3Pending, new S3File(parts[0], parts.length > 1 ? parts[1] : "", account,
                            acl.getRegion(), acl.getName(), slot), line);
                }
            } else if (AwsArnUtils.isArnFor(arn, "logs")) {
                AwsArnUtils.Arn group = AwsArnUtils.parse(arn);
                String name = group.resource().replaceFirst("^log-group:", "").replaceFirst(":\\*$", "");
                if (name.startsWith(PREFIX)) {
                    enqueue(logsPending, new Stream(group.accountId(), group.region(), name,
                            acl.getRegion() + "_" + acl.getName() + "_0"),
                            Map.of("timestamp", timestamp, "message", line));
                }
            }
        }
    }

    /** The first filter whose conditions are met decides; otherwise the default behavior does. */
    static boolean kept(JsonNode filter, JsonNode record) {
        if (!filter.isObject()) {
            return true;
        }
        for (JsonNode candidate : filter.path("Filters")) {
            boolean all = "MEETS_ALL".equals(candidate.path("Requirement").asText());
            boolean met = all;
            for (JsonNode condition : candidate.path("Conditions")) {
                met = all ? met && meets(condition, record) : met || meets(condition, record);
            }
            if (met) {
                return "KEEP".equals(candidate.path("Behavior").asText());
            }
        }
        return !"DROP".equals(filter.path("DefaultBehavior").asText());
    }

    private static boolean meets(JsonNode condition, JsonNode record) {
        if (condition.has("ActionCondition")) {
            String action = condition.path("ActionCondition").path("Action").asText();
            if (action.equals(record.path("action").asText())) {
                return true;
            }
            for (JsonNode rule : record.path("nonTerminatingMatchingRules")) {
                if (action.equals(rule.path("action").asText())) {
                    return true;
                }
            }
            return false;
        }
        String label = condition.path("LabelNameCondition").path("LabelName").asText();
        for (JsonNode applied : record.path("labels")) {
            if (label.equals(applied.path("name").asText())) {
                return true;
            }
        }
        return false;
    }

    /** Redactable fields (URI path, query string, single header, method) read {@code REDACTED}. */
    static void redact(JsonNode fields, ObjectNode httpRequest) {
        for (JsonNode field : fields) {
            if (field.has("UriPath")) {
                httpRequest.put("uri", "REDACTED");
            } else if (field.has("QueryString")) {
                httpRequest.put("args", "REDACTED");
            } else if (field.has("Method")) {
                httpRequest.put("httpMethod", "REDACTED");
            } else if (field.has("SingleHeader")) {
                String name = field.path("SingleHeader").path("Name").asText();
                for (JsonNode header : httpRequest.path("headers")) {
                    if (name.equalsIgnoreCase(header.path("name").asText())) {
                        ((ObjectNode) header).put("value", "REDACTED");
                    }
                }
            }
        }
    }

    private synchronized <K, V> void enqueue(Map<K, List<V>> pending, K key, V value) {
        List<V> list = pending.computeIfAbsent(key, k -> new ArrayList<>());
        list.add(value);
        if (list.size() > MAX_PENDING) {
            // shortcut: drops the oldest records of a destination that keeps refusing them, until delivery errors are reported.
            list.subList(0, list.size() - MAX_PENDING).clear();
        }
    }

    private void flush(boolean all) {
        Map<S3File, List<String>> files = new HashMap<>();
        Map<Stream, List<Map<String, Object>>> streams;
        Instant now = Instant.now();
        synchronized (this) {
            Iterator<Map.Entry<S3File, List<String>>> it = s3Pending.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<S3File, List<String>> entry = it.next();
                if (all || !entry.getKey().slot().plusSeconds(interval()).isAfter(now)) {
                    files.put(entry.getKey(), entry.getValue());
                    it.remove();
                }
            }
            streams = new HashMap<>(logsPending);
            logsPending.clear();
        }
        files.forEach((file, lines) -> {
            String key = s3Key(file, HexFormat.of().toHexDigits(ThreadLocalRandom.current().nextInt()));
            try {
                s3Service.putObject(file.bucket(), key, gzip(String.join("\n", lines) + "\n"),
                        "application/octet-stream", Map.of());
            } catch (RuntimeException e) {
                LOG.warnv("WAF log delivery to s3://{0}/{1} failed, keeping {2} records for the next flush: {3}",
                        file.bucket(), key, lines.size(), e.getMessage());
                lines.forEach(line -> enqueue(s3Pending, file, line));
            }
        });
        streams.forEach((stream, events) -> {
            try {
                try {
                    logsService.createLogStreamForAccount(stream.accountId(), stream.logGroup(), stream.name(),
                            stream.region());
                } catch (AwsException e) {
                    if (!"ResourceAlreadyExistsException".equals(e.getErrorCode())) {
                        throw e;
                    }
                }
                events.sort(Comparator.comparingLong(event -> (Long) event.get("timestamp")));
                logsService.putLogEventsForAccount(stream.accountId(), stream.logGroup(), stream.name(), events,
                        stream.region());
            } catch (RuntimeException e) {
                LOG.warnv("WAF log delivery to log group {0} failed, keeping {1} records for the next flush: {2}",
                        stream.logGroup(), events.size(), e.getMessage());
                events.forEach(event -> enqueue(logsPending, stream, event));
            }
        });
    }

    /**
     * {@code [prefix/]AWSLogs/<account>/WAFLogs/<region>/<web-acl-name>/YYYY/MM/dd/HH/mm/<account>_waflogs_
     * <region>_<web-acl-name>_<YYYYMMddTHHmmZ>_<hash>.log.gz}, dated by the start of the file's interval.
     */
    static String s3Key(S3File file, String hash) {
        String prefix = file.prefix().isEmpty() || file.prefix().endsWith("/") ? file.prefix() : file.prefix() + "/";
        return prefix + "AWSLogs/" + file.accountId() + "/WAFLogs/" + file.region() + "/" + file.webAclName() + "/"
                + FOLDER.format(file.slot()) + "/" + file.accountId() + "_waflogs_" + file.region() + "_"
                + file.webAclName() + "_" + STAMP.format(file.slot()) + "_" + hash + ".log.gz";
    }

    private int interval() {
        return Math.max(1, config.services().wafv2().logs().interval());
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
}
