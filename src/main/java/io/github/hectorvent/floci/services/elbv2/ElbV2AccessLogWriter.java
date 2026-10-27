package io.github.hectorvent.floci.services.elbv2;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsRegions;
import io.github.hectorvent.floci.core.common.ServiceCallAuthorizer;
import io.github.hectorvent.floci.services.elbv2.model.LoadBalancer;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.s3.S3Service;
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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

/**
 * Application Load Balancer access logs, delivered to the S3 bucket named by the load balancer's
 * {@code access_logs.s3.*} attributes. Entries are grouped into one file per load balancer node (the
 * local address that accepted the request) and interval, and each file is written once its interval
 * ends, as the log-delivery service, so the bucket's event notifications fire.
 *
 * <p>Enabling the logs checks the bucket as AWS does: same Region, SSE-S3 rather than SSE-KMS, a
 * policy that lets {@code logdelivery.elasticloadbalancing.amazonaws.com} (or the Region's legacy
 * Elastic Load Balancing account) put objects under {@code [prefix/]AWSLogs/<account>/}, and a test
 * object written there.
 */
@ApplicationScoped
public class ElbV2AccessLogWriter {

    private static final Logger LOG = Logger.getLogger(ElbV2AccessLogWriter.class);
    private static final String DELIVERY_SERVICE = "logdelivery.elasticloadbalancing";
    static final String TEST_FILE = "ELBAccessLogTestFile";
    static final int MAX_PENDING_PER_FILE = 100_000;
    private static final DateTimeFormatter END = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmm'Z'")
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy/MM/dd").withZone(ZoneOffset.UTC);

    /** The accounts AWS's legacy access-log bucket policies name, for the Regions that support them. */
    private static final Map<String, String> LEGACY_ACCOUNTS = Map.ofEntries(
            Map.entry("us-east-1", "127311923021"),
            Map.entry("us-east-2", "033677994240"),
            Map.entry("us-west-1", "027434742980"),
            Map.entry("us-west-2", "797873946194"),
            Map.entry("af-south-1", "098369216593"),
            Map.entry("ap-east-1", "754344448648"),
            Map.entry("ap-southeast-3", "589379963580"),
            Map.entry("ap-south-1", "718504428378"),
            Map.entry("ap-northeast-3", "383597477331"),
            Map.entry("ap-northeast-2", "600734575887"),
            Map.entry("ap-southeast-1", "114774131450"),
            Map.entry("ap-southeast-2", "783225319266"),
            Map.entry("ap-northeast-1", "582318560864"),
            Map.entry("ca-central-1", "985666609251"),
            Map.entry("eu-central-1", "054676820928"),
            Map.entry("eu-west-1", "156460612806"),
            Map.entry("eu-west-2", "652711504416"),
            Map.entry("eu-south-1", "635631232127"),
            Map.entry("eu-west-3", "009996457667"),
            Map.entry("eu-north-1", "897822967062"),
            Map.entry("me-south-1", "076674570225"),
            Map.entry("sa-east-1", "507241528517"),
            Map.entry("us-gov-east-1", "190560391635"),
            Map.entry("us-gov-west-1", "048591011584"));

    record LogFile(String bucket, String prefix, String loadBalancerArn, String region, String nodeIp, Instant end) {}

    private final EmulatorConfig config;
    private final S3Service s3Service;
    private final ServiceCallAuthorizer authorizer;
    private Map<LogFile, List<String>> pending = new HashMap<>();
    private ScheduledExecutorService executor;

    @Inject
    public ElbV2AccessLogWriter(EmulatorConfig config, S3Service s3Service, ServiceCallAuthorizer authorizer) {
        this.config = config;
        this.s3Service = s3Service;
        this.authorizer = authorizer;
    }

    @PostConstruct
    void start() {
        if (!config.services().elbv2().enabled()) {
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "elbv2-access-log-writer");
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

    /** Writes every pending file, including the ones whose interval has not ended yet. */
    public void flushNow() {
        flush(true);
    }

    /** The checks {@code ModifyLoadBalancerAttributes} makes before it turns access logs on. */
    void requireDeliverable(String region, LoadBalancer loadBalancer, String bucket, String prefix) {
        String keyPrefix = keyPrefix(prefix);
        if (keyPrefix.contains("AWSLogs")) {
            throw new AwsException("InvalidConfigurationRequest",
                    "The prefix for the access logs must not include the string AWSLogs", 400);
        }
        if (bucket == null || bucket.isEmpty() || !s3Service.bucketExists(bucket)) {
            throw accessDenied(bucket);
        }
        String bucketRegion = s3Service.getBucketRegion(bucket);
        if (bucketRegion != null && !bucketRegion.equals(region)) {
            throw new AwsException("InvalidConfigurationRequest",
                    "S3Bucket: " + bucket + " is not located in the same region with ELB", 400);
        }
        String account = AwsArnUtils.parse(loadBalancer.getLoadBalancerArn()).accountId();
        String key = keyPrefix + "AWSLogs/" + account + "/" + TEST_FILE;
        if (s3Service.getBucketEncryption(bucket).contains("aws:kms")
                || !deliverable(region, loadBalancer.getLoadBalancerArn(), bucket, key)) {
            throw accessDenied(bucket);
        }
        s3Service.putObject(bucket, key, ("Enable AccessLog for ELB: " + loadBalancer.getLoadBalancerName()
                + " at " + Instant.now()).getBytes(StandardCharsets.UTF_8), "text/plain", Map.of());
    }

    /** Buffers {@code entry} for {@code loadBalancer}'s log file, when its access logs are enabled. */
    void record(LoadBalancer loadBalancer, ElbV2AccessLogEntry entry) {
        Map<String, String> attributes = loadBalancer.getAttributes();
        String bucket = attributes.get("access_logs.s3.bucket");
        if (!"true".equalsIgnoreCase(attributes.get("access_logs.s3.enabled")) || bucket == null || bucket.isEmpty()) {
            return;
        }
        long interval = interval();
        Instant end = Instant.ofEpochSecond((entry.time().getEpochSecond() / interval + 1) * interval);
        LogFile file = new LogFile(bucket, attributes.getOrDefault("access_logs.s3.prefix", ""),
                entry.loadBalancerArn, entry.region, entry.nodeIp, end);
        enqueue(file, List.of(entry.render()));
    }

    private synchronized void enqueue(LogFile file, List<String> lines) {
        List<String> list = pending.computeIfAbsent(file, k -> new ArrayList<>());
        list.addAll(lines);
        if (list.size() > MAX_PENDING_PER_FILE) {
            // shortcut: drops the oldest entries of a file its bucket keeps refusing, until delivery errors are reported.
            list.subList(0, list.size() - MAX_PENDING_PER_FILE).clear();
        }
    }

    private void flush(boolean all) {
        Map<LogFile, List<String>> due = new HashMap<>();
        Instant now = Instant.now();
        synchronized (this) {
            Iterator<Map.Entry<LogFile, List<String>>> it = pending.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<LogFile, List<String>> entry = it.next();
                if (all || !entry.getKey().end().isAfter(now)) {
                    due.put(entry.getKey(), entry.getValue());
                    it.remove();
                }
            }
        }
        for (Map.Entry<LogFile, List<String>> entry : due.entrySet()) {
            LogFile file = entry.getKey();
            String key = s3Key(file, now, randomString());
            try {
                if (!deliverable(file.region(), file.loadBalancerArn(), file.bucket(), key)) {
                    throw accessDenied(file.bucket());
                }
                s3Service.putObject(file.bucket(), key, gzip(String.join("\n", entry.getValue()) + "\n"),
                        "application/octet-stream", Map.of());
            } catch (RuntimeException e) {
                LOG.warnv("Access-log delivery to s3://{0}/{1} failed, keeping {2} entries for the next flush: {3}",
                        file.bucket(), key, entry.getValue().size(), e.getMessage());
                enqueue(file, entry.getValue());
            }
        }
    }

    private boolean deliverable(String region, String loadBalancerArn, String bucket, String key) {
        String account = AwsArnUtils.parse(loadBalancerArn).accountId();
        String objectArn = AwsArnUtils.Arn.global(AwsRegions.partitionFor(region), "s3", "", bucket + "/" + key)
                .toString();
        if (authorizer.authorize(DELIVERY_SERVICE, "s3:PutObject", objectArn, loadBalancerArn, account)
                == Decision.ALLOW) {
            return true;
        }
        String legacyAccount = LEGACY_ACCOUNTS.get(region);
        return legacyAccount != null && authorizer.authorizeAccount(legacyAccount, "s3:PutObject", objectArn,
                loadBalancerArn, account) == Decision.ALLOW;
    }

    /**
     * {@code [prefix/]AWSLogs/<account>/elasticloadbalancing/<region>/yyyy/mm/dd/<account>_elasticloadbalancing_
     * <region>_<load-balancer-id>_<end-time>_<ip-address>_<random-string>.log.gz}, dated by delivery, with the
     * {@code app/<name>/<id>} load balancer ID's slashes as periods.
     */
    static String s3Key(LogFile file, Instant delivered, String random) {
        AwsArnUtils.Arn arn = AwsArnUtils.parse(file.loadBalancerArn());
        String account = arn.accountId();
        String loadBalancerId = arn.resource().substring("loadbalancer/".length()).replace('/', '.');
        return keyPrefix(file.prefix()) + "AWSLogs/" + account + "/elasticloadbalancing/" + file.region() + "/"
                + DAY.format(delivered) + "/" + account + "_elasticloadbalancing_" + file.region() + "_"
                + loadBalancerId + "_" + END.format(file.end()) + "_" + file.nodeIp() + "_" + random + ".log.gz";
    }

    private static String keyPrefix(String prefix) {
        return prefix == null || prefix.isEmpty() ? "" : prefix + (prefix.endsWith("/") ? "" : "/");
    }

    private static String randomString() {
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder random = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            random.append(alphabet.charAt(ThreadLocalRandom.current().nextInt(alphabet.length())));
        }
        return random.toString();
    }

    private int interval() {
        return Math.max(1, config.services().elbv2().accessLogs().interval());
    }

    private static AwsException accessDenied(String bucket) {
        return new AwsException("InvalidConfigurationRequest",
                "Access Denied for bucket: " + bucket + ". Please check S3bucket permission", 400);
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
