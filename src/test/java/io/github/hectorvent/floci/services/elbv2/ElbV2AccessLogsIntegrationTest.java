package io.github.hectorvent.floci.services.elbv2;

import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.github.hectorvent.floci.testutil.FreePorts;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2Client;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ActionTypeEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ElasticLoadBalancingV2Exception;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.LoadBalancerAttribute;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.LoadBalancerTypeEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ProtocolEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.RedirectActionStatusCodeEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.TargetTypeEnum;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Access logs for an Application Load Balancer, under IAM enforcement so the bucket policy decides
 * both enabling them and every delivery, as on AWS.
 */
@QuarkusTest
@TestProfile(ElbV2AccessLogsIntegrationTest.Profile.class)
class ElbV2AccessLogsIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final Pattern FIELD = Pattern.compile("\"[^\"]*\"|\\S+");
    private static final String TIME = "\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{6}Z";

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.elbv2.mock", "false",
                    "floci.services.iam.enforcement-enabled", "true");
        }
    }

    @TestHTTPResource("/")
    URI endpoint;

    @Inject
    S3Service s3;

    @Inject
    ElbV2AccessLogWriter writer;

    @Inject
    Vertx vertx;

    @Test
    void enablingAccessLogsRequiresTheDocumentedBucketPolicy() {
        String suffix = suffix();
        String bucket = "alb-logs-" + suffix;
        String legacyBucket = "alb-legacy-logs-" + suffix;
        s3.createBucket(bucket, REGION);
        s3.createBucket(legacyBucket, REGION);
        try (ElasticLoadBalancingV2Client elb = elb()) {
            String lbArn = createLoadBalancer(elb, "alb-perm-" + suffix);

            ElasticLoadBalancingV2Exception denied = assertThrows(ElasticLoadBalancingV2Exception.class,
                    () -> enableAccessLogs(elb, lbArn, bucket, "logs"));
            assertEquals("InvalidConfigurationRequest", denied.awsErrorDetails().errorCode());
            assertEquals("Access Denied for bucket: " + bucket + ". Please check S3bucket permission",
                    denied.awsErrorDetails().errorMessage());
            assertEquals("false", attribute(elb, lbArn, "access_logs.s3.enabled"));

            s3.putBucketPolicy(bucket, servicePolicy(bucket, "logs"));
            ElasticLoadBalancingV2Exception awsLogsPrefix = assertThrows(ElasticLoadBalancingV2Exception.class,
                    () -> enableAccessLogs(elb, lbArn, bucket, "logs/AWSLogs"));
            assertEquals("InvalidConfigurationRequest", awsLogsPrefix.awsErrorDetails().errorCode());

            enableAccessLogs(elb, lbArn, bucket, "logs");
            assertEquals("true", attribute(elb, lbArn, "access_logs.s3.enabled"));
            assertTrue(new String(s3.getObject(bucket, "logs/AWSLogs/" + ACCOUNT + "/ELBAccessLogTestFile").getData(),
                    StandardCharsets.UTF_8).startsWith("Enable AccessLog for ELB: alb-perm-" + suffix + " at "));

            s3.putBucketPolicy(legacyBucket, """
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                      "Principal":{"AWS":"arn:aws:iam::127311923021:root"},"Action":"s3:PutObject",
                      "Resource":"arn:aws:s3:::%s/AWSLogs/%s/*"}]}""".formatted(legacyBucket, ACCOUNT));
            enableAccessLogs(elb, lbArn, legacyBucket, "");
            assertEquals(legacyBucket, attribute(elb, lbArn, "access_logs.s3.bucket"));
        }
    }

    @Test
    void deliversOneEntryPerRequestInAwsFormat() throws Exception {
        String suffix = suffix();
        String bucket = "alb-entries-" + suffix;
        String name = "alb-log-" + suffix;
        s3.createBucket(bucket, REGION);
        s3.putBucketPolicy(bucket, servicePolicy(bucket, "edge"));
        Map<String, String> traceIds = new ConcurrentHashMap<>();
        HttpServer backend = vertx.createHttpServer().requestHandler(request -> {
            traceIds.put(request.path(), request.getHeader("X-Amzn-Trace-Id"));
            request.response().setStatusCode("/broken".equals(request.path()) ? 503 : 200).end("ok");
        }).listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().get(2, TimeUnit.SECONDS);
        int port = FreePorts.anyInterfacePort();
        int backendPort = backend.actualPort();
        try (ElasticLoadBalancingV2Client elb = elb()) {
            String lbArn = createLoadBalancer(elb, name);
            String tgArn = elb.createTargetGroup(r -> r.name("tg-" + suffix).protocol(ProtocolEnum.HTTP)
                    .port(backendPort).targetType(TargetTypeEnum.IP).healthCheckEnabled(false))
                    .targetGroups().getFirst().targetGroupArn();
            elb.registerTargets(r -> r.targetGroupArn(tgArn).targets(t -> t.id("127.0.0.1").port(backendPort)));
            String listenerArn = elb.createListener(r -> r.loadBalancerArn(lbArn).protocol(ProtocolEnum.HTTP)
                    .port(port).defaultActions(a -> a.type(ActionTypeEnum.FORWARD).targetGroupArn(tgArn)))
                    .listeners().getFirst().listenerArn();
            elb.createRule(r -> r.listenerArn(listenerArn).priority(10)
                    .conditions(c -> c.field("path-pattern").values("/old"))
                    .actions(a -> a.type(ActionTypeEnum.REDIRECT).redirectConfig(rc -> rc.path("/new")
                            .statusCode(RedirectActionStatusCodeEnum.HTTP_301))));
            elb.createRule(r -> r.listenerArn(listenerArn).priority(20)
                    .conditions(c -> c.field("path-pattern").values("/missing"))
                    .actions(a -> a.type(ActionTypeEnum.FIXED_RESPONSE).fixedResponseConfig(f -> f
                            .statusCode("404").contentType("text/plain").messageBody("gone"))));
            enableAccessLogs(elb, lbArn, bucket, "edge");

            HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
            Map<String, Integer> statuses = Map.of("/ok", 200, "/broken", 503, "/old", 301, "/missing", 404);
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertEquals(200,
                    client.send(get(port, "/ok"), HttpResponse.BodyHandlers.discarding()).statusCode()));
            for (Map.Entry<String, Integer> expected : statuses.entrySet()) {
                if (!"/ok".equals(expected.getKey())) {
                    assertEquals(expected.getValue(), client.send(get(port, expected.getKey()),
                            HttpResponse.BodyHandlers.discarding()).statusCode());
                }
            }

            Map<String, List<String>> entries = new HashMap<>();
            await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
                writer.flushNow();
                entries.clear();
                for (List<String> fields : readEntries(bucket, name)) {
                    String path = URI.create(fields.get(12).split(" ")[1]).getPath();
                    entries.put(path, fields);
                }
                assertTrue(entries.keySet().containsAll(statuses.keySet()), entries.keySet().toString());
            });

            String loadBalancerId = lbArn.substring(lbArn.indexOf(":loadbalancer/") + ":loadbalancer/".length());
            for (List<String> fields : entries.values()) {
                assertEquals(36, fields.size(), fields.toString());
                assertEquals("http", fields.get(0));
                assertTrue(fields.get(1).matches(TIME), fields.get(1));
                assertEquals(loadBalancerId, fields.get(2));
                assertTrue(fields.get(3).matches("127\\.0\\.0\\.1:\\d+"), fields.get(3));
                assertEquals("\"floci-access-log-test/1.0\"", fields.get(13));
                assertEquals("-", fields.get(14));
                assertEquals("-", fields.get(15));
                assertTrue(fields.get(17).matches("\"Root=1-[0-9a-f]{8}-[0-9a-f]{24}\""), fields.get(17));
                assertEquals("\"-\"", fields.get(18));
                assertEquals("\"-\"", fields.get(19));
                assertTrue(fields.get(21).matches(TIME), fields.get(21));
                assertEquals("\"-\"", fields.get(24));
                assertEquals("\"-\"", fields.get(27));
                assertEquals("\"-\"", fields.get(28));
                assertTrue(fields.get(29).matches("TID_[0-9a-f]{16}"), fields.get(29));
                assertEquals(List.of("\"-\"", "\"-\"", "\"-\"", "127.0.0.1", "-", "-"), fields.subList(30, 36));
            }

            List<String> ok = entries.get("/ok");
            assertEquals("127.0.0.1:" + backendPort, ok.get(4));
            assertTrue(ok.get(5).matches("\\d+\\.\\d{3}") && ok.get(6).matches("\\d+\\.\\d{3}"), ok.toString());
            assertEquals(List.of("200", "200"), ok.subList(8, 10));
            assertEquals("\"GET http://127.0.0.1:" + port + "/ok HTTP/1.1\"", ok.get(12));
            assertEquals(tgArn, ok.get(16));
            assertEquals("\"" + traceIds.get("/ok") + "\"", ok.get(17));
            assertEquals("0", ok.get(20));
            assertEquals(List.of("\"forward\"", "\"-\"", "\"-\"", "\"127.0.0.1:" + backendPort + "\"", "\"200\""),
                    ok.subList(22, 27));

            List<String> broken = entries.get("/broken");
            assertEquals(List.of("503", "503"), broken.subList(8, 10));
            assertEquals("\"503\"", broken.get(26));

            List<String> redirect = entries.get("/old");
            assertEquals(List.of("-", "-1", "-1", "-1", "301", "-"), redirect.subList(4, 10));
            assertEquals("-", redirect.get(16));
            assertEquals("10", redirect.get(20));
            assertEquals(List.of("\"redirect\"", "\"http://127.0.0.1:" + port + "/new\"", "\"-\"", "\"-\"", "\"-\""),
                    redirect.subList(22, 27));

            List<String> fixed = entries.get("/missing");
            assertEquals(List.of("-", "-1", "-1", "-1", "404", "-"), fixed.subList(4, 10));
            assertEquals("20", fixed.get(20));
            assertEquals("\"fixed-response\"", fixed.get(22));

            elb.deleteListener(r -> r.listenerArn(listenerArn));
            elb.deleteLoadBalancer(r -> r.loadBalancerArn(lbArn));
            elb.deleteTargetGroup(r -> r.targetGroupArn(tgArn));
        } finally {
            backend.close().toCompletionStage().toCompletableFuture().get(2, TimeUnit.SECONDS);
        }
    }

    private List<List<String>> readEntries(String bucket, String name) throws IOException {
        String prefix = "edge/AWSLogs/" + ACCOUNT + "/elasticloadbalancing/" + REGION + "/";
        List<List<String>> entries = new ArrayList<>();
        for (S3Object listed : s3.listObjects(bucket, prefix, null, 1000)) {
            assertTrue(listed.getKey().matches(Pattern.quote(prefix) + "\\d{4}/\\d{2}/\\d{2}/" + ACCOUNT
                    + "_elasticloadbalancing_" + REGION + "_app\\." + name + "\\.[0-9a-f]+_\\d{8}T\\d{4}Z_"
                    + "127\\.0\\.0\\.1_[a-z0-9]{8}\\.log\\.gz"), listed.getKey());
            byte[] data = s3.getObject(bucket, listed.getKey()).getData();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data))) {
                for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                    List<String> fields = new ArrayList<>();
                    Matcher matcher = FIELD.matcher(line);
                    while (matcher.find()) {
                        fields.add(matcher.group());
                    }
                    entries.add(fields);
                }
            }
        }
        return entries;
    }

    private static HttpRequest get(int port, String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("User-Agent", "floci-access-log-test/1.0").build();
    }

    private static String createLoadBalancer(ElasticLoadBalancingV2Client elb, String name) {
        return elb.createLoadBalancer(r -> r.name(name).type(LoadBalancerTypeEnum.APPLICATION)
                        .subnets(Ec2Service.defaultSubnetId(REGION, "a"), Ec2Service.defaultSubnetId(REGION, "b")))
                .loadBalancers().getFirst().loadBalancerArn();
    }

    private static void enableAccessLogs(ElasticLoadBalancingV2Client elb, String lbArn, String bucket,
                                         String prefix) {
        elb.modifyLoadBalancerAttributes(r -> r.loadBalancerArn(lbArn).attributes(
                LoadBalancerAttribute.builder().key("access_logs.s3.enabled").value("true").build(),
                LoadBalancerAttribute.builder().key("access_logs.s3.bucket").value(bucket).build(),
                LoadBalancerAttribute.builder().key("access_logs.s3.prefix").value(prefix).build()));
    }

    private static String attribute(ElasticLoadBalancingV2Client elb, String lbArn, String key) {
        return elb.describeLoadBalancerAttributes(r -> r.loadBalancerArn(lbArn)).attributes().stream()
                .filter(attribute -> attribute.key().equals(key)).findFirst().orElseThrow().value();
    }

    private static String servicePolicy(String bucket, String prefix) {
        return """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                  "Principal":{"Service":"logdelivery.elasticloadbalancing.amazonaws.com"},"Action":"s3:PutObject",
                  "Resource":"arn:aws:s3:::%s/%s/AWSLogs/%s/*",
                  "Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:elasticloadbalancing:%s:%s:loadbalancer/*"}}}]}"""
                .formatted(bucket, prefix, ACCOUNT, REGION, ACCOUNT);
    }

    private ElasticLoadBalancingV2Client elb() {
        return ElasticLoadBalancingV2Client.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .httpClient(UrlConnectionHttpClient.create()).build();
    }

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
