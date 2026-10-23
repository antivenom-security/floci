package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.XmlParser;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.cloudwatch.logs.model.LogEvent;
import io.github.hectorvent.floci.services.sns.SnsService;
import io.github.hectorvent.floci.services.sqs.SqsService;
import io.github.hectorvent.floci.services.sqs.model.Message;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.GetTrailStatusResponse;
import software.amazon.awssdk.services.cloudtrail.model.PublicKey;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Trail delivery at the test cadence of a 5 s flush and 60 s digests: S3 files in AWS's layout, one
 * CloudWatch Logs event per record, an SNS notification per file, and a digest chain the AWS CLI's
 * {@code validate-logs} accepts.
 */
@QuarkusTest
@TestProfile(CloudTrailDeliveryIntegrationTest.DeliveryProfile.class)
class CloudTrailDeliveryIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String AWS_CLI_IMAGE = "amazon/aws-cli:2.22.0";
    private static final Pattern LOG_KEY = Pattern.compile("AWSLogs/" + ACCOUNT + "/CloudTrail/" + REGION
            + "/(\\d{4})/(\\d{2})/(\\d{2})/" + ACCOUNT + "_CloudTrail_" + REGION
            + "_(\\d{4})(\\d{2})(\\d{2})T\\d{4}Z_[A-Za-z0-9]{16}\\.json\\.gz");

    public static class DeliveryProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.cloudtrail.flush-interval-seconds", "5",
                    "floci.services.cloudtrail.digest-interval-seconds", "60");
        }
    }

    private final ObjectMapper mapper = new ObjectMapper();

    @TestHTTPResource("/")
    URI endpoint;

    @Inject
    CloudWatchLogsService logs;

    @Inject
    SnsService sns;

    @Inject
    SqsService sqs;

    @Test
    @Timeout(value = 3, unit = TimeUnit.MINUTES)
    void deliversToS3CloudWatchLogsAndSns() throws Exception {
        String suffix = suffix();
        String bucket = "delivery-logs-" + suffix;
        String group = "/cloudtrail/delivery-" + suffix;
        given().when().put("/" + bucket).then().statusCode(200);
        logs.createLogGroup(group, null, Map.of(), REGION);
        String topicArn = sns.createTopic("delivery-" + suffix, Map.of(), Map.of(), REGION).getTopicArn();
        String queueUrl = sqs.createQueue("delivery-" + suffix, Map.of(), REGION).getQueueUrl();
        sns.subscribe(topicArn, "sqs", "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":delivery-" + suffix,
                REGION, Map.of());
        String trailName = "delivery-" + suffix;

        try (CloudTrailClient cloudTrail = cloudTrail()) {
            cloudTrail.createTrail(r -> r.name(trailName).s3BucketName(bucket).snsTopicName(topicArn)
                    .cloudWatchLogsLogGroupArn("arn:aws:logs:" + REGION + ":" + ACCOUNT + ":log-group:" + group + ":*")
                    .cloudWatchLogsRoleArn("arn:aws:iam::" + ACCOUNT + ":role/CloudTrailToLogs"));
            cloudTrail.startLogging(r -> r.name(trailName));
            cloudTrail.describeTrails(r -> r.trailNameList(trailName));

            List<String> keys = await(() -> {
                List<String> found = logKeys(bucket, "AWSLogs/");
                return found.isEmpty() ? null : found;
            });
            Set<String> eventIds = new HashSet<>();
            for (String key : keys) {
                Matcher m = LOG_KEY.matcher(key);
                assertTrue(m.matches(), "log file key out of layout: " + key);
                assertEquals(m.group(1) + m.group(2) + m.group(3), m.group(4) + m.group(5) + m.group(6),
                        "the date path is the publish date of the file name: " + key);
                for (JsonNode record : read(bucket, key).path("Records")) {
                    assertEquals(REGION, record.path("awsRegion").asText());
                    eventIds.add(record.path("eventID").asText());
                }
            }
            assertFalse(eventIds.isEmpty());

            String stream = ACCOUNT + "_CloudTrail_" + REGION;
            List<String> logged = await(() -> {
                List<String> ids = new ArrayList<>();
                for (LogEvent event : logs.getLogEvents(group, stream, null, null, 10_000, true, null, REGION)
                        .events()) {
                    ids.add(readTree(event.getMessage()).path("eventID").asText());
                }
                return ids.containsAll(eventIds) ? ids : null;
            });
            assertEquals(logged.size(), new HashSet<>(logged).size(), "one log event per record");

            JsonNode notification = await(() -> {
                List<Message> messages = sqs.receiveMessage(queueUrl, 1, 30, 0, REGION);
                return messages.isEmpty() ? null : readTree(readTree(messages.getFirst().getBody())
                        .path("Message").asText());
            });
            assertEquals(bucket, notification.path("s3Bucket").asText());
            assertEquals(1, notification.path("s3ObjectKey").size());
            assertTrue(LOG_KEY.matcher(notification.path("s3ObjectKey").get(0).asText()).matches());

            GetTrailStatusResponse status = cloudTrail.getTrailStatus(r -> r.name(trailName));
            assertNotNull(status.latestDeliveryTime());
            assertNotNull(status.latestCloudWatchLogsDeliveryTime());
            assertNotNull(status.latestNotificationTime());
            assertNull(status.latestCloudWatchLogsDeliveryError());
            assertNull(status.latestNotificationError());
            assertEquals(group, cloudTrail.describeTrails(r -> r.trailNameList(trailName)).trailList().getFirst()
                    .cloudWatchLogsLogGroupArn().split(":")[6]);
            cloudTrail.stopLogging(r -> r.name(trailName));
        }
    }

    @Test
    @Timeout(value = 9, unit = TimeUnit.MINUTES)
    void awsCliValidatesLogsAndDigestsAcrossIdlePeriods() throws Exception {
        String suffix = suffix();
        String source = "digest-source-" + suffix;
        String bucket = "digest-logs-" + suffix;
        String trailName = "digest-" + suffix;
        given().when().put("/" + source).then().statusCode(200);
        given().when().put("/" + bucket).then().statusCode(200);
        Instant startTime = Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.SECONDS);
        String trailArn;
        try (CloudTrailClient cloudTrail = cloudTrail()) {
            trailArn = cloudTrail.createTrail(r -> r.name(trailName).s3BucketName(bucket)
                    .enableLogFileValidation(true)).trailARN();
            cloudTrail.putEventSelectors(r -> r.trailName(trailName).eventSelectors(s -> s
                    .readWriteType("All").includeManagementEvents(false)
                    .dataResources(d -> d.type("AWS::S3::Object").values("arn:aws:s3:::" + source + "/"))));
            cloudTrail.startLogging(r -> r.name(trailName));
            for (int i = 0; i < 3; i++) {
                given().body("x").when().put("/" + source + "/object-" + i).then().statusCode(200);
            }

            String digestPrefix = "AWSLogs/" + ACCOUNT + "/CloudTrail-Digest/" + REGION + "/";
            List<JsonNode> digests = awaitWithin(420, () -> {
                List<JsonNode> found = new ArrayList<>();
                for (String key : logKeys(bucket, digestPrefix)) {
                    found.add(read(bucket, key));
                }
                boolean idle = found.stream().anyMatch(d -> d.path("logFiles").isEmpty());
                boolean busy = found.stream().anyMatch(d -> !d.path("logFiles").isEmpty());
                return found.size() >= 3 && idle && busy ? found : null;
            });
            for (JsonNode digest : digests) {
                assertTrue(digest.path("digestS3Object").asText().matches(digestPrefix
                        + "\\d{4}/\\d{2}/\\d{2}/" + ACCOUNT + "_CloudTrail-Digest_" + REGION + "_" + trailName + "_"
                        + REGION + "_\\d{8}T\\d{6}Z\\.json\\.gz"), digest.toString());
            }

            List<PublicKey> keys = cloudTrail.listPublicKeys(r -> r.startTime(startTime)).publicKeyList();
            assertEquals(1, keys.size());
            assertEquals(digests.getFirst().path("digestPublicKeyFingerprint").asText(), keys.getFirst().fingerprint());
            assertNotNull(cloudTrail.getTrailStatus(r -> r.name(trailName)).latestDigestDeliveryTime());
        }

        Assumptions.assumeTrue(dockerAvailable(), "Docker is needed to run the AWS CLI's validate-logs");
        Process cli = new ProcessBuilder("docker", "run", "--rm",
                "--add-host=host.docker.internal:host-gateway",
                "-e", "AWS_ACCESS_KEY_ID=test", "-e", "AWS_SECRET_ACCESS_KEY=test",
                "-e", "AWS_DEFAULT_REGION=" + REGION,
                "-e", "AWS_ENDPOINT_URL=http://host.docker.internal:" + endpoint.getPort(),
                "--entrypoint", "sh", AWS_CLI_IMAGE, "-c",
                "aws configure set default.s3.addressing_style path && aws cloudtrail validate-logs --verbose"
                        + " --trail-arn " + trailArn + " --start-time " + startTime)
                .redirectErrorStream(true).start();
        assertTrue(cli.waitFor(3, TimeUnit.MINUTES), "validate-logs did not finish");
        String output = new String(cli.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, cli.exitValue(), output);
        assertFalse(output.contains("INVALID"), output);
        Matcher valid = Pattern.compile("(\\d+)/(\\d+) digest files valid").matcher(output);
        assertTrue(valid.find(), output);
        assertEquals(valid.group(1), valid.group(2), output);
        assertTrue(Integer.parseInt(valid.group(1)) >= 3, output);
        assertTrue(Pattern.compile("(\\d+)/\\1 log files valid").matcher(output).find(), output);
    }

    private CloudTrailClient cloudTrail() {
        return CloudTrailClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .httpClient(UrlConnectionHttpClient.create()).build();
    }

    private static <T> T await(Supplier<T> probe) throws InterruptedException {
        return awaitWithin(60, probe);
    }

    private static <T> T awaitWithin(int seconds, Supplier<T> probe) throws InterruptedException {
        long deadline = System.currentTimeMillis() + seconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            T value = probe.get();
            if (value != null) {
                return value;
            }
            Thread.sleep(1000);
        }
        throw new AssertionError("condition not met within " + seconds + " s");
    }

    private static List<String> logKeys(String bucket, String prefix) {
        String xml = given().when().get("/" + bucket + "?list-type=2&prefix=" + prefix)
                .then().statusCode(200).extract().asString();
        return XmlParser.extractAll(xml, "Key").stream().filter(k -> k.endsWith(".json.gz")).toList();
    }

    private JsonNode read(String bucket, String key) {
        byte[] gz = given().when().get("/" + bucket + "/" + key).then().statusCode(200).extract().asByteArray();
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
            return mapper.readTree(in.readAllBytes());
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    private JsonNode readTree(String json) {
        try {
            return mapper.readTree(json);
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    private static boolean dockerAvailable() {
        try {
            return new ProcessBuilder("docker", "version").redirectErrorStream(true).start().waitFor() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
