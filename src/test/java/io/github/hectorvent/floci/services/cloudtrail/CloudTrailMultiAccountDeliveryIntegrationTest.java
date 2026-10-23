package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.RequestScopes;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.github.hectorvent.floci.services.sns.SnsService;
import io.github.hectorvent.floci.services.sqs.SqsService;
import io.github.hectorvent.floci.services.sqs.model.Message;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.GetTrailStatusResponse;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two accounts with a trail of the same name in the same region keep separate buffers, and each
 * trail's files are delivered under its own account.
 */
@QuarkusTest
class CloudTrailMultiAccountDeliveryIntegrationTest {

    private static final String REGION = "us-east-1";

    @TestHTTPResource("/")
    URI endpoint;

    @Inject
    CloudTrailLogWriter writer;

    @Inject
    S3Service s3;

    @Inject
    SnsService sns;

    @Inject
    SqsService sqs;

    @Inject
    CloudWatchLogsService logs;

    @Test
    void sameNamedTrailsInTwoAccountsDeliverTheirOwnRecords() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String trailName = "shared-" + suffix;
        String first = "000000000000";
        String second = "111111111111";
        String firstBucket = "multi-a-" + suffix;
        String secondBucket = "multi-b-" + suffix;
        s3.createBucket(firstBucket, REGION);
        RequestScopes.runAs(second, () -> s3.createBucket(secondBucket, REGION));
        String group = "/cloudtrail/multi-" + suffix;
        String queueName = "multi-" + suffix;
        String topicArn = RequestScopes.callAs(second, () -> {
            logs.createLogGroup(group, null, Map.of(), REGION);
            String topic = sns.createTopic("multi-" + suffix, Map.of(), Map.of(), REGION).getTopicArn();
            sqs.createQueue(queueName, Map.of(), REGION);
            sns.subscribe(topic, "sqs", "arn:aws:sqs:" + REGION + ":" + second + ":" + queueName, REGION, Map.of());
            return topic;
        });

        try (CloudTrailClient firstClient = cloudTrail("test");
             CloudTrailClient secondClient = cloudTrail(second)) {
            firstClient.createTrail(r -> r.name(trailName).s3BucketName(firstBucket));
            secondClient.createTrail(r -> r.name(trailName).s3BucketName(secondBucket).snsTopicName(topicArn)
                    .cloudWatchLogsLogGroupArn("arn:aws:logs:" + REGION + ":" + second + ":log-group:" + group + ":*")
                    .cloudWatchLogsRoleArn("arn:aws:iam::" + second + ":role/CloudTrailToLogs"));
            firstClient.startLogging(r -> r.name(trailName));
            secondClient.startLogging(r -> r.name(trailName));
            firstClient.describeTrails(r -> r.trailNameList(trailName));
            secondClient.describeTrails(r -> r.trailNameList(trailName));
            writer.flushNow();

            assertDeliveredFor(first, firstBucket);
            assertDeliveredFor(second, secondBucket);
            GetTrailStatusResponse status = secondClient.getTrailStatus(r -> r.name(trailName));
            assertNotNull(status.latestDeliveryTime());
            assertNotNull(status.latestNotificationTime(), status.toString());
            assertNull(status.latestNotificationError());
            assertNotNull(status.latestCloudWatchLogsDeliveryTime(), status.toString());
            assertNull(status.latestCloudWatchLogsDeliveryError());
            String queueUrl = RequestScopes.callAs(second, () -> sqs.getQueueUrl(queueName, REGION));
            List<Message> messages = RequestScopes.callAs(second,
                    () -> sqs.receiveMessage(queueUrl, 1, 30, 0, REGION));
            assertEquals(1, messages.size());
            assertTrue(messages.getFirst().getBody().contains(secondBucket), messages.getFirst().getBody());
            assertFalse(RequestScopes.callAs(second, () -> logs.getLogEvents(group, second + "_CloudTrail_" + REGION,
                    null, null, 100, true, null, REGION).events()).isEmpty());
            firstClient.stopLogging(r -> r.name(trailName));
            secondClient.stopLogging(r -> r.name(trailName));
        }
    }

    private void assertDeliveredFor(String account, String bucket) throws Exception {
        List<S3Object> objects = RequestScopes.callAs(account, () -> s3.listObjects(bucket, null, null, 1000));
        assertFalse(objects.isEmpty(), "no log file in " + bucket);
        List<JsonNode> records = new ArrayList<>();
        for (S3Object object : objects) {
            assertTrue(object.getKey().startsWith("AWSLogs/" + account + "/CloudTrail/"), object.getKey());
            byte[] gz = RequestScopes.callAs(account, () -> s3.getObject(bucket, object.getKey()).getData());
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                new ObjectMapper().readTree(in.readAllBytes()).path("Records").forEach(records::add);
            }
        }
        assertFalse(records.isEmpty());
        for (JsonNode record : records) {
            assertEquals(account, record.path("recipientAccountId").asText(), record.toString());
        }
    }

    private CloudTrailClient cloudTrail(String accessKey) {
        return CloudTrailClient.builder().endpointOverride(endpoint).region(Region.of(REGION))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKey, "test")))
                .httpClient(UrlConnectionHttpClient.create()).build();
    }
}
