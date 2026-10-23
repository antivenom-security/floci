package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.sns.SnsService;
import io.github.hectorvent.floci.testing.IamEnforcementProfile;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.CloudTrailException;
import software.amazon.awssdk.services.cloudtrail.model.GetTrailStatusResponse;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Under IAM enforcement CreateTrail checks that the bucket and topic policies let CloudTrail deliver,
 * and CloudWatch Logs delivery runs as the trail's role, which must trust CloudTrail and allow the writes.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class CloudTrailDeliveryPermissionsIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";

    @TestHTTPResource("/")
    URI endpoint;

    @Inject
    S3Service s3;

    @Inject
    SnsService sns;

    @Inject
    IamService iam;

    @Inject
    CloudWatchLogsService logs;

    @Inject
    CloudTrailLogWriter writer;

    @Test
    void createTrailRequiresTheDocumentedBucketPolicy() {
        String suffix = suffix();
        String bucket = "perm-logs-" + suffix;
        String trailName = "perm-" + suffix;
        s3.createBucket(bucket, REGION);
        try (CloudTrailClient cloudTrail = cloudTrail()) {
            CloudTrailException denied = assertThrows(CloudTrailException.class,
                    () -> cloudTrail.createTrail(r -> r.name(trailName).s3BucketName(bucket)));
            assertEquals("InsufficientS3BucketPolicyException", denied.awsErrorDetails().errorCode());

            s3.putBucketPolicy(bucket, bucketPolicy(bucket, trailName));
            assertEquals(bucket, cloudTrail.createTrail(r -> r.name(trailName).s3BucketName(bucket)).s3BucketName());
        }
    }

    @Test
    void createTrailRequiresTheTopicPolicy() {
        String suffix = suffix();
        String bucket = "perm-topic-logs-" + suffix;
        String trailName = "perm-topic-" + suffix;
        s3.createBucket(bucket, REGION);
        s3.putBucketPolicy(bucket, bucketPolicy(bucket, trailName));
        String topicArn = sns.createTopic("perm-" + suffix, Map.of(), Map.of(), REGION).getTopicArn();
        try (CloudTrailClient cloudTrail = cloudTrail()) {
            CloudTrailException denied = assertThrows(CloudTrailException.class,
                    () -> cloudTrail.createTrail(r -> r.name(trailName).s3BucketName(bucket).snsTopicName(topicArn)));
            assertEquals("InsufficientSnsTopicPolicyException", denied.awsErrorDetails().errorCode());

            sns.setTopicAttributes(topicArn, "Policy", """
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                      "Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"SNS:Publish","Resource":"%s"}]}"""
                    .formatted(topicArn), REGION);
            assertEquals(topicArn, cloudTrail.createTrail(r -> r.name(trailName).s3BucketName(bucket)
                    .snsTopicName(topicArn)).snsTopicARN());
        }
    }

    @Test
    void cloudWatchLogsDeliveryRunsAsTheTrailRole() {
        String suffix = suffix();
        String group = "/cloudtrail/perm-" + suffix;
        logs.createLogGroup(group, null, Map.of(), REGION);
        String trust = """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                  "Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"sts:AssumeRole"}]}""";
        String allowed = iam.createRole("ct-logs-" + suffix, "/", trust, null, 3600, Map.of()).getArn();
        iam.putRolePolicy("ct-logs-" + suffix, "logs", """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                  "Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}""");
        String bare = iam.createRole("ct-bare-" + suffix, "/", trust, null, 3600, Map.of()).getArn();

        GetTrailStatusResponse allowedStatus = deliverWithRole("perm-cwl-" + suffix, group, allowed);
        assertNotNull(allowedStatus.latestCloudWatchLogsDeliveryTime(), allowedStatus.toString());
        assertNull(allowedStatus.latestCloudWatchLogsDeliveryError());
        assertTrue(logs.getLogEvents(group, ACCOUNT + "_CloudTrail_" + REGION, null, null, 100, true, null, REGION)
                .events().size() > 0);

        GetTrailStatusResponse deniedStatus = deliverWithRole("perm-cwl-bare-" + suffix, group, bare);
        assertNull(deniedStatus.latestCloudWatchLogsDeliveryTime());
        assertTrue(deniedStatus.latestCloudWatchLogsDeliveryError().contains("logs:CreateLogStream"),
                deniedStatus.toString());
    }

    private GetTrailStatusResponse deliverWithRole(String trailName, String group, String roleArn) {
        String bucket = trailName + "-logs";
        s3.createBucket(bucket, REGION);
        s3.putBucketPolicy(bucket, bucketPolicy(bucket, trailName));
        try (CloudTrailClient cloudTrail = cloudTrail()) {
            cloudTrail.createTrail(r -> r.name(trailName).s3BucketName(bucket)
                    .cloudWatchLogsLogGroupArn("arn:aws:logs:" + REGION + ":" + ACCOUNT + ":log-group:" + group + ":*")
                    .cloudWatchLogsRoleArn(roleArn));
            cloudTrail.startLogging(r -> r.name(trailName));
            cloudTrail.describeTrails(r -> r.trailNameList(trailName));
            writer.flushNow();
            cloudTrail.stopLogging(r -> r.name(trailName));
            return cloudTrail.getTrailStatus(r -> r.name(trailName));
        }
    }

    private static String bucketPolicy(String bucket, String trailName) {
        String trailArn = "arn:aws:cloudtrail:" + REGION + ":" + ACCOUNT + ":trail/" + trailName;
        return """
                {"Version":"2012-10-17","Statement":[
                  {"Sid":"AWSCloudTrailAclCheck","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},
                   "Action":"s3:GetBucketAcl","Resource":"arn:aws:s3:::%1$s",
                   "Condition":{"StringEquals":{"aws:SourceArn":"%2$s"}}},
                  {"Sid":"AWSCloudTrailWrite","Effect":"Allow","Principal":{"Service":"cloudtrail.amazonaws.com"},
                   "Action":"s3:PutObject","Resource":"arn:aws:s3:::%1$s/AWSLogs/%3$s/*",
                   "Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control","aws:SourceArn":"%2$s"}}}]}"""
                .formatted(bucket, trailArn, ACCOUNT);
    }

    private CloudTrailClient cloudTrail() {
        return CloudTrailClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .httpClient(UrlConnectionHttpClient.create()).build();
    }

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
