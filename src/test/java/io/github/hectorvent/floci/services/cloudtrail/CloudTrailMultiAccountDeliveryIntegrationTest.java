package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.XmlParser;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

    @Test
    void sameNamedTrailsInTwoAccountsDeliverTheirOwnRecords() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String trailName = "shared-" + suffix;
        String first = "000000000000";
        String second = "111111111111";
        String firstBucket = "multi-a-" + suffix;
        String secondBucket = "multi-b-" + suffix;
        given().when().put("/" + firstBucket).then().statusCode(200);
        given().when().put("/" + secondBucket).then().statusCode(200);

        try (CloudTrailClient firstClient = cloudTrail("test");
             CloudTrailClient secondClient = cloudTrail(second)) {
            firstClient.createTrail(r -> r.name(trailName).s3BucketName(firstBucket));
            secondClient.createTrail(r -> r.name(trailName).s3BucketName(secondBucket));
            firstClient.startLogging(r -> r.name(trailName));
            secondClient.startLogging(r -> r.name(trailName));
            firstClient.describeTrails(r -> r.trailNameList(trailName));
            secondClient.describeTrails(r -> r.trailNameList(trailName));
            writer.flushNow();

            assertDeliveredFor(first, firstBucket);
            assertDeliveredFor(second, secondBucket);
            assertNotNull(secondClient.getTrailStatus(r -> r.name(trailName)).latestDeliveryTime());
            firstClient.stopLogging(r -> r.name(trailName));
            secondClient.stopLogging(r -> r.name(trailName));
        }
    }

    private static void assertDeliveredFor(String account, String bucket) throws Exception {
        String xml = given().when().get("/" + bucket + "?list-type=2").then().statusCode(200).extract().asString();
        List<String> keys = XmlParser.extractAll(xml, "Key");
        assertFalse(keys.isEmpty(), "no log file in " + bucket);
        List<JsonNode> records = new ArrayList<>();
        for (String key : keys) {
            assertTrue(key.startsWith("AWSLogs/" + account + "/CloudTrail/"), key);
            byte[] gz = given().when().get("/" + bucket + "/" + key).then().statusCode(200).extract().asByteArray();
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
