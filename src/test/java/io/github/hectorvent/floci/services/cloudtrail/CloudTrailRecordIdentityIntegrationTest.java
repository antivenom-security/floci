package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.testing.EnforcementFixtures;
import io.github.hectorvent.floci.testing.PartitionCleanup;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import static io.github.hectorvent.floci.testing.EnforcementFixtures.auth;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S3 data events record who called and the request id the caller received: an IAM user's key is an
 * {@code IAMUser}, an assumed-role session an {@code AssumedRole} with its {@code sessionIssuer},
 * and the {@code test} key the account {@code Root}. A plain-HTTP call carries no {@code tlsDetails}.
 */
@QuarkusTest
class CloudTrailRecordIdentityIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final Pattern S3_REQUEST_ID = Pattern.compile("[0-9A-F]{16}");
    private static final Pattern KEY = Pattern.compile("<Key>([^<]+)</Key>");

    @Inject
    CloudTrailLogWriter writer;

    @TestHTTPResource("/")
    URI baseUri;

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void s3PutObjectRecordsTheCallerIdentityAndTheResponseRequestId() throws Exception {
        int port = baseUri.getPort();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "ct-identity-" + suffix;
        String logs = "ct-identity-logs-" + suffix;
        String trail = "ct-identity-trail-" + suffix;
        String root = auth("test", "s3");

        given().header("Authorization", root).put("/" + bucket).then().statusCode(200);
        given().header("Authorization", root).put("/" + logs).then().statusCode(200);
        cleanup.register(() -> EnforcementFixtures.removeBucket(port, root, logs));
        cleanup.register(() -> EnforcementFixtures.removeBucket(port, root, bucket));
        cloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + logs + "\"}");
        cleanup.register(() -> cloudTrail("DeleteTrail", "{\"Name\":\"" + trail + "\"}"));
        cloudTrail("PutEventSelectors", """
                {"TrailName":"%s","EventSelectors":[{"ReadWriteType":"All","IncludeManagementEvents":false,
                 "DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::%s/"]}]}]}"""
                .formatted(trail, bucket));
        cloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");

        String userName = "ct-user-" + suffix;
        EnforcementFixtures.UserCredentials user = EnforcementFixtures.createUser(cleanup, port,
                auth("test", "iam"), userName);
        String roleName = "ct-role-" + suffix;
        String roleArn = EnforcementFixtures.createRole(cleanup, port, ACCOUNT, "/", roleName, """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}""");
        EnforcementFixtures.Session session = EnforcementFixtures.assumeRole(port, "test", roleArn);

        Map<String, String> requestIds = new HashMap<>();
        requestIds.put("user.txt", put(bucket, "user.txt", auth(user.accessKeyId(), "s3"), null));
        requestIds.put("role.txt", put(bucket, "role.txt", auth(session.accessKeyId(), "s3"), session.sessionToken()));
        requestIds.put("root.txt", put(bucket, "root.txt", root, null));

        writer.flushNow();

        Map<String, JsonNode> records = putRecords(logs, root);
        assertEquals(requestIds.keySet(), records.keySet(), "records: " + records);
        for (Map.Entry<String, String> entry : requestIds.entrySet()) {
            JsonNode record = records.get(entry.getKey());
            assertTrue(S3_REQUEST_ID.matcher(entry.getValue()).matches(), entry.getValue());
            assertEquals(entry.getValue(), record.path("requestID").asText(), record.toString());
            assertFalse(record.has("tlsDetails"), record.toString());
            assertFalse(record.path("additionalEventData").has("CipherSuite"), record.toString());
        }

        JsonNode iamUser = records.get("user.txt").path("userIdentity");
        assertEquals("IAMUser", iamUser.path("type").asText(), iamUser.toString());
        assertEquals(userName, iamUser.path("userName").asText());
        assertEquals("arn:aws:iam::" + ACCOUNT + ":user/" + userName, iamUser.path("arn").asText());
        assertTrue(iamUser.path("principalId").asText().startsWith("AIDA"), iamUser.toString());
        assertEquals(user.accessKeyId(), iamUser.path("accessKeyId").asText());
        assertFalse(iamUser.has("sessionContext"));

        JsonNode assumed = records.get("role.txt").path("userIdentity");
        assertEquals("AssumedRole", assumed.path("type").asText(), assumed.toString());
        assertEquals("arn:aws:sts::" + ACCOUNT + ":assumed-role/" + roleName + "/s", assumed.path("arn").asText());
        assertEquals(session.accessKeyId(), assumed.path("accessKeyId").asText());
        JsonNode issuer = assumed.path("sessionContext").path("sessionIssuer");
        assertEquals("Role", issuer.path("type").asText());
        assertEquals(roleArn, issuer.path("arn").asText());
        assertEquals(roleName, issuer.path("userName").asText());
        assertEquals(ACCOUNT, issuer.path("accountId").asText());
        assertTrue(issuer.path("principalId").asText().startsWith("AROA"), issuer.toString());
        assertEquals(issuer.path("principalId").asText() + ":s", assumed.path("principalId").asText());
        assertNotNull(assumed.path("sessionContext").path("attributes").path("creationDate").textValue());
        assertEquals("false", assumed.path("sessionContext").path("attributes").path("mfaAuthenticated").asText());

        JsonNode rootIdentity = records.get("root.txt").path("userIdentity");
        assertEquals("{\"type\":\"Root\",\"principalId\":\"" + ACCOUNT + "\",\"arn\":\"arn:aws:iam::" + ACCOUNT
                + ":root\",\"accountId\":\"" + ACCOUNT + "\",\"accessKeyId\":\"test\"}", rootIdentity.toString());
    }

    private static String put(String bucket, String key, String authorization, String token) {
        RequestSpecification request = given().header("Authorization", authorization).body("hello");
        if (token != null) {
            request = request.header("X-Amz-Security-Token", token);
        }
        return request.when().put("/" + bucket + "/" + key).then().statusCode(200)
                .extract().header("x-amz-request-id");
    }

    /** The trail's PutObject records of objects in the source bucket, by key. */
    private static Map<String, JsonNode> putRecords(String logs, String authorization) throws Exception {
        String listing = given().header("Authorization", authorization).get("/" + logs + "?list-type=2")
                .then().statusCode(200).extract().asString();
        ObjectMapper mapper = new ObjectMapper();
        Map<String, JsonNode> records = new HashMap<>();
        Matcher key = KEY.matcher(listing);
        while (key.find()) {
            byte[] gz = given().header("Authorization", authorization).get("/" + logs + "/" + key.group(1))
                    .then().statusCode(200).extract().asByteArray();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                for (JsonNode record : mapper.readTree(in.readAllBytes()).path("Records")) {
                    if ("PutObject".equals(record.path("eventName").asText())) {
                        records.put(record.path("requestParameters").path("key").asText(), record);
                    }
                }
            }
        }
        return records;
    }

    private static void cloudTrail(String action, String body) {
        given().header("X-Amz-Target", "CloudTrail_20131101." + action)
                .header("Authorization", auth("test", "cloudtrail"))
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .when().post("/")
                .then().statusCode(200);
    }
}
