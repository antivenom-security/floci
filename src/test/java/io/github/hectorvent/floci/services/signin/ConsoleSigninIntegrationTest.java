package io.github.hectorvent.floci.services.signin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.RequestScopes;
import io.github.hectorvent.floci.core.common.Totp;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailLogWriter;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.client.builder.AwsClientBuilder;
import software.amazon.awssdk.awscore.client.builder.AwsSyncClientBuilder;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.Event;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttributeKey;
import software.amazon.awssdk.services.eventbridge.EventBridgeClient;
import software.amazon.awssdk.services.eventbridge.model.RuleState;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.AccessKey;
import software.amazon.awssdk.services.iam.model.VirtualMFADevice;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ThreadLocalRandom;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Console sign-in through Floci's password endpoint and AWS's federation endpoint. Every attempt
 * is asserted as the one record AWS's console sign-in examples show, found alike in event history,
 * a trail's log file and an EventBridge rule's queue. Each test runs in an account of its own.
 */
@QuarkusTest
@Timeout(120)
class ConsoleSigninIntegrationTest {

    private static final String PASSWORD = "Sign-in-Passw0rd!";
    private static final String USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) Floci-test";
    private static final String SIGN_IN_PATTERN =
            "{\"source\":[\"aws.signin\"],\"detail-type\":[\"AWS Console Sign In via CloudTrail\"]}";

    private final ObjectMapper mapper = new ObjectMapper();

    @TestHTTPResource("/")
    URI endpoint;

    @Inject
    CloudTrailLogWriter writer;

    @Inject
    S3Service s3;

    @Test
    void passwordSignInRecordsASuccessfulConsoleLogin() throws Exception {
        Account account = new Account();
        String userId = account.userWithPassword("alice");

        signIn(account.id, "alice", PASSWORD, null).statusCode(200).body("ConsoleLogin",
                equalTo("Success"));

        JsonNode record = account.recorded("ConsoleLogin");
        assertSignInEvent(record, "ConsoleLogin", account.id, "us-east-1");
        assertEquals(Set.of("type", "principalId", "arn", "accountId", "userName"),
                keys(record.path("userIdentity")));
        assertEquals("IAMUser", record.path("userIdentity").path("type").asText());
        assertEquals(userId, record.path("userIdentity").path("principalId").asText());
        assertEquals("arn:aws:iam::" + account.id + ":user/alice", record.path("userIdentity").path("arn").asText());
        assertEquals("alice", record.path("userIdentity").path("userName").asText());
        assertEquals("Success", record.path("responseElements").path("ConsoleLogin").asText());
        assertFalse(record.has("errorMessage"));
        assertEquals(List.of("LoginTo", "MobileVersion", "MFAUsed"), fieldNames(record.path("additionalEventData")));
        assertEquals("https://console.aws.amazon.com/console/home",
                record.path("additionalEventData").path("LoginTo").asText());
        assertEquals("No", record.path("additionalEventData").path("MobileVersion").asText());
        assertEquals("No", record.path("additionalEventData").path("MFAUsed").asText());
    }

    @Test
    void wrongPasswordRecordsAFailureWithoutAnArn() throws Exception {
        Account account = new Account();
        String userId = account.userWithPassword("paulo");

        signIn(account.id, "paulo", "not-the-password", null).statusCode(401)
                .body("ConsoleLogin", equalTo("Failure"));

        JsonNode record = account.recorded("ConsoleLogin");
        assertSignInEvent(record, "ConsoleLogin", account.id, "us-east-1");
        assertEquals(Set.of("type", "principalId", "accountId", "accessKeyId", "userName"),
                keys(record.path("userIdentity")));
        assertEquals(userId, record.path("userIdentity").path("principalId").asText());
        assertEquals("", record.path("userIdentity").path("accessKeyId").asText());
        assertEquals("paulo", record.path("userIdentity").path("userName").asText());
        assertEquals("Failed authentication", record.path("errorMessage").asText());
        assertFalse(record.has("errorCode"));
        assertEquals("Failure", record.path("responseElements").path("ConsoleLogin").asText());
        assertEquals("No", record.path("additionalEventData").path("MFAUsed").asText());
    }

    @Test
    void unknownUserNameIsHidden() throws Exception {
        Account account = new Account();

        signIn(account.id, "my-bank-password", PASSWORD, null).statusCode(401);

        JsonNode record = account.recorded("ConsoleLogin");
        assertSignInEvent(record, "ConsoleLogin", account.id, "us-east-1");
        assertEquals(Set.of("type", "accountId", "accessKeyId", "userName"), keys(record.path("userIdentity")));
        assertEquals("IAMUser", record.path("userIdentity").path("type").asText());
        assertEquals("HIDDEN_DUE_TO_SECURITY_REASONS", record.path("userIdentity").path("userName").asText());
        assertEquals("Failure", record.path("responseElements").path("ConsoleLogin").asText());
    }

    @Test
    void mfaUserWithoutACodeGetsOnlyCheckMfa() throws Exception {
        Account account = new Account();
        account.userWithPassword("mary");
        account.mfaDevice("mary");

        signIn(account.id, "mary", PASSWORD, null).statusCode(401);

        JsonNode record = account.recorded("CheckMfa");
        assertSignInEvent(record, "CheckMfa", account.id, "us-east-1");
        assertEquals(Set.of("type", "principalId", "accountId", "accessKeyId", "userName"),
                keys(record.path("userIdentity")));
        assertEquals("Success", record.path("responseElements").path("CheckMfa").asText());
        assertEquals("Virtual MFA", record.path("additionalEventData").path("MfaType").asText());
        assertTrue(account.lookup("ConsoleLogin").isEmpty());
    }

    @Test
    void wrongMfaCodeRecordsAFailureWithMfaUsed() throws Exception {
        Account account = new Account();
        account.userWithPassword("mfa-wrong");
        String seed = account.mfaDevice("mfa-wrong");
        String wrong = Totp.codeAt(seed, Totp.stepAt(Instant.now()) + 5);

        signIn(account.id, "mfa-wrong", PASSWORD, wrong).statusCode(401);

        JsonNode record = account.recorded("ConsoleLogin");
        assertSignInEvent(record, "ConsoleLogin", account.id, "us-east-1");
        assertEquals("Failure", record.path("responseElements").path("ConsoleLogin").asText());
        assertEquals("Yes", record.path("additionalEventData").path("MFAUsed").asText());
        assertFalse(record.path("additionalEventData").has("MFAIdentifier"));
        assertEquals("", record.path("userIdentity").path("accessKeyId").asText());
    }

    @Test
    void rightMfaCodeRecordsTheDevice() throws Exception {
        Account account = new Account();
        account.userWithPassword("anaya");
        String seed = account.mfaDevice("anaya");

        signIn(account.id, "anaya", PASSWORD, Totp.codeAt(seed, Totp.stepAt(Instant.now()))).statusCode(200);

        JsonNode record = account.recorded("ConsoleLogin");
        assertSignInEvent(record, "ConsoleLogin", account.id, "us-east-1");
        assertEquals("Success", record.path("responseElements").path("ConsoleLogin").asText());
        assertEquals(List.of("LoginTo", "MobileVersion", "MFAIdentifier", "MFAUsed"),
                fieldNames(record.path("additionalEventData")));
        assertEquals("arn:aws:iam::" + account.id + ":mfa/anaya-device",
                record.path("additionalEventData").path("MFAIdentifier").asText());
        assertEquals("Yes", record.path("additionalEventData").path("MFAUsed").asText());
        assertEquals("arn:aws:iam::" + account.id + ":user/anaya", record.path("userIdentity").path("arn").asText());
    }

    @Test
    void aliasAndRegionalHostSignInRecordsInThatRegion() throws Exception {
        Account account = new Account("us-west-2");
        account.userWithPassword("regional");
        String alias = "alias-" + account.id;
        try (IamClient iam = account.client(IamClient.builder(), Region.AWS_GLOBAL)) {
            iam.createAccountAlias(r -> r.accountAlias(alias));
        }

        request().header("Host", "us-west-2.signin.aws.amazon.com")
                .formParam("account", alias).formParam("username", "regional").formParam("password", PASSWORD)
                .when().post("/_floci/signin/console").then().statusCode(200);

        JsonNode record = account.recorded("ConsoleLogin");
        assertSignInEvent(record, "ConsoleLogin", account.id, "us-west-2");
        assertEquals("Success", record.path("responseElements").path("ConsoleLogin").asText());
    }

    @Test
    void unknownAccountAliasFailsWithoutARecord() {
        signIn("no-such-alias-" + ThreadLocalRandom.current().nextInt(1_000_000), "alice", PASSWORD, null)
                .statusCode(401);
    }

    @Test
    void federationSignsAnAssumedRoleIn() throws Exception {
        Account account = new Account();
        Credentials credentials = account.assumeRole("broker-role", "JohnDoe");
        String session = session(credentials);

        String token = browser().queryParam("Action", "getSigninToken").queryParam("Session", session)
                .queryParam("SessionDuration", "1800")
                .when().get("/federation").then().statusCode(200).extract().path("SigninToken");
        assertNotNull(token);

        JsonNode issued = account.recorded("GetSigninToken");
        assertSignInEvent(issued, "GetSigninToken", account.id, "us-east-1");
        assertEquals(credentials.accessKeyId(),
                issued.path("responseElements").path("credentials").path("accessKeyId").asText());
        assertEquals("Success", issued.path("responseElements").path("GetSigninToken").asText());
        assertEquals(credentials.accessKeyId(), issued.path("userIdentity").path("accessKeyId").asText());

        String destination = "https://console.aws.amazon.com/";
        String location = browser().redirects().follow(false)
                .queryParam("Action", "login").queryParam("Issuer", "https://example.com")
                .queryParam("Destination", destination).queryParam("SigninToken", token)
                .when().get("/federation").then().statusCode(302).extract().header("Location");
        assertEquals(destination, location);

        JsonNode record = account.recorded("ConsoleLogin");
        assertSignInEvent(record, "ConsoleLogin", account.id, "us-east-1");
        JsonNode identity = record.path("userIdentity");
        assertEquals("AssumedRole", identity.path("type").asText());
        assertEquals("arn:aws:sts::" + account.id + ":assumed-role/broker-role/JohnDoe", identity.path("arn").asText());
        assertEquals(credentials.accessKeyId(), identity.path("accessKeyId").asText());
        assertEquals("Role", identity.path("sessionContext").path("sessionIssuer").path("type").asText());
        assertEquals("Success", record.path("responseElements").path("ConsoleLogin").asText());
        assertEquals(List.of("MobileVersion", "MFAUsed"), fieldNames(record.path("additionalEventData")));

        browser().redirects().follow(false).queryParam("Action", "login").queryParam("Destination", destination)
                .queryParam("SigninToken", token).when().get("/federation").then().statusCode(400);
    }

    @Test
    void federationSignsAFederatedUserInOverPost() throws Exception {
        Account account = new Account();
        account.userWithPassword("broker");
        Credentials credentials;
        try (IamClient iam = account.client(IamClient.builder(), Region.AWS_GLOBAL)) {
            AccessKey key = iam.createAccessKey(r -> r.userName("broker")).accessKey();
            try (StsClient sts = StsClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                    .httpClient(UrlConnectionHttpClient.create())
                    .credentialsProvider(StaticCredentialsProvider.create(
                            AwsBasicCredentials.create(key.accessKeyId(), key.secretAccessKey())))
                    .build()) {
                credentials = sts.getFederationToken(r -> r.name("fed-user").policy(
                        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\","
                                + "\"Resource\":\"*\"}]}")).credentials();
            }
        }
        String session = session(credentials);

        browser().formParam("Action", "getSigninToken").formParam("Session", session)
                .formParam("SessionDuration", "1800")
                .when().post("/federation").then().statusCode(400);
        String token = browser().formParam("Action", "getSigninToken").formParam("Session", session)
                .when().post("/federation").then().statusCode(200).extract().path("SigninToken");
        browser().redirects().follow(false).formParam("Action", "login").formParam("SigninToken", token)
                .formParam("Destination", "https://console.aws.amazon.com/")
                .when().post("/federation").then().statusCode(302);

        JsonNode record = account.recorded("ConsoleLogin");
        assertSignInEvent(record, "ConsoleLogin", account.id, "us-east-1");
        assertEquals("FederatedUser", record.path("userIdentity").path("type").asText());
        assertEquals(credentials.accessKeyId(), record.path("userIdentity").path("accessKeyId").asText());
    }

    @Test
    void federationRefusesAWrongSessionKey() throws Exception {
        Account account = new Account();
        Credentials credentials = account.assumeRole("refused-role", "Mallory");
        String session = mapper.writeValueAsString(Map.of("sessionId", credentials.accessKeyId(),
                "sessionKey", "wrong", "sessionToken", credentials.sessionToken()));

        browser().queryParam("Action", "getSigninToken").queryParam("Session", session)
                .when().get("/federation").then().statusCode(400);
        assertTrue(account.lookup("GetSigninToken").isEmpty());
    }

    private void assertSignInEvent(JsonNode record, String eventName, String accountId, String region) {
        assertEquals("1.11", record.path("eventVersion").asText());
        assertEquals("signin.amazonaws.com", record.path("eventSource").asText());
        assertEquals(eventName, record.path("eventName").asText());
        assertEquals(region, record.path("awsRegion").asText());
        assertEquals("127.0.0.1", record.path("sourceIPAddress").asText());
        assertEquals(USER_AGENT, record.path("userAgent").asText());
        assertTrue(record.has("requestParameters") && record.path("requestParameters").isNull());
        assertFalse(record.has("requestID"));
        assertFalse(record.path("readOnly").asBoolean());
        assertEquals("AwsConsoleSignIn", record.path("eventType").asText());
        assertTrue(record.path("managementEvent").asBoolean());
        assertEquals(accountId, record.path("recipientAccountId").asText());
        assertEquals("Management", record.path("eventCategory").asText());
        assertEquals(accountId, record.path("userIdentity").path("accountId").asText());
    }

    private ValidatableResponse signIn(String account, String user, String password,
                                                                String mfaCode) {
        RequestSpecification spec = request().formParam("account", account).formParam("username", user)
                .formParam("password", password);
        if (mfaCode != null) {
            spec = spec.formParam("mfa_code", mfaCode);
        }
        return spec.when().post("/_floci/signin/console").then();
    }

    private RequestSpecification request() {
        return browser().contentType("application/x-www-form-urlencoded");
    }

    private static RequestSpecification browser() {
        return given().header("User-Agent", USER_AGENT);
    }

    private String session(Credentials credentials) throws Exception {
        return mapper.writeValueAsString(Map.of("sessionId", credentials.accessKeyId(),
                "sessionKey", credentials.secretAccessKey(), "sessionToken", credentials.sessionToken()));
    }

    private static Set<String> keys(JsonNode node) {
        return new TreeSet<>(fieldNames(node));
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private final class Account {

        private final String id = String.valueOf(ThreadLocalRandom.current().nextLong(100_000_000_000L, 999_999_999_999L));
        private final String region;
        private final String bucket = "signin-trail-" + id;
        private final String queueUrl;

        Account() {
            this("us-east-1");
        }

        Account(String region) {
            this.region = region;
            RequestScopes.runAs(id, () -> s3.createBucket(bucket, region));
            try (CloudTrailClient cloudTrail = client(CloudTrailClient.builder(), Region.of(region));
                 SqsClient sqs = client(SqsClient.builder(), Region.of(region));
                 EventBridgeClient events = client(EventBridgeClient.builder(), Region.of(region))) {
                cloudTrail.createTrail(r -> r.name("signin-trail").s3BucketName(bucket));
                cloudTrail.startLogging(r -> r.name("signin-trail"));
                queueUrl = sqs.createQueue(r -> r.queueName("signin-events")).queueUrl();
                String queueArn = sqs.getQueueAttributes(r -> r.queueUrl(queueUrl)
                        .attributeNames(QueueAttributeName.QUEUE_ARN)).attributes().get(QueueAttributeName.QUEUE_ARN);
                events.putRule(r -> r.name("sign-ins").eventPattern(SIGN_IN_PATTERN).state(RuleState.ENABLED));
                events.putTargets(r -> r.rule("sign-ins").targets(t -> t.id("queue").arn(queueArn)));
            }
        }

        <B extends AwsClientBuilder<B, C> & AwsSyncClientBuilder<B, C>, C> C client(B builder, Region clientRegion) {
            builder.httpClient(UrlConnectionHttpClient.create());
            return builder.endpointOverride(endpoint).region(clientRegion)
                    .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(id, "secret")))
                    .build();
        }

        String userWithPassword(String user) {
            try (IamClient iam = client(IamClient.builder(), Region.AWS_GLOBAL)) {
                String userId = iam.createUser(r -> r.userName(user)).user().userId();
                iam.createLoginProfile(r -> r.userName(user).password(PASSWORD));
                return userId;
            }
        }

        String mfaDevice(String user) {
            try (IamClient iam = client(IamClient.builder(), Region.AWS_GLOBAL)) {
                VirtualMFADevice device = iam.createVirtualMFADevice(r -> r.virtualMFADeviceName(user + "-device"))
                        .virtualMFADevice();
                String seed = device.base32StringSeed().asUtf8String();
                long step = Totp.stepAt(Instant.now());
                iam.enableMFADevice(r -> r.userName(user).serialNumber(device.serialNumber())
                        .authenticationCode1(Totp.codeAt(seed, step - 1)).authenticationCode2(Totp.codeAt(seed, step)));
                return seed;
            }
        }

        Credentials assumeRole(String role, String sessionName) {
            try (IamClient iam = client(IamClient.builder(), Region.AWS_GLOBAL);
                 StsClient sts = client(StsClient.builder(), Region.US_EAST_1)) {
                String roleArn = iam.createRole(r -> r.roleName(role).assumeRolePolicyDocument(
                        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":"
                                + "\"arn:aws:iam::" + id + ":root\"},\"Action\":\"sts:AssumeRole\"}]}")).role().arn();
                return sts.assumeRole(r -> r.roleArn(roleArn).roleSessionName(sessionName)).credentials();
            }
        }

        List<Event> lookup(String eventName) {
            try (CloudTrailClient cloudTrail = client(CloudTrailClient.builder(), Region.of(region))) {
                return cloudTrail.lookupEvents(r -> r.lookupAttributes(a -> a
                        .attributeKey(LookupAttributeKey.EVENT_NAME).attributeValue(eventName))).events();
            }
        }

        /** The newest {@code eventName} record, asserted identical in history, the trail file and EventBridge. */
        JsonNode recorded(String eventName) throws Exception {
            List<Event> events = lookup(eventName);
            assertFalse(events.isEmpty(), "no " + eventName + " in event history");
            JsonNode fromHistory = mapper.readTree(events.get(0).cloudTrailEvent());

            writer.flushNow();
            JsonNode fromTrail = null;
            for (S3Object object : RequestScopes.callAs(id, () -> s3.listObjects(bucket, "AWSLogs/", null, 1000))) {
                byte[] gz = RequestScopes.callAs(id, () -> s3.getObject(bucket, object.getKey()).getData());
                try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                    for (JsonNode record : mapper.readTree(in.readAllBytes()).path("Records")) {
                        if (record.path("eventID").equals(fromHistory.path("eventID"))) {
                            fromTrail = record;
                        }
                    }
                }
            }
            assertEquals(fromHistory, fromTrail, "trail file record");

            JsonNode fromEventBridge = null;
            try (SqsClient sqs = client(SqsClient.builder(), Region.of(region))) {
                for (int attempt = 0; attempt < 5 && fromEventBridge == null; attempt++) {
                    for (Message message : sqs.receiveMessage(r -> r.queueUrl(queueUrl).waitTimeSeconds(5)
                            .maxNumberOfMessages(10)).messages()) {
                        JsonNode event = mapper.readTree(message.body());
                        if (event.path("detail").path("eventID").equals(fromHistory.path("eventID"))) {
                            assertEquals("aws.signin", event.path("source").asText());
                            assertEquals("AWS Console Sign In via CloudTrail", event.path("detail-type").asText());
                            assertEquals(region, event.path("region").asText());
                            fromEventBridge = event.path("detail");
                        }
                    }
                }
            }
            assertEquals(fromHistory, fromEventBridge, "EventBridge record");
            return fromHistory;
        }
    }
}
