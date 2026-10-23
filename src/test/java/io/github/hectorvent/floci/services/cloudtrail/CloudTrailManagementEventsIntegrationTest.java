package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.services.ecs.container.EcsTaskRoleCredentials;
import io.github.hectorvent.floci.services.lambda.launcher.LambdaExecutionRoleCredentials;
import io.github.hectorvent.floci.services.lambda.model.LambdaFunction;
import io.github.hectorvent.floci.testing.IamEnforcementProfile;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.CloudTrailException;
import software.amazon.awssdk.services.cloudtrail.model.Event;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttributeKey;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.AccessKey;
import software.amazon.awssdk.services.iam.model.IamException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Management events land in event history, with or without a trail, as AWS records them: the
 * caller's identity, request parameters and response elements in CloudTrail's form, denials with
 * their error, read-only calls without response elements, and AWS services' own role assumptions.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class CloudTrailManagementEventsIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String ALLOW_ALL = """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}""";

    private final ObjectMapper mapper = new ObjectMapper();

    @TestHTTPResource("/")
    URI endpoint;

    @Inject
    CloudTrailService trails;

    @Inject
    EcsTaskRoleCredentials ecsTaskRoleCredentials;

    @Inject
    LambdaExecutionRoleCredentials lambdaExecutionRoleCredentials;

    @Test
    void iamUserCreateUserIsRecordedWithParametersAndResponse() throws Exception {
        User admin = adminUser();
        String created = "richard-" + suffix();
        try (IamClient iam = iam(admin.keys())) {
            iam.createUser(r -> r.userName(created));
        }

        JsonNode record = latest(LookupAttributeKey.USERNAME, admin.name(), "CreateUser");
        assertEquals("1.11", record.path("eventVersion").asText());
        assertEquals("iam.amazonaws.com", record.path("eventSource").asText());
        assertEquals("us-east-1", record.path("awsRegion").asText());
        assertEquals("IAMUser", record.path("userIdentity").path("type").asText());
        assertEquals(admin.name(), record.path("userIdentity").path("userName").asText());
        assertEquals(created, record.path("requestParameters").path("userName").asText());
        assertEquals(created, record.path("responseElements").path("user").path("userName").asText());
        assertFalse(record.path("readOnly").asBoolean());
        assertEquals("Management", record.path("eventCategory").asText());
        assertFalse(record.has("tlsDetails"));
    }

    @Test
    void rootKeyActionsAreRecordedAsRoot() throws Exception {
        String created = "rooted-" + suffix();
        try (IamClient iam = iam(AwsBasicCredentials.create("test", "test"))) {
            iam.createUser(r -> r.userName(created));
        }
        for (Event event : lookup(LookupAttributeKey.EVENT_NAME, "CreateUser")) {
            JsonNode record = mapper.readTree(event.cloudTrailEvent());
            if ("test".equals(record.path("userIdentity").path("accessKeyId").asText())) {
                assertEquals("Root", record.path("userIdentity").path("type").asText());
                assertEquals("arn:aws:iam::" + ACCOUNT + ":root", record.path("userIdentity").path("arn").asText());
                assertEquals("root", event.username());
            }
        }
    }

    @Test
    void deniedCreateUserIsRecordedWithItsError() throws Exception {
        String nobody = "nobody-" + suffix();
        AwsCredentials keys = createUser(nobody, null);
        try (IamClient iam = iam(keys)) {
            assertThrows(IamException.class, () -> iam.createUser(r -> r.userName("denied-" + suffix())));
        }

        JsonNode record = latest(LookupAttributeKey.USERNAME, nobody, "CreateUser");
        assertEquals("AccessDenied", record.path("errorCode").asText());
        assertThat(record.path("errorMessage").asText(), containsString("iam:CreateUser"));
        assertTrue(record.path("responseElements").isNull());
    }

    @Test
    void assumeRoleAndTheSessionsActionsAreRecorded() throws Exception {
        User admin = adminUser();
        String roleName = "role-" + suffix();
        String roleArn;
        Credentials session;
        try (IamClient iam = iam(admin.keys())) {
            roleArn = iam.createRole(r -> r.roleName(roleName).assumeRolePolicyDocument("""
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                      "Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}]}""".formatted(ACCOUNT)))
                    .role().arn();
            iam.putRolePolicy(r -> r.roleName(roleName).policyName("all").policyDocument(ALLOW_ALL));
        }
        try (StsClient sts = StsClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(admin.keys()))
                .httpClient(UrlConnectionHttpClient.create()).build()) {
            session = sts.assumeRole(r -> r.roleArn(roleArn).roleSessionName("worker")).credentials();
        }

        JsonNode assume = latest(LookupAttributeKey.USERNAME, admin.name(), "AssumeRole");
        assertEquals(roleArn, assume.path("requestParameters").path("roleArn").asText());
        assertEquals("HIDDEN_DUE_TO_SECURITY_REASONS",
                assume.path("responseElements").path("credentials").path("sessionToken").asText());
        assertEquals(session.accessKeyId(),
                assume.path("responseElements").path("credentials").path("accessKeyId").asText());
        assertThat(assume.toString(), not(containsString(session.sessionToken())));
        assertTrue(assume.path("readOnly").asBoolean());
        assertEquals("HIDDEN_DUE_TO_SECURITY_REASONS",
                assume.path("responseElements").path("credentials").path("secretAccessKey").asText());
        assertTrue(lookup(LookupAttributeKey.READ_ONLY, "true").stream()
                .anyMatch(event -> "AssumeRole".equals(event.eventName())
                        && event.cloudTrailEvent().contains(session.accessKeyId())));
        assertEquals("AWS::IAM::Role", assume.path("resources").path(0).path("type").asText());

        try (IamClient iam = iam(AwsSessionCredentials.create(session.accessKeyId(), session.secretAccessKey(),
                session.sessionToken()))) {
            iam.createUser(r -> r.userName("by-session-" + suffix()));
        }
        JsonNode action = latest(LookupAttributeKey.ACCESS_KEY_ID, session.accessKeyId(), "CreateUser");
        JsonNode identity = action.path("userIdentity");
        assertEquals("AssumedRole", identity.path("type").asText());
        assertEquals("arn:aws:sts::" + ACCOUNT + ":assumed-role/" + roleName + "/worker", identity.path("arn").asText());
        assertEquals(roleArn, identity.path("sessionContext").path("sessionIssuer").path("arn").asText());
    }

    @Test
    void getSecretValueIsReadOnlyAndNeverCarriesTheSecret() throws Exception {
        User admin = adminUser();
        String secret = "s3cr3t-" + suffix();
        String name = "secret-" + suffix();
        try (SecretsManagerClient secrets = SecretsManagerClient.builder().endpointOverride(endpoint)
                .region(Region.US_EAST_1).credentialsProvider(StaticCredentialsProvider.create(admin.keys()))
                .httpClient(UrlConnectionHttpClient.create()).build()) {
            secrets.createSecret(r -> r.name(name).secretString(secret));
            secrets.getSecretValue(r -> r.secretId(name));
        }

        JsonNode create = latest(LookupAttributeKey.USERNAME, admin.name(), "CreateSecret");
        assertEquals("HIDDEN_DUE_TO_SECURITY_REASONS", create.path("requestParameters").path("secretString").asText());
        JsonNode get = latest(LookupAttributeKey.USERNAME, admin.name(), "GetSecretValue");
        assertTrue(get.path("readOnly").asBoolean());
        assertTrue(get.path("responseElements").isNull());
        assertEquals(name, get.path("requestParameters").path("secretId").asText());
        assertThat(get.toString(), not(containsString(secret)));
        assertThat(create.toString(), not(containsString(secret)));
    }

    @Test
    void excludedManagementEventSourcesStayOutOfTheTrailButInHistory() throws Exception {
        String trailName = "mgmt-" + suffix();
        try (CloudTrailClient cloudTrail = cloudTrail(AwsBasicCredentials.create("test", "test"), true);
             KmsClient kms = KmsClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                     .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                     .httpClient(UrlConnectionHttpClient.create()).build();
             IamClient iam = iam(AwsBasicCredentials.create("test", "test"))) {
            cloudTrail.createTrail(r -> r.name(trailName).s3BucketName("trail-bucket-" + suffix()));
            cloudTrail.putEventSelectors(r -> r.trailName(trailName).eventSelectors(s -> s
                    .readWriteType("All").includeManagementEvents(true)
                    .excludeManagementEventSources("kms.amazonaws.com")));
            cloudTrail.startLogging(r -> r.name(trailName));
            kms.createKey(r -> r.description("excluded"));
            iam.createUser(r -> r.userName("included-" + suffix()));
            cloudTrail.stopLogging(r -> r.name(trailName));

            List<String> sources = drain(trailName).stream().map(record -> record.path("eventSource").asText()).toList();
            assertTrue(sources.contains("iam.amazonaws.com"), sources.toString());
            assertThat(sources, everyItem(not(containsString("kms"))));
            assertFalse(lookup(LookupAttributeKey.EVENT_NAME, "CreateKey").isEmpty());
            cloudTrail.deleteTrail(r -> r.name(trailName));
        }
    }

    @Test
    void writeOnlyTrailWithoutGlobalEventsSkipsAssumeRoleAndIam() throws Exception {
        String trailName = "write-" + suffix();
        User admin = adminUser();
        String roleName = "wo-" + suffix();
        try (CloudTrailClient cloudTrail = cloudTrail(AwsBasicCredentials.create("test", "test"), true);
             IamClient iam = iam(admin.keys());
             StsClient sts = StsClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                     .credentialsProvider(StaticCredentialsProvider.create(admin.keys()))
                     .httpClient(UrlConnectionHttpClient.create()).build();
             SecretsManagerClient secrets = SecretsManagerClient.builder().endpointOverride(endpoint)
                     .region(Region.US_EAST_1).credentialsProvider(StaticCredentialsProvider.create(admin.keys()))
                     .httpClient(UrlConnectionHttpClient.create()).build()) {
            String roleArn = iam.createRole(r -> r.roleName(roleName).assumeRolePolicyDocument("""
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                      "Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"sts:AssumeRole"}]}""".formatted(ACCOUNT)))
                    .role().arn();
            cloudTrail.createTrail(r -> r.name(trailName).s3BucketName("trail-bucket-" + suffix())
                    .includeGlobalServiceEvents(false));
            cloudTrail.putEventSelectors(r -> r.trailName(trailName).eventSelectors(s -> s.readWriteType("WriteOnly")));
            cloudTrail.startLogging(r -> r.name(trailName));
            sts.assumeRole(r -> r.roleArn(roleArn).roleSessionName("wo"));
            iam.createUser(r -> r.userName("global-" + suffix()));
            secrets.createSecret(r -> r.name("regional-" + suffix()).secretString("x"));
            cloudTrail.stopLogging(r -> r.name(trailName));

            List<String> names = drain(trailName).stream().map(record -> record.path("eventName").asText()).toList();
            assertTrue(names.contains("CreateSecret"), names.toString());
            assertFalse(names.contains("AssumeRole"), names.toString());
            assertFalse(names.contains("CreateUser"), names.toString());
            cloudTrail.deleteTrail(r -> r.name(trailName));
        }
    }

    @Test
    void serviceEventsRouteToTheRecipientAccountsTrails() throws Exception {
        String other = "111111111111";
        String otherTrail = "acct-" + suffix();
        String defaultTrail = "dflt-" + suffix();
        String roleName = "x-" + suffix();
        String roleArn;
        try (IamClient iam = iam(AwsBasicCredentials.create(other, "test"));
             CloudTrailClient otherCloudTrail = cloudTrail(AwsBasicCredentials.create(other, "test"), true);
             CloudTrailClient cloudTrail = cloudTrail(AwsBasicCredentials.create("test", "test"), true)) {
            roleArn = iam.createRole(r -> r.roleName(roleName).assumeRolePolicyDocument("""
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                      "Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}"""))
                    .role().arn();
            otherCloudTrail.createTrail(r -> r.name(otherTrail).s3BucketName("trail-bucket-" + suffix()));
            otherCloudTrail.startLogging(r -> r.name(otherTrail));
            cloudTrail.createTrail(r -> r.name(defaultTrail).s3BucketName("trail-bucket-" + suffix()));
            cloudTrail.startLogging(r -> r.name(defaultTrail));

            String taskArn = "arn:aws:ecs:us-east-1:" + other + ":task/c/" + suffix();
            assertTrue(ecsTaskRoleCredentials.issue(taskArn, roleArn, other, Instant.now()).isPresent());
            ecsTaskRoleCredentials.revoke(taskArn);
            otherCloudTrail.stopLogging(r -> r.name(otherTrail));
            cloudTrail.stopLogging(r -> r.name(defaultTrail));

            assertTrue(drain(otherTrail).stream().anyMatch(record -> record.toString().contains(roleArn)));
            assertFalse(drain(defaultTrail).stream().anyMatch(record -> record.toString().contains(roleArn)));
            otherCloudTrail.deleteTrail(r -> r.name(otherTrail));
            cloudTrail.deleteTrail(r -> r.name(defaultTrail));
        }
    }

    @Test
    void emptyEventSelectorsAreRejected() {
        String trailName = "empty-" + suffix();
        try (CloudTrailClient cloudTrail = cloudTrail(AwsBasicCredentials.create("test", "test"), true)) {
            cloudTrail.createTrail(r -> r.name(trailName).s3BucketName("trail-bucket-" + suffix()));
            CloudTrailException thrown = assertThrows(CloudTrailException.class,
                    () -> cloudTrail.putEventSelectors(r -> r.trailName(trailName).eventSelectors(List.of())));
            assertEquals("InvalidEventSelectorsException", thrown.awsErrorDetails().errorCode());
            cloudTrail.deleteTrail(r -> r.name(trailName));
        }
    }

    private List<ObjectNode> drain(String trailName) {
        CloudTrailService.TrailKey key = new CloudTrailService.TrailKey("us-east-1", trailName, "us-east-1");
        List<ObjectNode> records = trails.drainPendingRecords(key);
        trails.completeDelivery(key);
        return records;
    }

    @Test
    void lookupByReadOnlyReturnsOnlyReadEventsNewestFirst() throws Exception {
        List<Event> events = lookup(LookupAttributeKey.READ_ONLY, "true");
        assertFalse(events.isEmpty());
        Instant previous = Instant.MAX;
        for (Event event : events) {
            assertTrue(mapper.readTree(event.cloudTrailEvent()).path("readOnly").asBoolean());
            assertFalse(event.eventTime().isAfter(previous));
            previous = event.eventTime();
        }
    }

    @Test
    void thirdLookupWithinASecondIsThrottled() throws Exception {
        Thread.sleep(1100);
        try (CloudTrailClient cloudTrail = cloudTrail(AwsBasicCredentials.create("test", "test"), false)) {
            cloudTrail.lookupEvents(r -> r.maxResults(1));
            cloudTrail.lookupEvents(r -> r.maxResults(1));
            CloudTrailException thrown = assertThrows(CloudTrailException.class,
                    () -> cloudTrail.lookupEvents(r -> r.maxResults(1)));
            assertEquals("ThrottlingException", thrown.awsErrorDetails().errorCode());
        }
    }

    @Test
    void ecsTaskRoleAndLambdaExecutionRoleAssumptionsAreServiceEvents() throws Exception {
        String roleName = "svc-" + suffix();
        String roleArn;
        try (IamClient iam = iam(AwsBasicCredentials.create("test", "test"))) {
            roleArn = iam.createRole(r -> r.roleName(roleName).assumeRolePolicyDocument("""
                    {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                      "Principal":{"Service":["ecs-tasks.amazonaws.com","lambda.amazonaws.com"]},
                      "Action":"sts:AssumeRole"}]}""")).role().arn();
        }
        String taskId = suffix();
        assertTrue(ecsTaskRoleCredentials.issue("arn:aws:ecs:us-east-1:" + ACCOUNT + ":task/c/" + taskId, roleArn,
                ACCOUNT, Instant.now()).isPresent());
        JsonNode ecs = serviceAssumeRole(roleArn, "ecs-tasks.amazonaws.com");
        assertEquals(taskId, ecs.path("requestParameters").path("roleSessionName").asText());
        assertEquals("ecs-tasks.amazonaws.com", ecs.path("sourceIPAddress").asText());
        assertEquals("ecs-tasks.amazonaws.com", ecs.path("userAgent").asText());
        assertEquals("HIDDEN_DUE_TO_SECURITY_REASONS",
                ecs.path("responseElements").path("credentials").path("sessionToken").asText());
        assertEquals(roleArn, ecs.path("resources").path(0).path("ARN").asText());
        assertEquals("AWS::IAM::Role", ecs.path("resources").path(0).path("type").asText());
        ecsTaskRoleCredentials.revoke("arn:aws:ecs:us-east-1:" + ACCOUNT + ":task/c/" + taskId);

        LambdaFunction function = new LambdaFunction();
        function.setFunctionName("fn-" + suffix());
        function.setAccountId(ACCOUNT);
        function.setFunctionArn("arn:aws:lambda:us-east-1:" + ACCOUNT + ":function:" + function.getFunctionName());
        function.setRole(roleArn);
        lambdaExecutionRoleCredentials.forFunction(function).ifPresent(credentials ->
                lambdaExecutionRoleCredentials.unregister(ACCOUNT, credentials.accessKeyId()));
        JsonNode lambda = serviceAssumeRole(roleArn, "lambda.amazonaws.com");
        assertEquals(function.getFunctionName(), lambda.path("requestParameters").path("roleSessionName").asText());
    }

    private JsonNode serviceAssumeRole(String roleArn, String principal) throws Exception {
        for (Event event : lookup(LookupAttributeKey.RESOURCE_NAME, roleArn)) {
            JsonNode record = mapper.readTree(event.cloudTrailEvent());
            JsonNode identity = record.path("userIdentity");
            if ("AWSService".equals(identity.path("type").asText()) && principal.equals(identity.path("invokedBy").asText())) {
                return record;
            }
        }
        throw new AssertionError("no AssumeRole by " + principal + " for " + roleArn);
    }

    private JsonNode latest(LookupAttributeKey key, String value, String eventName) throws Exception {
        for (Event event : lookup(key, value)) {
            if (eventName.equals(event.eventName())) {
                JsonNode record = mapper.readTree(event.cloudTrailEvent());
                assertNotNull(record.path("requestID").asText(null));
                return record;
            }
        }
        throw new AssertionError("no " + eventName + " event for " + key + "=" + value);
    }

    private List<Event> lookup(LookupAttributeKey key, String value) {
        try (CloudTrailClient cloudTrail = cloudTrail(AwsBasicCredentials.create("test", "test"), true)) {
            return cloudTrail.lookupEvents(r -> r.lookupAttributes(a -> a.attributeKey(key).attributeValue(value)))
                    .events();
        }
    }

    private record User(String name, AwsCredentials keys) {
    }

    private User adminUser() {
        String name = "admin-" + suffix();
        return new User(name, createUser(name, ALLOW_ALL));
    }

    private AwsCredentials createUser(String name, String policy) {
        try (IamClient iam = iam(AwsBasicCredentials.create("test", "test"))) {
            iam.createUser(r -> r.userName(name));
            if (policy != null) {
                iam.putUserPolicy(r -> r.userName(name).policyName("all").policyDocument(policy));
            }
            AccessKey key = iam.createAccessKey(r -> r.userName(name)).accessKey();
            return AwsBasicCredentials.create(key.accessKeyId(), key.secretAccessKey());
        }
    }

    private IamClient iam(AwsCredentials credentials) {
        return IamClient.builder().endpointOverride(endpoint).region(Region.AWS_GLOBAL)
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
                .httpClient(UrlConnectionHttpClient.create()).build();
    }

    private CloudTrailClient cloudTrail(AwsCredentials credentials, boolean retry) {
        return CloudTrailClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
                .overrideConfiguration(o -> {
                    if (!retry) {
                        o.retryStrategy(AwsRetryStrategy.doNotRetry());
                    }
                })
                .httpClient(UrlConnectionHttpClient.create()).build();
    }

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
