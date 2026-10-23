package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.testing.CfnStackWaits;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.client.builder.AwsClientBuilder;
import software.amazon.awssdk.awscore.client.builder.AwsSyncClientBuilder;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.eventbridge.EventBridgeClient;
import software.amazon.awssdk.services.eventbridge.model.RuleState;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;

import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Management events a logging trail covers reach the default bus as CloudTrail sends them: an IAM
 * write to an {@code ENABLED} rule, a read-only Secrets Manager call only to a rule in state
 * {@code ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS}, and nothing without a trail. Each test runs
 * in an account of its own, so other tests' trails never cover its events.
 */
@QuarkusTest
@Timeout(90)
class CloudTrailEventBridgeIntegrationTest {

    private static final String IAM_PATTERN =
            "{\"source\":[\"aws.iam\"],\"detail-type\":[\"AWS API Call via CloudTrail\"]}";

    private final ObjectMapper mapper = new ObjectMapper();

    @TestHTTPResource("/")
    URI endpoint;

    @Test
    void createUserReachesAnIamApiCallRule() throws Exception {
        Account account = new Account();
        account.startTrail();
        String queueUrl = account.ruleToQueue("iam-calls", IAM_PATTERN, RuleState.ENABLED);
        String user = "eb-" + UUID.randomUUID().toString().substring(0, 8);
        try (IamClient iam = account.client(IamClient.builder(), Region.AWS_GLOBAL)) {
            iam.createUser(r -> r.userName(user));
        }

        JsonNode event = mapper.readTree(account.receive(queueUrl, 20).get(0).body());
        assertEquals("0", event.path("version").asText());
        assertEquals("aws.iam", event.path("source").asText());
        assertEquals("AWS API Call via CloudTrail", event.path("detail-type").asText());
        assertEquals(account.id, event.path("account").asText());
        assertEquals("us-east-1", event.path("region").asText());
        assertTrue(event.path("resources").isArray() && event.path("resources").isEmpty());
        assertEquals("iam.amazonaws.com", event.path("detail").path("eventSource").asText());
        assertEquals("CreateUser", event.path("detail").path("eventName").asText());
        assertEquals(user, event.path("detail").path("requestParameters").path("userName").asText());
        assertEquals("AwsApiCall", event.path("detail").path("eventType").asText());
    }

    @Test
    void getSecretValueReachesOnlyARuleWithAllManagementEvents() throws Exception {
        Account account = new Account();
        account.startTrail();
        String pattern = "{\"source\":[\"aws.secretsmanager\"],\"detail\":{\"eventName\":[\"GetSecretValue\"]}}";
        String enabled = account.ruleToQueue("writes-only", pattern, RuleState.ENABLED);
        String all = account.ruleToQueue("all-management", pattern,
                RuleState.ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS);
        try (EventBridgeClient events = account.client(EventBridgeClient.builder(), Region.US_EAST_1)) {
            assertEquals(RuleState.ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS,
                    events.describeRule(r -> r.name("all-management")).state());
            assertEquals(RuleState.ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS,
                    events.listRules(r -> r.namePrefix("all-management")).rules().get(0).state());
        }
        String name = "eb-secret-" + UUID.randomUUID().toString().substring(0, 8);
        try (SecretsManagerClient secrets = account.client(SecretsManagerClient.builder(), Region.US_EAST_1)) {
            secrets.createSecret(r -> r.name(name).secretString("value"));
            secrets.getSecretValue(r -> r.secretId(name));
        }

        JsonNode event = mapper.readTree(account.receive(all, 20).get(0).body());
        assertEquals("GetSecretValue", event.path("detail").path("eventName").asText());
        assertTrue(event.path("detail").path("readOnly").asBoolean());
        assertTrue(account.receive(enabled, 2).isEmpty());
    }

    @Test
    void withoutATrailNothingIsDelivered() {
        Account account = new Account();
        String queueUrl = account.ruleToQueue("no-trail", IAM_PATTERN, RuleState.ENABLED);
        try (IamClient iam = account.client(IamClient.builder(), Region.AWS_GLOBAL)) {
            iam.createUser(r -> r.userName("eb-untrailed"));
        }

        assertTrue(account.receive(queueUrl, 3).isEmpty());
    }

    @Test
    void aCloudFormationRuleKeepsTheAllManagementEventsState() {
        String stack = "cfn-ct-rule-" + UUID.randomUUID().toString().substring(0, 8);
        given().contentType("application/x-www-form-urlencoded")
                .formParam("Action", "CreateStack")
                .formParam("StackName", stack)
                .formParam("TemplateBody", """
                        {"Resources": {"Rule": {"Type": "AWS::Events::Rule", "Properties": {
                          "Name": "%s", "EventPattern": {"source": ["aws.iam"]},
                          "State": "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"}}}}""".formatted(stack))
                .when().post("/").then().statusCode(200);
        assertEquals("CREATE_COMPLETE", CfnStackWaits.awaitTerminal(stack).status());

        try (EventBridgeClient events = EventBridgeClient.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test")))
                .httpClient(UrlConnectionHttpClient.create()).build()) {
            assertEquals(RuleState.ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS,
                    events.describeRule(r -> r.name(stack)).state());
        }
    }

    private final class Account {

        private final String id = String.valueOf(ThreadLocalRandom.current().nextLong(100_000_000_000L, 999_999_999_999L));

        <B extends AwsClientBuilder<B, C> & AwsSyncClientBuilder<B, C>, C> C client(B builder, Region region) {
            builder.httpClient(UrlConnectionHttpClient.create());
            return builder.endpointOverride(endpoint).region(region)
                    .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(id, "secret")))
                    .build();
        }

        void startTrail() {
            try (CloudTrailClient cloudTrail = client(CloudTrailClient.builder(), Region.US_EAST_1)) {
                cloudTrail.createTrail(r -> r.name("eb-trail").s3BucketName("eb-trail-" + id));
                cloudTrail.startLogging(r -> r.name("eb-trail"));
            }
        }

        String ruleToQueue(String rule, String pattern, RuleState state) {
            try (SqsClient sqs = client(SqsClient.builder(), Region.US_EAST_1);
                 EventBridgeClient events = client(EventBridgeClient.builder(), Region.US_EAST_1)) {
                String queueUrl = sqs.createQueue(r -> r.queueName(rule)).queueUrl();
                String queueArn = sqs.getQueueAttributes(r -> r.queueUrl(queueUrl)
                        .attributeNames(QueueAttributeName.QUEUE_ARN)).attributes().get(QueueAttributeName.QUEUE_ARN);
                events.putRule(r -> r.name(rule).eventPattern(pattern).state(state));
                events.putTargets(r -> r.rule(rule).targets(t -> t.id("queue").arn(queueArn)));
                return queueUrl;
            }
        }

        List<Message> receive(String queueUrl, int seconds) {
            try (SqsClient sqs = client(SqsClient.builder(), Region.US_EAST_1)) {
                return sqs.receiveMessage(r -> r.queueUrl(queueUrl).waitTimeSeconds(seconds)
                        .maxNumberOfMessages(10)).messages();
            }
        }
    }
}
