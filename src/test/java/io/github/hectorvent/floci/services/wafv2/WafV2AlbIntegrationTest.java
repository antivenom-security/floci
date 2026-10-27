package io.github.hectorvent.floci.services.wafv2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.cloudwatch.logs.model.LogEvent;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.elbv2.ElbV2AccessLogWriter;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2Client;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ActionTypeEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.LoadBalancerAttribute;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.LoadBalancerTypeEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ProtocolEnum;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.TargetTypeEnum;
import software.amazon.awssdk.services.wafv2.Wafv2Client;
import software.amazon.awssdk.services.wafv2.model.ActionCondition;
import software.amazon.awssdk.services.wafv2.model.ActionValue;
import software.amazon.awssdk.services.wafv2.model.AllowAction;
import software.amazon.awssdk.services.wafv2.model.BlockAction;
import software.amazon.awssdk.services.wafv2.model.ByteMatchStatement;
import software.amazon.awssdk.services.wafv2.model.ComparisonOperator;
import software.amazon.awssdk.services.wafv2.model.Condition;
import software.amazon.awssdk.services.wafv2.model.CountAction;
import software.amazon.awssdk.services.wafv2.model.CustomHTTPHeader;
import software.amazon.awssdk.services.wafv2.model.CustomResponse;
import software.amazon.awssdk.services.wafv2.model.CustomResponseBody;
import software.amazon.awssdk.services.wafv2.model.DefaultAction;
import software.amazon.awssdk.services.wafv2.model.FieldToMatch;
import software.amazon.awssdk.services.wafv2.model.Filter;
import software.amazon.awssdk.services.wafv2.model.FilterBehavior;
import software.amazon.awssdk.services.wafv2.model.FilterRequirement;
import software.amazon.awssdk.services.wafv2.model.IPAddressVersion;
import software.amazon.awssdk.services.wafv2.model.LabelNameCondition;
import software.amazon.awssdk.services.wafv2.model.LoggingFilter;
import software.amazon.awssdk.services.wafv2.model.ManagedRuleGroupStatement;
import software.amazon.awssdk.services.wafv2.model.Method;
import software.amazon.awssdk.services.wafv2.model.NoneAction;
import software.amazon.awssdk.services.wafv2.model.OverrideAction;
import software.amazon.awssdk.services.wafv2.model.PositionalConstraint;
import software.amazon.awssdk.services.wafv2.model.QueryString;
import software.amazon.awssdk.services.wafv2.model.RateBasedStatement;
import software.amazon.awssdk.services.wafv2.model.RateBasedStatementAggregateKeyType;
import software.amazon.awssdk.services.wafv2.model.RegexMatchStatement;
import software.amazon.awssdk.services.wafv2.model.ResponseContentType;
import software.amazon.awssdk.services.wafv2.model.Rule;
import software.amazon.awssdk.services.wafv2.model.RuleAction;
import software.amazon.awssdk.services.wafv2.model.Scope;
import software.amazon.awssdk.services.wafv2.model.SingleHeader;
import software.amazon.awssdk.services.wafv2.model.SizeConstraintStatement;
import software.amazon.awssdk.services.wafv2.model.Statement;
import software.amazon.awssdk.services.wafv2.model.TextTransformation;
import software.amazon.awssdk.services.wafv2.model.TextTransformationType;
import software.amazon.awssdk.services.wafv2.model.UriPath;
import software.amazon.awssdk.services.wafv2.model.VisibilityConfig;

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
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A web ACL associated with an Application Load Balancer, evaluated on live requests through the
 * data plane, with its traffic logs read back from S3 and CloudWatch Logs.
 */
@QuarkusTest
@TestProfile(WafV2AlbIntegrationTest.Profile.class)
class WafV2AlbIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.elbv2.mock", "false");
        }
    }

    @TestHTTPResource("/")
    URI endpoint;

    @Inject
    S3Service s3;

    @Inject
    CloudWatchLogsService logs;

    @Inject
    WafV2LogWriter wafLogs;

    @Inject
    ElbV2AccessLogWriter accessLogs;

    @Inject
    Vertx vertx;

    private final HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    private ElasticLoadBalancingV2Client elb;
    private Wafv2Client waf;
    private HttpServer backend;
    private String suffix;
    private String lbArn;
    private int port;

    @BeforeEach
    void startLoadBalancer() throws Exception {
        suffix = UUID.randomUUID().toString().substring(0, 8);
        elb = ElasticLoadBalancingV2Client.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(credentials()).httpClient(UrlConnectionHttpClient.create()).build();
        waf = Wafv2Client.builder().endpointOverride(endpoint).region(Region.US_EAST_1)
                .credentialsProvider(credentials()).httpClient(UrlConnectionHttpClient.create()).build();
        backend = vertx.createHttpServer().requestHandler(request -> request.response().end("from-target"))
                .listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().get(2, TimeUnit.SECONDS);
        int backendPort = backend.actualPort();
        port = FreePorts.anyInterfacePort();
        lbArn = elb.createLoadBalancer(r -> r.name("waf-" + suffix).type(LoadBalancerTypeEnum.APPLICATION)
                        .subnets(Ec2Service.defaultSubnetId(REGION, "a"), Ec2Service.defaultSubnetId(REGION, "b")))
                .loadBalancers().getFirst().loadBalancerArn();
        String tgArn = elb.createTargetGroup(r -> r.name("waf-tg-" + suffix).protocol(ProtocolEnum.HTTP)
                        .port(backendPort).targetType(TargetTypeEnum.IP).healthCheckEnabled(false))
                .targetGroups().getFirst().targetGroupArn();
        elb.registerTargets(r -> r.targetGroupArn(tgArn).targets(t -> t.id("127.0.0.1").port(backendPort)));
        elb.createListener(r -> r.loadBalancerArn(lbArn).protocol(ProtocolEnum.HTTP).port(port)
                .defaultActions(a -> a.type(ActionTypeEnum.FORWARD).targetGroupArn(tgArn)));
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertEquals(200, send("GET", "/", Map.of())
                .statusCode()));
    }

    @AfterEach
    void stop() throws Exception {
        elb.close();
        waf.close();
        backend.close().toCompletionStage().toCompletableFuture().get(2, TimeUnit.SECONDS);
    }

    @Test
    void evaluatesEachStatementTypeAndActionAndLogsToS3() throws Exception {
        String bucket = "aws-waf-logs-alb-" + suffix;
        s3.createBucket(bucket, REGION);
        String accessLogBucket = "alb-access-" + suffix;
        s3.createBucket(accessLogBucket, REGION);
        elb.modifyLoadBalancerAttributes(r -> r.loadBalancerArn(lbArn).attributes(
                LoadBalancerAttribute.builder().key("access_logs.s3.enabled").value("true").build(),
                LoadBalancerAttribute.builder().key("access_logs.s3.bucket").value(accessLogBucket).build()));
        String ipSetArn = waf.createIPSet(r -> r.name("local-" + suffix).scope(Scope.REGIONAL)
                .ipAddressVersion(IPAddressVersion.IPV4).addresses("127.0.0.0/8")).summary().arn();
        String aclName = "acl-" + suffix;
        String aclArn = waf.createWebACL(r -> r.name(aclName).scope(Scope.REGIONAL)
                .defaultAction(DefaultAction.builder().allow(AllowAction.builder().build()).build())
                .visibilityConfig(visibility("acl"))
                .customResponseBodies(Map.of("slow-down", CustomResponseBody.builder()
                        .contentType(ResponseContentType.APPLICATION_JSON).content("{\"error\":\"slow down\"}").build()))
                .rules(
                        rule("ip-block", 1, Statement.builder().andStatement(a -> a.statements(
                                Statement.builder().ipSetReferenceStatement(i -> i.arn(ipSetArn)).build(),
                                byteMatch(uriPath(), "/ip", PositionalConstraint.EXACTLY))).build(), block()),
                        rule("probe-count", 2, byteMatch(header("x-probe"), "scan", PositionalConstraint.CONTAINS,
                                TextTransformationType.LOWERCASE), count()).toBuilder()
                                .ruleLabels(l -> l.name("probe")).build(),
                        rule("sqli-regex", 3, Statement.builder().regexMatchStatement(RegexMatchStatement.builder()
                                .regexString("id=[0-9]+'").fieldToMatch(FieldToMatch.builder()
                                        .queryString(QueryString.builder().build()).build())
                                .textTransformations(transformation(TextTransformationType.URL_DECODE)).build())
                                .build(), RuleAction.builder().block(BlockAction.builder().customResponse(
                                CustomResponse.builder().responseCode(429).customResponseBodyKey("slow-down")
                                        .responseHeaders(CustomHTTPHeader.builder().name("x-waf-reason")
                                                .value("sqli").build()).build()).build()).build()),
                        rule("big-header", 4, Statement.builder().sizeConstraintStatement(
                                SizeConstraintStatement.builder().fieldToMatch(header("x-big"))
                                        .comparisonOperator(ComparisonOperator.GT).size(10L)
                                        .textTransformations(transformation(TextTransformationType.NONE)).build())
                                .build(), block()),
                        rule("delete-allow", 5, byteMatch(FieldToMatch.builder().method(Method.builder().build())
                                .build(), "DELETE", PositionalConstraint.EXACTLY), allow()),
                        rule("script-block", 6, Statement.builder().andStatement(a -> a.statements(
                                Statement.builder().notStatement(n -> n.statement(
                                        byteMatch(uriPath(), "/public/", PositionalConstraint.STARTS_WITH))).build(),
                                Statement.builder().orStatement(o -> o.statements(
                                        byteMatch(uriPath(), ".php", PositionalConstraint.ENDS_WITH),
                                        byteMatch(uriPath(), "admin", PositionalConstraint.CONTAINS_WORD))).build()))
                                .build(), block()),
                        Rule.builder().name("managed").priority(7).statement(s -> s.managedRuleGroupStatement(
                                ManagedRuleGroupStatement.builder().vendorName("AWS")
                                        .name("AWSManagedRulesCommonRuleSet").build()))
                                .overrideAction(OverrideAction.builder().none(NoneAction.builder().build()).build())
                                .visibilityConfig(visibility("managed")).build(),
                        rule("delete-block", 8, byteMatch(FieldToMatch.builder().method(Method.builder().build())
                                .build(), "DELETE", PositionalConstraint.EXACTLY), block())))
                .summary().arn();
        waf.associateWebACL(r -> r.webACLArn(aclArn).resourceArn(lbArn));
        waf.putLoggingConfiguration(r -> r.loggingConfiguration(c -> c.resourceArn(aclArn)
                .logDestinationConfigs("arn:aws:s3:::" + bucket + "/edge")));

        HttpResponse<String> ip = send("GET", "/ip", Map.of());
        assertEquals(403, ip.statusCode());
        assertEquals("<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n"
                + "<center><h1>403 Forbidden</h1></center>\r\n</body>\r\n</html>\r\n", ip.body());
        assertEquals("text/html", ip.headers().firstValue("Content-Type").orElseThrow());
        assertEquals(200, send("GET", "/probe", Map.of("x-probe", "SCANNER")).statusCode());
        HttpResponse<String> sqli = send("GET", "/q?id=1%27", Map.of());
        assertEquals(429, sqli.statusCode());
        assertEquals("{\"error\":\"slow down\"}", sqli.body());
        assertEquals("sqli", sqli.headers().firstValue("x-waf-reason").orElseThrow());
        assertEquals("application/json", sqli.headers().firstValue("Content-Type").orElseThrow());
        assertEquals(200, send("GET", "/q?id=1", Map.of()).statusCode());
        assertEquals(403, send("GET", "/big", Map.of("x-big", "12345678901")).statusCode());
        assertEquals(200, send("GET", "/small", Map.of("x-big", "1234567890")).statusCode());
        assertEquals(200, send("DELETE", "/delete.php", Map.of()).statusCode());
        assertEquals(403, send("GET", "/index.php", Map.of()).statusCode());
        assertEquals(403, send("GET", "/my-admin/", Map.of()).statusCode());
        assertEquals(200, send("GET", "/administrator", Map.of()).statusCode());
        assertEquals(200, send("GET", "/public/index.php", Map.of()).statusCode());
        HttpResponse<String> allowed = send("GET", "/fine?a=b", Map.of());
        assertEquals("from-target", allowed.body());

        String prefix = "edge/AWSLogs/" + ACCOUNT + "/WAFLogs/" + REGION + "/" + aclName + "/";
        Map<String, JsonNode> records = new HashMap<>();
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            wafLogs.flushNow();
            records.clear();
            for (JsonNode record : s3Records(bucket, prefix, aclName)) {
                records.put(record.path("httpRequest").path("httpMethod").asText() + " "
                        + record.path("httpRequest").path("uri").asText()
                        + (record.path("httpRequest").path("args").asText().isEmpty() ? ""
                        : "?" + record.path("httpRequest").path("args").asText()), record);
            }
            assertTrue(records.containsKey("GET /fine?a=b"), records.keySet().toString());
        });

        assertTerminated(records.get("GET /ip"), "ip-block", "BLOCK");
        assertTerminated(records.get("GET /probe"), "Default_Action", "ALLOW");
        JsonNode probe = records.get("GET /probe");
        assertEquals("probe-count", probe.path("nonTerminatingMatchingRules").get(0).path("ruleId").asText());
        assertEquals("COUNT", probe.path("nonTerminatingMatchingRules").get(0).path("action").asText());
        assertEquals("awswaf:" + ACCOUNT + ":webacl:" + aclName + ":probe",
                probe.path("labels").get(0).path("name").asText());
        assertTerminated(records.get("GET /q?id=1%27"), "sqli-regex", "BLOCK");
        assertEquals(429, records.get("GET /q?id=1%27").path("responseCodeSent").asInt());
        assertTerminated(records.get("GET /q?id=1"), "Default_Action", "ALLOW");
        assertTerminated(records.get("GET /big"), "big-header", "BLOCK");
        assertTerminated(records.get("GET /small"), "Default_Action", "ALLOW");
        assertTerminated(records.get("DELETE /delete.php"), "delete-allow", "ALLOW");
        assertTerminated(records.get("GET /index.php"), "script-block", "BLOCK");
        assertTerminated(records.get("GET /my-admin/"), "script-block", "BLOCK");
        assertTerminated(records.get("GET /administrator"), "Default_Action", "ALLOW");
        assertTerminated(records.get("GET /public/index.php"), "Default_Action", "ALLOW");

        JsonNode fine = records.get("GET /fine?a=b");
        List<String> keys = new ArrayList<>();
        fine.fieldNames().forEachRemaining(keys::add);
        assertEquals(List.of("timestamp", "formatVersion", "webaclId", "terminatingRuleId", "terminatingRuleType",
                "action", "terminatingRuleMatchDetails", "httpSourceName", "httpSourceId", "ruleGroupList",
                "rateBasedRuleList", "nonTerminatingMatchingRules", "requestHeadersInserted", "responseCodeSent",
                "httpRequest"), keys);
        assertEquals(1, fine.path("formatVersion").asInt());
        assertEquals(aclArn, fine.path("webaclId").asText());
        assertEquals("REGULAR", fine.path("terminatingRuleType").asText());
        assertEquals("ALB", fine.path("httpSourceName").asText());
        assertEquals(ACCOUNT + "-app/waf-" + suffix + "/" + lbArn.substring(lbArn.lastIndexOf('/') + 1),
                fine.path("httpSourceId").asText());
        assertTrue(fine.path("requestHeadersInserted").isNull());
        assertTrue(fine.path("responseCodeSent").isNull());
        JsonNode http = fine.path("httpRequest");
        List<String> httpKeys = new ArrayList<>();
        http.fieldNames().forEachRemaining(httpKeys::add);
        assertEquals(List.of("clientIp", "country", "headers", "uri", "args", "httpVersion", "httpMethod",
                "requestId"), httpKeys);
        assertEquals("127.0.0.1", http.path("clientIp").asText());
        assertEquals("-", http.path("country").asText());
        assertEquals("/fine", http.path("uri").asText());
        assertEquals("a=b", http.path("args").asText());
        assertEquals("HTTP/1.1", http.path("httpVersion").asText());
        assertTrue(http.path("requestId").asText().matches("1-[0-9a-f]{8}-[0-9a-f]{24}"), http.toString());
        assertTrue(headerValue(http, "User-Agent").startsWith("floci-waf-test"), http.toString());

        Map<String, String> actions = new HashMap<>();
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            accessLogs.flushNow();
            actions.clear();
            for (S3Object listed : s3.listObjects(accessLogBucket, "AWSLogs/" + ACCOUNT + "/elasticloadbalancing/", null,
                    1000)) {
                for (String line : gunzip(s3.getObject(accessLogBucket, listed.getKey()).getData()).split("\n")) {
                    Matcher m = Pattern.compile("^\\S+ \\S+ \\S+ \\S+ (\\S+) \\S+ \\S+ \\S+ (\\d+) "
                            + ".*\"GET http://[^ ]+(/ip|/fine\\?a=b) HTTP/1.1\".*\"(waf[^\"]*)\"").matcher(line);
                    if (m.find()) {
                        actions.put(m.group(3), m.group(2) + " " + m.group(1) + " " + m.group(4));
                    }
                }
            }
            assertEquals(2, actions.size(), actions.toString());
        });
        assertEquals("403 - waf", actions.get("/ip"));
        assertTrue(actions.get("/fine?a=b").matches("200 127\\.0\\.0\\.1:\\d+ waf,forward"), actions.toString());

        waf.disassociateWebACL(r -> r.resourceArn(lbArn));
        assertEquals(200, send("GET", "/ip", Map.of()).statusCode());
    }

    @Test
    void rateBasedRuleBlocksPastTheLimitPerSourceIpAndLogsToCloudWatch() throws Exception {
        String group = "aws-waf-logs-rate-" + suffix;
        logs.createLogGroup(group, null, Map.of(), REGION);
        String aclName = "rate-" + suffix;
        String aclArn = waf.createWebACL(r -> r.name(aclName).scope(Scope.REGIONAL)
                .defaultAction(DefaultAction.builder().allow(AllowAction.builder().build()).build())
                .visibilityConfig(visibility("rate"))
                .rules(rule("api-rate", 1, Statement.builder().rateBasedStatement(RateBasedStatement.builder()
                        .limit(10L).evaluationWindowSec(60L).aggregateKeyType(RateBasedStatementAggregateKeyType.IP)
                        .scopeDownStatement(byteMatch(uriPath(), "/api", PositionalConstraint.STARTS_WITH)).build())
                        .build(), block())))
                .summary().arn();
        waf.associateWebACL(r -> r.webACLArn(aclArn).resourceArn(lbArn));
        waf.putLoggingConfiguration(r -> r.loggingConfiguration(c -> c.resourceArn(aclArn)
                .logDestinationConfigs("arn:aws:logs:" + REGION + ":" + ACCOUNT + ":log-group:" + group)));

        for (int i = 0; i < 10; i++) {
            assertEquals(200, send("GET", "/api/items", Map.of()).statusCode());
        }
        assertEquals(403, send("GET", "/api/items", Map.of()).statusCode());
        assertEquals(200, send("GET", "/home", Map.of()).statusCode());

        String stream = REGION + "_" + aclName + "_0";
        List<JsonNode> records = new ArrayList<>();
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            wafLogs.flushNow();
            records.clear();
            for (LogEvent event : logs.getLogEvents(group, stream, null, null, 100, true, null, REGION).events()) {
                records.add(MAPPER.readTree(event.getMessage()));
            }
            assertEquals(12, records.size());
        });
        List<JsonNode> blocked = records.stream().filter(record -> "BLOCK".equals(record.path("action").asText()))
                .toList();
        assertEquals(1, blocked.size(), records.toString());
        assertTerminated(blocked.getFirst(), "api-rate", "BLOCK");
        assertEquals("RATE_BASED", blocked.getFirst().path("terminatingRuleType").asText());
        JsonNode rate = blocked.getFirst().path("rateBasedRuleList").get(0);
        assertEquals("api-rate", rate.path("rateBasedRuleId").asText());
        assertEquals("api-rate", rate.path("rateBasedRuleName").asText());
        assertEquals("IP", rate.path("limitKey").asText());
        assertEquals("127.0.0.1", rate.path("limitValue").asText());
        assertEquals(10, rate.path("maxRateAllowed").asInt());
        assertEquals("60", rate.path("evaluationWindowSec").asText());
        JsonNode home = records.stream().filter(record -> "/home".equals(record.path("httpRequest").path("uri")
                .asText())).findFirst().orElseThrow();
        assertTerminated(home, "Default_Action", "ALLOW");
        assertEquals(1, home.path("rateBasedRuleList").size());
    }

    @Test
    void loggingFilterAndRedactedFieldsShapeTheRecords() throws Exception {
        String bucket = "aws-waf-logs-filter-" + suffix;
        s3.createBucket(bucket, REGION);
        String aclName = "filter-" + suffix;
        String watched = "awswaf:" + ACCOUNT + ":webacl:" + aclName + ":watched";
        String aclArn = waf.createWebACL(r -> r.name(aclName).scope(Scope.REGIONAL)
                .defaultAction(DefaultAction.builder().block(BlockAction.builder().build()).build())
                .visibilityConfig(visibility("filter"))
                .rules(rule("watch", 1, byteMatch(header("x-watch"), "1", PositionalConstraint.EXACTLY), count())
                                .toBuilder().ruleLabels(l -> l.name("watched")).build(),
                        rule("open", 2, byteMatch(uriPath(), "/open", PositionalConstraint.STARTS_WITH), allow())))
                .summary().arn();
        waf.associateWebACL(r -> r.webACLArn(aclArn).resourceArn(lbArn));
        waf.putLoggingConfiguration(r -> r.loggingConfiguration(c -> c.resourceArn(aclArn)
                .logDestinationConfigs("arn:aws:s3:::" + bucket)
                .redactedFields(uriPath(), FieldToMatch.builder().queryString(QueryString.builder().build()).build(),
                        FieldToMatch.builder().method(Method.builder().build()).build(), header("x-secret"))
                .loggingFilter(LoggingFilter.builder().defaultBehavior(FilterBehavior.DROP).filters(
                        Filter.builder().behavior(FilterBehavior.KEEP).requirement(FilterRequirement.MEETS_ALL)
                                .conditions(Condition.builder().actionCondition(ActionCondition.builder()
                                                .action(ActionValue.COUNT).build()).build(),
                                        Condition.builder().labelNameCondition(LabelNameCondition.builder()
                                                .labelName(watched).build()).build()).build(),
                        Filter.builder().behavior(FilterBehavior.KEEP).requirement(FilterRequirement.MEETS_ANY)
                                .conditions(Condition.builder().actionCondition(ActionCondition.builder()
                                        .action(ActionValue.BLOCK).build()).build()).build()).build())));

        assertEquals(403, send("GET", "/closed?token=abc", Map.of("x-secret", "hunter2")).statusCode());
        assertEquals(200, send("GET", "/open/door", Map.of()).statusCode());
        assertEquals(200, send("GET", "/open/door", Map.of("x-watch", "1", "x-secret", "hunter2")).statusCode());

        String prefix = "AWSLogs/" + ACCOUNT + "/WAFLogs/" + REGION + "/" + aclName + "/";
        List<JsonNode> records = new ArrayList<>();
        await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
            wafLogs.flushNow();
            records.clear();
            records.addAll(s3Records(bucket, prefix, aclName));
            assertEquals(2, records.size(), records.toString());
        });
        JsonNode closed = records.stream().filter(record -> "BLOCK".equals(record.path("action").asText()))
                .findFirst().orElseThrow();
        assertTerminated(closed, "Default_Action", "BLOCK");
        assertEquals("REDACTED", closed.path("httpRequest").path("uri").asText());
        assertEquals("REDACTED", closed.path("httpRequest").path("args").asText());
        assertEquals("REDACTED", closed.path("httpRequest").path("httpMethod").asText());
        assertEquals("REDACTED", headerValue(closed.path("httpRequest"), "x-secret"));
        assertFalse(closed.has("labels"));
        JsonNode open = records.stream().filter(record -> "ALLOW".equals(record.path("action").asText()))
                .findFirst().orElseThrow();
        assertTerminated(open, "open", "ALLOW");
        assertEquals("watch", open.path("nonTerminatingMatchingRules").get(0).path("ruleId").asText());
        assertEquals(watched, open.path("labels").get(0).path("name").asText());
        assertEquals("REDACTED", headerValue(open.path("httpRequest"), "x-secret"));
        assertEquals("1", headerValue(open.path("httpRequest"), "x-watch"));
    }

    private static void assertTerminated(JsonNode record, String ruleId, String action) {
        assertEquals(ruleId, record.path("terminatingRuleId").asText(), record.toString());
        assertEquals(action, record.path("action").asText(), record.toString());
    }

    private static String headerValue(JsonNode http, String name) {
        for (JsonNode header : http.path("headers")) {
            if (name.equalsIgnoreCase(header.path("name").asText())) {
                return header.path("value").asText();
            }
        }
        throw new AssertionError("no header " + name + " in " + http);
    }

    private List<JsonNode> s3Records(String bucket, String prefix, String aclName) throws IOException {
        List<JsonNode> records = new ArrayList<>();
        for (S3Object listed : s3.listObjects(bucket, prefix, null, 1000)) {
            assertTrue(listed.getKey().matches(Pattern.quote(prefix) + "\\d{4}/\\d{2}/\\d{2}/\\d{2}/\\d{2}/" + ACCOUNT
                    + "_waflogs_" + REGION + "_" + aclName + "_\\d{8}T\\d{4}Z_[0-9a-f]{8}\\.log\\.gz"), listed.getKey());
            for (String line : gunzip(s3.getObject(bucket, listed.getKey()).getData()).split("\n")) {
                records.add(MAPPER.readTree(line));
            }
        }
        return records;
    }

    private static String gunzip(byte[] data) throws IOException {
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data))) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private HttpResponse<String> send(String method, String path, Map<String, String> headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .method(method, HttpRequest.BodyPublishers.noBody()).header("User-Agent", "floci-waf-test/1.0");
        headers.forEach(request::header);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static Rule rule(String name, int priority, Statement statement, RuleAction action) {
        return Rule.builder().name(name).priority(priority).statement(statement).action(action)
                .visibilityConfig(visibility(name)).build();
    }

    private static Statement byteMatch(FieldToMatch field, String search, PositionalConstraint constraint,
                                       TextTransformationType... transformations) {
        List<TextTransformation> list = new ArrayList<>();
        for (TextTransformationType type : transformations.length == 0
                ? new TextTransformationType[]{TextTransformationType.NONE} : transformations) {
            list.add(TextTransformation.builder().priority(list.size()).type(type).build());
        }
        return Statement.builder().byteMatchStatement(ByteMatchStatement.builder().fieldToMatch(field)
                .searchString(SdkBytes.fromUtf8String(search)).positionalConstraint(constraint)
                .textTransformations(list).build()).build();
    }

    private static TextTransformation transformation(TextTransformationType type) {
        return TextTransformation.builder().priority(0).type(type).build();
    }

    private static FieldToMatch uriPath() {
        return FieldToMatch.builder().uriPath(UriPath.builder().build()).build();
    }

    private static FieldToMatch header(String name) {
        return FieldToMatch.builder().singleHeader(SingleHeader.builder().name(name).build()).build();
    }

    private static RuleAction block() {
        return RuleAction.builder().block(BlockAction.builder().build()).build();
    }

    private static RuleAction allow() {
        return RuleAction.builder().allow(AllowAction.builder().build()).build();
    }

    private static RuleAction count() {
        return RuleAction.builder().count(CountAction.builder().build()).build();
    }

    private static VisibilityConfig visibility(String metric) {
        return VisibilityConfig.builder().sampledRequestsEnabled(true).cloudWatchMetricsEnabled(true)
                .metricName(metric).build();
    }

    private static StaticCredentialsProvider credentials() {
        return StaticCredentialsProvider.create(AwsBasicCredentials.create("test", "test"));
    }
}
