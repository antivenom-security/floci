package io.github.hectorvent.floci.services.wafv2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.RequestScopes;
import io.github.hectorvent.floci.services.ec2.SecurityGroupPolicy;
import io.github.hectorvent.floci.services.elbv2.ElbV2RequestInspector;
import io.github.hectorvent.floci.services.wafv2.model.IpSet;
import io.github.hectorvent.floci.services.wafv2.model.WebAcl;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpVersion;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Evaluates the web ACL associated with an Application Load Balancer on each request, in rule
 * priority order, and writes the AWS WAF log record when the ACL has a logging configuration.
 *
 * <p>Supported statements: {@code IPSetReferenceStatement}, {@code ByteMatchStatement},
 * {@code RegexMatchStatement} and {@code SizeConstraintStatement} on the URI path, query string, a
 * single header or the method, {@code RateBasedStatement} aggregated by source IP, and
 * {@code AndStatement}, {@code OrStatement} and {@code NotStatement}. Rule actions Allow, Block and
 * Count. A rule using anything else, such as {@code ManagedRuleGroupStatement}, never matches and is
 * reported once per web ACL.
 */
@ApplicationScoped
public class WafV2AlbInspector implements ElbV2RequestInspector {

    private static final Logger LOG = Logger.getLogger(WafV2AlbInspector.class);
    private static final String FORBIDDEN = "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n"
            + "<center><h1>403 Forbidden</h1></center>\r\n</body>\r\n</html>\r\n";
    private static final Set<String> ACTIONS = Set.of("Allow", "Block", "Count");

    private final WafV2Service service;
    private final WafV2LogWriter logWriter;
    private final ObjectMapper mapper;
    // shortcut: rate keys are never evicted, only their timestamps; fine for an emulator's client count.
    private final Map<String, Deque<Long>> rates = new ConcurrentHashMap<>();
    private final Set<String> warned = ConcurrentHashMap.newKeySet();

    @Inject
    public WafV2AlbInspector(WafV2Service service, WafV2LogWriter logWriter, ObjectMapper mapper) {
        this.service = service;
        this.logWriter = logWriter;
        this.mapper = mapper;
    }

    @Override
    public Response inspect(HttpServerRequest request, String region, String loadBalancerArn,
                            List<String> actionsExecuted) {
        String account = AwsArnUtils.parse(loadBalancerArn).accountId();
        return RequestScopes.callAs(account, region, () -> {
            WebAcl acl = service.getWebAclForResource(loadBalancerArn);
            if (acl == null) {
                return null;
            }
            Evaluation evaluation;
            try {
                evaluation = evaluate(acl, request);
            } catch (RuntimeException | JsonProcessingException e) {
                LOG.warnv(e, "Web ACL {0} could not inspect a request to {1}", acl.getArn(), loadBalancerArn);
                actionsExecuted.add("waf-failed");
                return null;
            }
            actionsExecuted.add("waf");
            try {
                String logging = service.findLoggingConfiguration(acl.getArn());
                if (logging != null) {
                    logWriter.record(acl, mapper.readTree(logging), record(acl, loadBalancerArn, request, evaluation));
                }
            } catch (RuntimeException | JsonProcessingException e) {
                LOG.warnv(e, "Web ACL {0} could not log a request to {1}", acl.getArn(), loadBalancerArn);
            }
            return evaluation.response;
        });
    }

    static final class Evaluation {
        final long timestamp = System.currentTimeMillis();
        final String clientIp;
        final List<String> labels = new ArrayList<>();
        final List<String> counted = new ArrayList<>();
        final List<ObjectNode> rateBased = new ArrayList<>();
        String terminatingRuleId = "Default_Action";
        String terminatingRuleType = "REGULAR";
        String action;
        Integer responseCodeSent;
        Response response;

        Evaluation(String clientIp) {
            this.clientIp = clientIp;
        }
    }

    private static final class Unsupported extends RuntimeException {
        Unsupported(String what) {
            super(what, null, false, false);
        }
    }

    Evaluation evaluate(WebAcl acl, HttpServerRequest request) throws JsonProcessingException {
        Evaluation evaluation = new Evaluation(request.remoteAddress().hostAddress());
        List<JsonNode> rules = new ArrayList<>();
        if (acl.getRules() != null) {
            mapper.readTree(acl.getRules()).forEach(rules::add);
        }
        rules.sort(Comparator.comparingLong(rule -> rule.path("Priority").asLong()));
        for (JsonNode rule : rules) {
            String name = rule.path("Name").asText();
            String kind = firstField(rule.path("Action"));
            boolean matched;
            try {
                if (!ACTIONS.contains(kind)) {
                    throw new Unsupported(rule.has("OverrideAction") ? firstField(rule.path("Statement"))
                            : kind + " action");
                }
                JsonNode statement = rule.path("Statement");
                matched = statement.has("RateBasedStatement")
                        ? rateLimited(acl, name, statement.path("RateBasedStatement"), request, evaluation)
                        : matches(statement, request, evaluation.clientIp);
            } catch (Unsupported unsupported) {
                if (warned.add(acl.getArn())) {
                    LOG.warnv("Web ACL {0} rule {1} uses {2}, which Floci does not evaluate; it never matches",
                            acl.getArn(), name, unsupported.getMessage());
                }
                continue;
            }
            if (!matched) {
                continue;
            }
            rule.path("RuleLabels").forEach(label ->
                    evaluation.labels.add(acl.getLabelNamespace() + label.path("Name").asText()));
            if ("Count".equals(kind)) {
                evaluation.counted.add(name);
                continue;
            }
            evaluation.terminatingRuleId = name;
            evaluation.terminatingRuleType = rule.path("Statement").has("RateBasedStatement") ? "RATE_BASED"
                    : "REGULAR";
            terminate(acl, evaluation, kind, rule.path("Action").path(kind));
            return evaluation;
        }
        JsonNode defaultAction = acl.getDefaultAction() == null ? mapper.createObjectNode()
                : mapper.readTree(acl.getDefaultAction());
        String kind = defaultAction.has("Block") ? "Block" : "Allow";
        terminate(acl, evaluation, kind, defaultAction.path(kind));
        return evaluation;
    }

    private void terminate(WebAcl acl, Evaluation evaluation, String kind, JsonNode action)
            throws JsonProcessingException {
        evaluation.action = kind.toUpperCase(Locale.ROOT);
        if (!"Block".equals(kind)) {
            return;
        }
        JsonNode custom = action.path("CustomResponse");
        if (custom.isMissingNode()) {
            evaluation.response = new Response(403, Map.of("Content-Type", "text/html", "Server", "awselb/2.0"),
                    FORBIDDEN);
            return;
        }
        Map<String, String> headers = new LinkedHashMap<>();
        custom.path("ResponseHeaders").forEach(h -> headers.put(h.path("Name").asText(), h.path("Value").asText()));
        String body = "";
        String key = custom.path("CustomResponseBodyKey").asText(null);
        if (key != null && acl.getCustomResponseBodies() != null) {
            JsonNode custombody = mapper.readTree(acl.getCustomResponseBodies()).path(key);
            body = custombody.path("Content").asText("");
            headers.put("Content-Type", switch (custombody.path("ContentType").asText()) {
                case "TEXT_HTML" -> "text/html";
                case "APPLICATION_JSON" -> "application/json";
                default -> "text/plain";
            });
        }
        evaluation.responseCodeSent = custom.path("ResponseCode").asInt();
        evaluation.response = new Response(evaluation.responseCodeSent, headers, body);
    }

    /** Counts the request against its source IP when the scope-down statement matches; true past the limit. */
    private boolean rateLimited(WebAcl acl, String name, JsonNode rate, HttpServerRequest request,
                                Evaluation evaluation) {
        if (!"IP".equals(rate.path("AggregateKeyType").asText())) {
            throw new Unsupported("RateBasedStatement AggregateKeyType " + rate.path("AggregateKeyType").asText());
        }
        long limit = rate.path("Limit").asLong();
        int window = rate.path("EvaluationWindowSec").asInt(300);
        evaluation.rateBased.add(mapper.createObjectNode()
                .put("rateBasedRuleId", name)
                .put("rateBasedRuleName", name)
                .put("limitKey", "IP")
                .put("limitValue", evaluation.clientIp)
                .put("maxRateAllowed", limit)
                .put("evaluationWindowSec", String.valueOf(window)));
        JsonNode scopeDown = rate.path("ScopeDownStatement");
        if (!scopeDown.isMissingNode() && !matches(scopeDown, request, evaluation.clientIp)) {
            return false;
        }
        Deque<Long> hits = rates.computeIfAbsent(acl.getArn() + "|" + name + "|" + evaluation.clientIp,
                k -> new ArrayDeque<>());
        synchronized (hits) {
            hits.addLast(evaluation.timestamp);
            while (hits.peekFirst() <= evaluation.timestamp - window * 1000L) {
                hits.pollFirst();
            }
            return hits.size() > limit;
        }
    }

    private boolean matches(JsonNode statement, HttpServerRequest request, String clientIp) {
        String type = firstField(statement);
        JsonNode body = statement.path(type);
        return switch (type) {
            case "AndStatement" -> {
                for (JsonNode nested : body.path("Statements")) {
                    if (!matches(nested, request, clientIp)) {
                        yield false;
                    }
                }
                yield true;
            }
            case "OrStatement" -> {
                for (JsonNode nested : body.path("Statements")) {
                    if (matches(nested, request, clientIp)) {
                        yield true;
                    }
                }
                yield false;
            }
            case "NotStatement" -> !matches(body.path("Statement"), request, clientIp);
            case "IPSetReferenceStatement" -> {
                if (body.has("IPSetForwardedIPConfig")) {
                    throw new Unsupported("IPSetForwardedIPConfig");
                }
                IpSet set = service.findIpSet(body.path("ARN").asText());
                yield set != null && set.getAddresses() != null
                        && set.getAddresses().stream().anyMatch(cidr -> SecurityGroupPolicy.inCidr(clientIp, cidr));
            }
            case "ByteMatchStatement" -> {
                String value = inspected(request, body);
                yield value != null && byteMatch(value, searchString(body), body.path("PositionalConstraint").asText());
            }
            case "RegexMatchStatement" -> {
                String value = inspected(request, body);
                yield value != null && Pattern.compile(body.path("RegexString").asText()).matcher(value).find();
            }
            case "SizeConstraintStatement" -> {
                String value = inspected(request, body);
                yield value != null && compare(value.length(), body.path("ComparisonOperator").asText(),
                        body.path("Size").asLong());
            }
            default -> throw new Unsupported(type);
        };
    }

    /** The request component as bytes (one char per byte), after the statement's text transformations. */
    private static String inspected(HttpServerRequest request, JsonNode statement) {
        JsonNode fieldToMatch = statement.path("FieldToMatch");
        String field = firstField(fieldToMatch);
        String value = switch (field) {
            case "UriPath" -> request.path();
            case "QueryString" -> request.query() == null ? "" : request.query();
            case "SingleHeader" -> request.getHeader(fieldToMatch.path(field).path("Name").asText());
            case "Method" -> request.method().name();
            default -> throw new Unsupported("FieldToMatch " + field);
        };
        if (value == null) {
            return null;
        }
        List<JsonNode> transformations = new ArrayList<>();
        statement.path("TextTransformations").forEach(transformations::add);
        transformations.sort(Comparator.comparingInt(t -> t.path("Priority").asInt()));
        String bytes = new String(value.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
        for (JsonNode transformation : transformations) {
            String type = transformation.path("Type").asText();
            bytes = WafV2TextTransformations.apply(type, bytes);
            if (bytes == null) {
                throw new Unsupported("TextTransformation " + type);
            }
        }
        return bytes;
    }

    /** The API's SearchString is a base64 blob; a value that is not base64 is taken as written. */
    private static String searchString(JsonNode statement) {
        String encoded = statement.path("SearchString").asText();
        try {
            return new String(Base64.getDecoder().decode(encoded), StandardCharsets.ISO_8859_1);
        } catch (IllegalArgumentException e) {
            return new String(encoded.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
        }
    }

    static boolean byteMatch(String value, String search, String constraint) {
        return switch (constraint) {
            case "EXACTLY" -> value.equals(search);
            case "STARTS_WITH" -> value.startsWith(search);
            case "ENDS_WITH" -> value.endsWith(search);
            case "CONTAINS" -> value.contains(search);
            case "CONTAINS_WORD" -> {
                int i = search.isEmpty() ? -1 : value.indexOf(search);
                for (; i >= 0; i = value.indexOf(search, i + 1)) {
                    int end = i + search.length();
                    if ((i == 0 || !wordChar(value.charAt(i - 1)))
                            && (end == value.length() || !wordChar(value.charAt(end)))) {
                        yield true;
                    }
                }
                yield false;
            }
            default -> throw new Unsupported("PositionalConstraint " + constraint);
        };
    }

    private static boolean wordChar(char c) {
        return c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    private static boolean compare(long size, String operator, long limit) {
        return switch (operator) {
            case "EQ" -> size == limit;
            case "NE" -> size != limit;
            case "LE" -> size <= limit;
            case "LT" -> size < limit;
            case "GE" -> size >= limit;
            case "GT" -> size > limit;
            default -> throw new Unsupported("ComparisonOperator " + operator);
        };
    }

    private static String firstField(JsonNode node) {
        return node.fieldNames().hasNext() ? node.fieldNames().next() : "";
    }

    /** AWS's "Log fields for protection pack (web ACL) traffic", in the order of its examples. */
    ObjectNode record(WebAcl acl, String loadBalancerArn, HttpServerRequest request, Evaluation evaluation) {
        AwsArnUtils.Arn lb = AwsArnUtils.parse(loadBalancerArn);
        ObjectNode record = mapper.createObjectNode();
        record.put("timestamp", evaluation.timestamp);
        record.put("formatVersion", 1);
        record.put("webaclId", acl.getArn());
        record.put("terminatingRuleId", evaluation.terminatingRuleId);
        record.put("terminatingRuleType", evaluation.terminatingRuleType);
        record.put("action", evaluation.action);
        record.putArray("terminatingRuleMatchDetails");
        record.put("httpSourceName", "ALB");
        record.put("httpSourceId", lb.accountId() + "-" + lb.resource().substring("loadbalancer/".length()));
        record.putArray("ruleGroupList");
        record.putArray("rateBasedRuleList").addAll(evaluation.rateBased);
        ArrayNode counted = record.putArray("nonTerminatingMatchingRules");
        evaluation.counted.forEach(ruleId -> counted.addObject().put("ruleId", ruleId).put("action", "COUNT")
                .putArray("ruleMatchDetails"));
        record.putNull("requestHeadersInserted");
        if (evaluation.responseCodeSent != null) {
            record.put("responseCodeSent", evaluation.responseCodeSent);
        } else {
            record.putNull("responseCodeSent");
        }
        ObjectNode http = record.putObject("httpRequest");
        http.put("clientIp", evaluation.clientIp);
        http.put("country", "-");
        ArrayNode headers = http.putArray("headers");
        request.headers().forEach(header -> headers.addObject().put("name", header.getKey())
                .put("value", header.getValue()));
        http.put("uri", request.path());
        http.put("args", request.query() == null ? "" : request.query());
        http.put("httpVersion", request.version() == HttpVersion.HTTP_2 ? "HTTP/2.0"
                : request.version() == HttpVersion.HTTP_1_0 ? "HTTP/1.0" : "HTTP/1.1");
        http.put("httpMethod", request.method().name());
        String trace = request.getHeader("X-Amzn-Trace-Id");
        http.put("requestId", trace == null ? null : trace.replaceFirst("^(?:.*;)?Root=([^;]*).*$", "$1"));
        if (!evaluation.labels.isEmpty()) {
            ArrayNode labels = record.putArray("labels");
            evaluation.labels.forEach(label -> labels.addObject().put("name", label));
        }
        return record;
    }
}
