package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Names the AWS operation a request invokes, as CloudTrail's {@code eventName} does, from the
 * service models in {@link AwsOperationModels}.
 *
 * <p>A Query request names it in {@code Action}, a JSON request in the suffix of
 * {@code X-Amz-Target}, an RPCv2 CBOR request in its route. A REST request is matched against each
 * model operation's HTTP method, URI template and required query literals, preferring the one whose
 * required headers and query parameters the request carries, and
 * the most specific match wins. S3 virtual-host requests reach here already rewritten to path
 * style by {@code S3VirtualHostFilter}, which runs before resource matching.
 */
@ApplicationScoped
public class OperationResolver {

    private static final Logger LOG = Logger.getLogger(OperationResolver.class);
    private static final Pattern LABEL = Pattern.compile("\\{([^}]+?)(\\+?)}");
    private static final Pattern RPC_V2_PATH = Pattern.compile("^/service/[^/]+/operation/([^/]+)$");

    /** The operation a request invokes: its model, the event source it is recorded under, and its name. */
    public record Operation(String model, String eventSource, String name) {
    }

    private record Route(String model, String eventSource, String name, String method, Pattern path,
                         Map<String, String> query, List<String> headers, List<String> queryParameters,
                         int literalChars) {
    }

    private final IamActionRegistry actionRegistry;
    private final Map<String, List<Route>> routesByScope = new ConcurrentHashMap<>();

    @Inject
    public OperationResolver(IamActionRegistry actionRegistry) {
        this.actionRegistry = actionRegistry;
    }

    /** The operation {@code ctx} invokes on the service signed for as {@code credentialScope}, or null. */
    public Operation resolve(String credentialScope, ContainerRequestContext ctx) {
        Operation operation = resolveOperation(credentialScope, ctx);
        if (operation == null) {
            LOG.debugv("No operation resolved for {0} {1} {2}", credentialScope, ctx.getMethod(),
                    ctx.getUriInfo().getRequestUri().getRawPath());
        }
        return operation;
    }

    private Operation resolveOperation(String credentialScope, ContainerRequestContext ctx) {
        if (IamActionRegistry.isQueryRequest(ctx)) {
            String action = actionRegistry.queryAction(ctx);
            if (action != null && !action.isBlank()) {
                return byName(credentialScope, null, action, true, actionRegistry.queryVersion(ctx));
            }
        }
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target != null && target.contains(".")) {
            int dot = target.lastIndexOf('.');
            return byName(credentialScope, target.substring(0, dot), target.substring(dot + 1), false, null);
        }
        String path = rawPath(ctx);
        Matcher rpcV2 = RPC_V2_PATH.matcher(path);
        if (rpcV2.matches() && ctx.getHeaderString("smithy-protocol") != null) {
            return byName(credentialScope, null, rpcV2.group(1), false, null);
        }
        return byRoute(credentialScope, ctx.getMethod().toUpperCase(), path,
                ctx.getUriInfo().getQueryParameters(), ctx);
    }

    /**
     * The operation {@code name} in a model the target prefix names, or else in one signed for as the
     * scope: for a Query request a Query or EC2 model, preferring the one whose API version is the
     * request's {@code Version} and then the one named for the scope, as RDS is beside DocumentDB.
     */
    private static Operation byName(String credentialScope, String targetPrefix, String name, boolean query,
                                    String version) {
        Operation best = null;
        int bestScore = -1;
        for (AwsOperationModels.ModelInfo info : AwsOperationModels.models()) {
            boolean prefixMatches = targetPrefix != null && targetPrefix.equals(info.targetPrefix());
            boolean queryModel = "query".equals(info.protocol()) || "ec2".equals(info.protocol());
            if (!prefixMatches && (!info.signingName().equals(credentialScope) || queryModel != query)) {
                continue;
            }
            if (!AwsOperationModels.model(info.name()).path("operations").has(name)) {
                continue;
            }
            if (prefixMatches) {
                return new Operation(info.name(), info.eventSource(), name);
            }
            int score = (info.apiVersion().equals(version) ? 2 : 0)
                    + (info.name().equals(credentialScope) ? 1 : 0);
            if (score > bestScore) {
                best = new Operation(info.name(), info.eventSource(), name);
                bestScore = score;
            }
        }
        return best;
    }

    private Operation byRoute(String credentialScope, String method, String path,
                              MultivaluedMap<String, String> query, ContainerRequestContext ctx) {
        Route best = null;
        int bestScore = Integer.MIN_VALUE;
        for (Route route : routes(credentialScope)) {
            if (!route.method().equals(method) || !route.path().matcher(path).matches()
                    || !queryMatches(route.query(), query)) {
                continue;
            }
            int present = 0;
            for (String header : route.headers()) {
                if (ctx.getHeaderString(header) != null) {
                    present++;
                }
            }
            for (String parameter : route.queryParameters()) {
                if (query.containsKey(parameter)) {
                    present++;
                }
            }
            boolean allPresent = present == route.headers().size() + route.queryParameters().size();
            int score = (allPresent ? 1 << 24 : 0) + (present << 20) + (route.query().size() << 16)
                    + route.literalChars();
            if (score > bestScore) {
                best = route;
                bestScore = score;
            }
        }
        return best == null ? null : new Operation(best.model(), best.eventSource(), best.name());
    }

    private static boolean queryMatches(Map<String, String> required, MultivaluedMap<String, String> query) {
        for (Map.Entry<String, String> literal : required.entrySet()) {
            String value = query.getFirst(literal.getKey());
            if (value == null || (!literal.getValue().isEmpty() && !literal.getValue().equals(value))) {
                return false;
            }
        }
        return true;
    }

    private List<Route> routes(String credentialScope) {
        return routesByScope.computeIfAbsent(credentialScope, OperationResolver::compileRoutes);
    }

    private static List<Route> compileRoutes(String credentialScope) {
        List<Route> routes = new ArrayList<>();
        for (AwsOperationModels.ModelInfo info : AwsOperationModels.models()) {
            if (!info.signingName().equals(credentialScope) || !info.protocol().startsWith("rest-")) {
                continue;
            }
            AwsOperationModels.model(info.name()).path("operations").properties()
                    .forEach(entry -> routes.add(route(info, entry.getKey(), entry.getValue())));
        }
        routes.sort(Comparator.comparing(Route::name, Comparator.comparingInt(String::length))
                .thenComparing(Route::name));
        return List.copyOf(routes);
    }

    private static Route route(AwsOperationModels.ModelInfo info, String name, JsonNode operation) {
        String template = operation.path("uri").asText();
        Matcher label = LABEL.matcher(template);
        StringBuilder regex = new StringBuilder("^");
        int literalChars = 0;
        int last = 0;
        while (label.find()) {
            String literal = template.substring(last, label.start());
            regex.append(Pattern.quote(literal)).append(label.group(2).isEmpty() ? "[^/]+" : ".+");
            literalChars += literal.length();
            last = label.end();
        }
        String tail = template.substring(last);
        literalChars += tail.length();
        regex.append(Pattern.quote(tail));
        if (!template.endsWith("+}") && !template.endsWith("/")) {
            regex.append("/?");
        }
        regex.append('$');
        Map<String, String> query = new LinkedHashMap<>();
        operation.path("query").properties().forEach(literal -> {
            if (!"x-id".equals(literal.getKey())) {
                query.put(literal.getKey(), literal.getValue().asText());
            }
        });
        return new Route(info.name(), info.eventSource(), name, operation.path("method").asText(),
                Pattern.compile(regex.toString()), Map.copyOf(query), texts(operation.path("headers")),
                texts(operation.path("queryParameters")), literalChars);
    }

    private static List<String> texts(JsonNode array) {
        List<String> texts = new ArrayList<>();
        array.forEach(text -> texts.add(text.asText()));
        return List.copyOf(texts);
    }

    private static String rawPath(ContainerRequestContext ctx) {
        String path = ctx.getUriInfo().getRequestUri().getRawPath();
        String base = ctx.getUriInfo().getBaseUri().getRawPath();
        if (base != null && base.length() > 1 && path.startsWith(base)) {
            path = path.substring(base.length() - 1);
        }
        return path.startsWith("/") ? path : "/" + path;
    }
}
