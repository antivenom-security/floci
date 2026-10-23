package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsOperationModels;
import io.github.hectorvent.floci.core.common.AwsPartition;
import io.github.hectorvent.floci.core.common.AwsPartitions;
import io.github.hectorvent.floci.core.common.OperationResolver;
import io.github.hectorvent.floci.core.common.OperationResolver.Operation;
import io.github.hectorvent.floci.core.common.RequestContext;
import io.github.hectorvent.floci.core.common.ResolvedServiceCatalog;
import io.github.hectorvent.floci.core.common.ServicePrincipals;
import io.github.hectorvent.floci.core.common.SigV4CredentialScope;
import io.github.hectorvent.floci.core.common.XmlParser;
import io.github.hectorvent.floci.core.common.XmlParser.XmlElement;
import io.github.hectorvent.floci.services.cloudtrail.record.CloudTrailEvent;
import io.github.hectorvent.floci.services.cloudtrail.record.CloudTrailRecordBuilder;
import io.github.hectorvent.floci.services.cloudtrail.record.TlsDetails;
import io.github.hectorvent.floci.services.cloudtrail.record.UserIdentityBuilder;
import io.github.hectorvent.floci.services.cloudtrail.record.WireParameters;
import io.github.hectorvent.floci.services.iam.RequestBodyReader;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.StreamingOutput;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Records every signed AWS API call that is a management event. The request phase, once the
 * signature has been checked and before IAM authorizes the call, names the operation from the
 * model and reads its input off the wire: the form, JSON body, or REST path and query string, and a
 * body only when its declared length is at most 256 KB. The response phase builds the record from
 * the response or the error it carries, IAM denials included, and hands it to
 * {@link CloudTrailRecorder}.
 *
 * <p>Unsigned calls, calls no model operation matches, operations CloudTrail does not log, and data
 * events (which S3 records on its own path) are skipped.
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION + 50)
public class CloudTrailCaptureFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Logger LOG = Logger.getLogger(CloudTrailCaptureFilter.class);
    private static final String OPERATION = CloudTrailCaptureFilter.class.getName() + ".operation";
    private static final String PARAMETERS = CloudTrailCaptureFilter.class.getName() + ".parameters";
    static final int MAX_CAPTURED_BODY_BYTES = 256 * 1024;

    private final EmulatorConfig config;
    private final RequestContext requestContext;
    private final OperationResolver operationResolver;
    private final ResolvedServiceCatalog catalog;
    private final CloudTrailRecordBuilder recordBuilder;
    private final UserIdentityBuilder userIdentityBuilder;
    private final CloudTrailRecorder recorder;
    private final CurrentVertxRequest currentVertxRequest;
    private final ObjectMapper mapper;

    @Inject
    public CloudTrailCaptureFilter(EmulatorConfig config, RequestContext requestContext,
                                   OperationResolver operationResolver, ResolvedServiceCatalog catalog,
                                   CloudTrailRecordBuilder recordBuilder, UserIdentityBuilder userIdentityBuilder,
                                   CloudTrailRecorder recorder, CurrentVertxRequest currentVertxRequest,
                                   ObjectMapper mapper) {
        this.config = config;
        this.requestContext = requestContext;
        this.operationResolver = operationResolver;
        this.catalog = catalog;
        this.recordBuilder = recordBuilder;
        this.userIdentityBuilder = userIdentityBuilder;
        this.recorder = recorder;
        this.currentVertxRequest = currentVertxRequest;
        this.mapper = mapper;
    }

    /** The first X-Forwarded-For address when {@code trustForwardedFor}, otherwise the TCP peer. */
    public static String sourceIp(HttpServerRequest request, boolean trustForwardedFor) {
        String forwarded = trustForwardedFor ? request.getHeader("X-Forwarded-For") : null;
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
        }
        return request.remoteAddress() == null ? null : request.remoteAddress().host();
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!recorder.enabled()) {
            return;
        }
        String auth = ctx.getHeaderString("Authorization");
        String scope = auth == null ? null
                : SigV4CredentialScope.serviceName(auth).map(catalog::canonicalCredentialScope).orElse(null);
        if (scope == null) {
            return;
        }
        try {
            Operation operation = operationResolver.resolve(scope, ctx);
            if (operation == null
                    || CloudTrailRecordBuilder.isDataEvent(operation.eventSource(), operation.name())
                    || CloudTrailRecordBuilder.isNotLogged(operation.eventSource(), operation.name())) {
                return;
            }
            ctx.setProperty(OPERATION, operation);
            JsonNode parameters = recordBuilder.parameters(operation, false, input(operation, ctx));
            if (parameters != null && !parameters.isEmpty()) {
                ctx.setProperty(PARAMETERS, parameters);
            }
        } catch (RuntimeException e) {
            LOG.debugv(e, "CloudTrail could not capture {0} {1}", ctx.getMethod(), ctx.getUriInfo().getPath());
        }
    }

    @Override
    public void filter(ContainerRequestContext ctx, ContainerResponseContext response) {
        if (!(ctx.getProperty(OPERATION) instanceof Operation operation)) {
            return;
        }
        try {
            recorder.record(record(operation, (JsonNode) ctx.getProperty(PARAMETERS), response));
        } catch (RuntimeException e) {
            LOG.warnv(e, "CloudTrail could not record {0}", operation.name());
        }
    }

    private ObjectNode record(Operation operation, JsonNode parameters, ContainerResponseContext response) {
        String errorCode = null;
        String errorMessage = null;
        JsonNode responseElements = null;
        if (response.getStatus() >= 400) {
            String[] error = error(response);
            errorCode = error[0];
            errorMessage = error[1];
        } else if (!CloudTrailRecordBuilder.isReadOnly(operation.eventSource(), operation.name())) {
            responseElements = recordBuilder.parameters(operation, true,
                    output(operation, response.getEntity()));
        }
        HttpServerRequest request = null;
        RoutingContext routing = currentVertxRequest.getCurrent();
        if (routing != null) {
            request = routing.request();
        }
        String requestId = response.getHeaderString("x-amz-request-id");
        return recordBuilder.build(CloudTrailEvent.builder()
                .eventSource(operation.eventSource())
                .eventName(operation.name())
                .awsRegion(eventRegion(operation.eventSource(), requestContext.getRegion()))
                .eventTime(Instant.now())
                .userIdentity(userIdentityBuilder.forAccessKey(requestContext.getAccessKeyId()))
                .sourceIPAddress(request == null ? null
                        : sourceIp(request, config.services().cloudtrail().trustForwardedFor()))
                .userAgent(request == null ? null : request.getHeader("User-Agent"))
                .errorCode(errorCode)
                .errorMessage(errorMessage)
                .requestParameters(parameters)
                .responseElements(responseElements)
                .requestId(requestId != null ? requestId : requestContext.getRequestId())
                .tlsDetails(request == null ? null : TlsDetails.of(request))
                .recipientAccountId(requestContext.getAccountId())
                .build());
    }

    /** Global services record in their partition's signing region, as IAM does in us-east-1. */
    private static String eventRegion(String eventSource, String region) {
        return AwsPartitions.forRegionOrCommercial(region).globalEndpoint(ServicePrincipals.serviceName(eventSource))
                .filter(endpoint -> !endpoint.regionalized())
                .map(AwsPartition.GlobalEndpoint::signingRegion)
                .orElse(region);
    }

    private JsonNode input(Operation operation, ContainerRequestContext ctx) {
        String shape = operationNode(operation).path("input").asText("");
        if (shape.isEmpty()) {
            return null;
        }
        WireParameters wire = new WireParameters(mapper, AwsOperationModels.model(operation.model()).path("shapes"));
        return switch (protocol(operation)) {
            case "query", "ec2" -> wire.fromForm(shape, form(ctx), "ec2".equals(protocol(operation)));
            case "json" -> json(body(ctx));
            case "rest-json", "rest-xml" -> wire.fromRest(shape, operationNode(operation).path("uri").asText(),
                    path(ctx), ctx.getUriInfo().getQueryParameters(),
                    "rest-json".equals(protocol(operation)) ? json(body(ctx)) : null);
            default -> null;
        };
    }

    private JsonNode output(Operation operation, Object entity) {
        String shape = operationNode(operation).path("output").asText("");
        if (shape.isEmpty() || entity == null || entity instanceof InputStream || entity instanceof StreamingOutput
                || entity instanceof File) {
            return null;
        }
        WireParameters wire = new WireParameters(mapper, AwsOperationModels.model(operation.model()).path("shapes"));
        return switch (protocol(operation)) {
            case "query", "ec2" -> {
                XmlElement root = XmlParser.parseDocumentElementTree(text(entity));
                if (root == null) {
                    yield null;
                }
                XmlElement result = root.child(operation.name() + "Result");
                yield wire.fromXml(shape, result != null ? result : root);
            }
            case "json", "rest-json" -> tree(entity);
            default -> null;
        };
    }

    private String[] error(ContainerResponseContext response) {
        Object entity = response.getEntity();
        String code = response.getHeaderString("x-amzn-ErrorType");
        String message = null;
        String text = entity instanceof String || entity instanceof byte[] ? text(entity) : null;
        if (text != null && text.trim().startsWith("<")) {
            code = XmlParser.extractFirst(text, "Code", code);
            message = XmlParser.extractFirst(text, "Message", null);
        } else {
            JsonNode body = tree(entity);
            if (body != null) {
                code = firstText(body, code, "__type", "code", "Code");
                message = firstText(body, null, "message", "Message");
            }
        }
        if (code == null) {
            code = String.valueOf(response.getStatus());
        }
        code = code.substring(code.lastIndexOf('#') + 1);
        int colon = code.indexOf(':');
        return new String[] {colon > 0 ? code.substring(0, colon) : code, message};
    }

    private static String firstText(JsonNode body, String fallback, String... fields) {
        for (String field : fields) {
            if (body.path(field).isTextual()) {
                return body.path(field).asText();
            }
        }
        return fallback;
    }

    private JsonNode tree(Object entity) {
        try {
            if (entity instanceof JsonNode node) {
                return node;
            }
            if (entity instanceof String || entity instanceof byte[]) {
                return json(text(entity).getBytes(StandardCharsets.UTF_8));
            }
            return entity == null || entity instanceof InputStream || entity instanceof StreamingOutput
                    ? null : mapper.valueToTree(entity);
        } catch (IllegalArgumentException e) {
            LOG.debugv(e, "CloudTrail could not read a {0} response", entity.getClass().getName());
            return null;
        }
    }

    private JsonNode json(byte[] body) {
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            return mapper.readTree(body);
        } catch (IOException e) {
            LOG.debugv(e, "CloudTrail could not parse a JSON body");
            return null;
        }
    }

    private static String text(Object entity) {
        return entity instanceof byte[] bytes ? new String(bytes, StandardCharsets.UTF_8) : String.valueOf(entity);
    }

    private static byte[] body(ContainerRequestContext ctx) {
        int length = ctx.getLength();
        return length < 0 || length > MAX_CAPTURED_BODY_BYTES ? null : RequestBodyReader.buffer(ctx);
    }

    private static Map<String, String> form(ContainerRequestContext ctx) {
        Map<String, String> form = new LinkedHashMap<>();
        if ("GET".equalsIgnoreCase(ctx.getMethod())) {
            ctx.getUriInfo().getQueryParameters().forEach((key, values) -> form.put(key, values.getFirst()));
        } else if (ctx.getMediaType() != null
                && ctx.getMediaType().isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE)) {
            byte[] body = body(ctx);
            String encoded = body == null ? "" : new String(body, StandardCharsets.UTF_8);
            for (String pair : encoded.split("&")) {
                if (pair.isEmpty()) {
                    continue;
                }
                int eq = pair.indexOf('=');
                form.put(URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8),
                        eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return form;
    }

    private static String path(ContainerRequestContext ctx) {
        String path = ctx.getUriInfo().getPath(false);
        return path.startsWith("/") ? path : "/" + path;
    }

    private static JsonNode operationNode(Operation operation) {
        return AwsOperationModels.model(operation.model()).path("operations").path(operation.name());
    }

    private static String protocol(Operation operation) {
        return AwsOperationModels.info(operation.model()).protocol();
    }
}
