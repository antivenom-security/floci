package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OperationResolverTest {

    /** The credential scopes IamActionRegistry routes REST requests for. */
    private static final Set<String> REST_SCOPES = Set.of("s3", "lambda", "apigateway", "pipes", "scheduler",
            "ses", "rds-data", "resource-groups");
    private static final Pattern LABEL = Pattern.compile("\\{([^}]+?)(\\+?)}");

    private final IamActionRegistry registry = mock(IamActionRegistry.class);
    private final OperationResolver resolver = new OperationResolver(registry);

    @TestFactory
    Stream<DynamicTest> everyRestOperationOfARoutedScopeResolvesToItsModelName() {
        List<DynamicTest> tests = new ArrayList<>();
        for (AwsOperationModels.ModelInfo info : AwsOperationModels.models()) {
            if (!REST_SCOPES.contains(info.signingName()) || !info.protocol().startsWith("rest-")) {
                continue;
            }
            AwsOperationModels.model(info.name()).path("operations").properties().forEach(entry -> {
                JsonNode operation = entry.getValue();
                Set<String> expected = equivalentOperations(info.signingName(), operation);
                tests.add(DynamicTest.dynamicTest(info.name() + " " + entry.getKey(), () -> {
                    OperationResolver.Operation resolved = resolver.resolve(info.signingName(), request(operation));
                    assertNotNull(resolved, entry.getKey());
                    assertTrue(expected.contains(resolved.name()),
                            entry.getKey() + " resolved to " + resolved.name() + ", expected one of " + expected);
                    assertEquals(info.eventSource(), resolved.eventSource());
                }));
            });
        }
        assertTrue(tests.size() > 700, "routed operations: " + tests.size());
        return tests.stream();
    }

    @Test
    void s3SubResourcesResolveToTheirOperations() {
        assertEquals("ListObjects", rest("s3", "GET", "/bucket", Map.of(), Map.of()));
        assertEquals("ListObjects", rest("s3", "GET", "/bucket/", Map.of(), Map.of()));
        assertEquals("ListObjectsV2", rest("s3", "GET", "/bucket", Map.of("list-type", "2"), Map.of()));
        assertEquals("GetBucketAcl", rest("s3", "GET", "/bucket", Map.of("acl", ""), Map.of()));
        assertEquals("GetObjectAcl", rest("s3", "GET", "/bucket/a/b.txt", Map.of("acl", ""), Map.of()));
        assertEquals("ListMultipartUploads", rest("s3", "GET", "/bucket", Map.of("uploads", ""), Map.of()));
        assertEquals("CreateMultipartUpload", rest("s3", "POST", "/bucket/k", Map.of("uploads", ""), Map.of()));
        assertEquals("UploadPart", rest("s3", "PUT", "/bucket/k",
                Map.of("partNumber", "1", "uploadId", "u"), Map.of()));
        assertEquals("UploadPartCopy", rest("s3", "PUT", "/bucket/k",
                Map.of("partNumber", "1", "uploadId", "u"), Map.of("x-amz-copy-source", "/src/k")));
        assertEquals("DeleteObjects", rest("s3", "POST", "/bucket", Map.of("delete", ""), Map.of()));
        assertEquals("PutObject", rest("s3", "PUT", "/bucket/k", Map.of(), Map.of()));
        assertEquals("CopyObject", rest("s3", "PUT", "/bucket/k", Map.of(), Map.of("x-amz-copy-source", "/src/k")));
        assertEquals("GetObject", rest("s3", "GET", "/bucket/k", Map.of(), Map.of()));
        assertEquals("HeadObject", rest("s3", "HEAD", "/bucket/k", Map.of(), Map.of()));
        assertEquals("HeadBucket", rest("s3", "HEAD", "/bucket", Map.of(), Map.of()));
        assertEquals("CreateBucket", rest("s3", "PUT", "/bucket", Map.of(), Map.of()));
        assertEquals("ListBuckets", rest("s3", "GET", "/", Map.of(), Map.of()));
        assertEquals("PutBucketPolicy", rest("s3", "PUT", "/bucket", Map.of("policy", ""), Map.of()));
        assertEquals("GetObjectTagging", rest("s3", "GET", "/bucket/k", Map.of("tagging", ""), Map.of()));
    }

    @Test
    void lambdaAndApiGatewayRoutesResolveToTheirOperations() {
        assertEquals("Invoke", rest("lambda", "POST", "/2015-03-31/functions/fn/invocations", Map.of(), Map.of()));
        assertEquals("ListFunctions", rest("lambda", "GET", "/2015-03-31/functions/", Map.of(), Map.of()));
        assertEquals("GetFunction", rest("lambda", "GET", "/2015-03-31/functions/fn", Map.of(), Map.of()));
        assertEquals("UpdateFunctionCode", rest("lambda", "PUT", "/2015-03-31/functions/fn/code", Map.of(), Map.of()));
        assertEquals("GetRestApis", rest("apigateway", "GET", "/restapis", Map.of(), Map.of()));
        assertEquals("CreateDeployment", rest("apigateway", "POST", "/restapis/abc/deployments", Map.of(), Map.of()));
        assertEquals("GetApis", rest("apigateway", "GET", "/v2/apis", Map.of(), Map.of()));
    }

    @Test
    void jsonTargetQueryActionAndRpcV2RouteNameTheOperation() {
        ContainerRequestContext json = context("POST", "/", Map.of(), Map.of("X-Amz-Target", "AmazonSSM.GetParameter"));
        assertEquals(new OperationResolver.Operation("ssm", "ssm.amazonaws.com", "GetParameter"),
                resolver.resolve("ssm", json));

        ContainerRequestContext streams = context("POST", "/", Map.of(),
                Map.of("X-Amz-Target", "DynamoDBStreams_20120810.GetRecords"));
        assertEquals("dynamodbstreams", resolver.resolve("dynamodb", streams).model());

        ContainerRequestContext query = context("GET", "/", Map.of("Action", "CreateUser"), Map.of());
        when(query.getProperty(AwsProtocolClaimFilter.CLAIM_PROPERTY))
                .thenReturn(new ProtocolClaim(WireProtocol.AWS_QUERY, null, null, null));
        when(registry.queryAction(query)).thenReturn("CreateUser");
        assertEquals(new OperationResolver.Operation("iam", "iam.amazonaws.com", "CreateUser"),
                resolver.resolve("iam", query));

        ContainerRequestContext rpcV2 = context("POST", "/service/GraniteServiceVersion20100801/operation/PutMetricData",
                Map.of(), Map.of("smithy-protocol", "rpc-v2-cbor"));
        assertEquals("PutMetricData", resolver.resolve("monitoring", rpcV2).name());
    }

    @Test
    void anUnmodelledRouteResolvesToNothing() {
        assertNull(resolver.resolve("lambda", context("GET", "/no/such/route", Map.of(), Map.of())));
        assertNull(resolver.resolve("iam", context("POST", "/", Map.of(), Map.of("X-Amz-Target", "Nope.Nothing"))));
    }

    private String rest(String scope, String method, String path, Map<String, String> query,
                        Map<String, String> headers) {
        OperationResolver.Operation operation = resolver.resolve(scope, context(method, path, query, headers));
        return operation == null ? null : operation.name();
    }

    /** The operations of {@code scope} a request built from {@code operation}'s route cannot tell apart from it. */
    private static Set<String> equivalentOperations(String scope, JsonNode operation) {
        String key = routeKey(operation);
        Set<String> names = new HashSet<>();
        for (AwsOperationModels.ModelInfo info : AwsOperationModels.models()) {
            if (info.signingName().equals(scope) && info.protocol().startsWith("rest-")) {
                AwsOperationModels.model(info.name()).path("operations").properties().forEach(entry -> {
                    if (routeKey(entry.getValue()).equals(key)) {
                        names.add(entry.getKey());
                    }
                });
            }
        }
        return names;
    }

    private static String routeKey(JsonNode operation) {
        Map<String, String> query = new TreeMap<>();
        operation.path("query").properties().forEach(literal -> {
            if (!"x-id".equals(literal.getKey())) {
                query.put(literal.getKey(), literal.getValue().asText());
            }
        });
        return operation.path("method").asText() + " " + LABEL.matcher(operation.path("uri").asText())
                .replaceAll(match -> match.group(2).isEmpty() ? "{}" : "{+}") + " " + query + " "
                + operation.path("headers") + " " + operation.path("queryParameters");
    }

    private static ContainerRequestContext request(JsonNode operation) {
        Map<String, String> query = new TreeMap<>();
        operation.path("query").properties().forEach(literal -> query.put(literal.getKey(),
                literal.getValue().asText().isEmpty() ? "" : literal.getValue().asText()));
        Map<String, String> headers = new TreeMap<>();
        operation.path("headers").forEach(header -> headers.put(header.asText(), "value"));
        operation.path("queryParameters").forEach(parameter -> query.put(parameter.asText(), "1"));
        return context(operation.path("method").asText(), fill(operation.path("uri").asText()), query, headers);
    }

    private static String fill(String template) {
        Matcher label = LABEL.matcher(template);
        StringBuilder path = new StringBuilder();
        while (label.find()) {
            String value = label.group(1).toLowerCase().replaceAll("[^a-z0-9]", "") + "-value";
            label.appendReplacement(path, label.group(2).isEmpty() ? value : value + "/part");
        }
        label.appendTail(path);
        return path.toString();
    }

    private static ContainerRequestContext context(String method, String path, Map<String, String> query,
                                                   Map<String, String> headers) {
        MultivaluedMap<String, String> parameters = new MultivaluedHashMap<>();
        query.forEach(parameters::add);
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(parameters);
        when(uriInfo.getPath()).thenReturn(path);
        when(uriInfo.getRequestUri()).thenReturn(URI.create("http://localhost:4566" + path));
        when(uriInfo.getBaseUri()).thenReturn(URI.create("http://localhost:4566/"));
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMethod()).thenReturn(method);
        headers.forEach((name, value) -> when(ctx.getHeaderString(name)).thenReturn(value));
        return ctx;
    }
}
