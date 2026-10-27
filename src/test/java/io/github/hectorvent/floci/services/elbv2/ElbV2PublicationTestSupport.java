package io.github.hectorvent.floci.services.elbv2;

import io.github.hectorvent.floci.services.elbv2.model.Listener;
import io.github.hectorvent.floci.services.elbv2.model.Rule;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpConnection;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.HttpVersion;
import org.mockito.invocation.InvocationOnMock;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Supplier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class ElbV2PublicationTestSupport {
    private ElbV2PublicationTestSupport() { }

    /** A plain GET for {@code host}, answered on {@code response}, with what the access log reads. */
    static HttpServerRequest request(String host, HttpServerResponse response) {
        HttpServerRequest request = mock(HttpServerRequest.class);
        when(request.host()).thenReturn(host);
        when(request.response()).thenReturn(response);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.version()).thenReturn(HttpVersion.HTTP_1_1);
        when(request.uri()).thenReturn("/");
        when(request.headers()).thenReturn(MultiMap.caseInsensitiveMultiMap());
        when(request.connection()).thenReturn(mock(HttpConnection.class));
        return request;
    }

    static void publishRuntime(ElbV2DataPlane plane, Listener listener, String region,
                               Integer previousPort, List<Rule> rules) {
        while (!plane.publishListener(listener, region, previousPort, () -> {
            plane.recompileRules(listener.getListenerArn(), () -> rules);
            return true;
        }, () -> rules, Supplier::get)) {
            // The service retries a runtime reservation changed by another publisher.
        }
    }

    static void removeRuntime(ElbV2DataPlane plane, String arn, Integer storedPort) {
        while (!plane.removeListener(arn, storedPort, () -> true)) {
            // Retry an identity changed while waiting for its port gate.
        }
    }

    static boolean applyPublication(InvocationOnMock call) {
        Function<Supplier<Boolean>, Boolean> admission = call.getArgument(5);
        return admission.apply(() -> call.getArgument(3, BooleanSupplier.class).getAsBoolean());
    }

    static void allowPublications(ElbV2DataPlane dataPlane) {
        lenient().doAnswer(ElbV2PublicationTestSupport::applyPublication)
                .when(dataPlane).publishListener(any(Listener.class), anyString(), any(), any(), any(), any());
        lenient().doAnswer(call -> call.getArgument(1, BooleanSupplier.class).getAsBoolean())
                .when(dataPlane).updateListener(any(), any());
        lenient().doAnswer(call -> call.getArgument(2, BooleanSupplier.class).getAsBoolean())
                .when(dataPlane).removeListener(anyString(), any(), any());
    }

}
