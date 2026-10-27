package io.github.hectorvent.floci.services.elbv2;

import io.vertx.core.http.HttpServerRequest;

import java.util.List;
import java.util.Map;

/**
 * Inspects each request an Application Load Balancer listener accepts, before its rules run, the way
 * AWS WAF inspects requests to a load balancer with an associated web ACL. Every CDI bean of this
 * type is consulted in turn; none exists until a service such as WAF provides one.
 */
public interface ElbV2RequestInspector {

    /**
     * @param actionsExecuted the request's access-log {@code actions_executed} so far, to which an
     *                        inspector adds its own, such as {@code waf} or {@code waf-failed}
     * @return null to let the request continue to the listener's rules, or the response the load
     *         balancer sends instead, without reaching a target
     */
    Response inspect(HttpServerRequest request, String region, String loadBalancerArn, List<String> actionsExecuted);

    record Response(int statusCode, Map<String, String> headers, String body) {}
}
