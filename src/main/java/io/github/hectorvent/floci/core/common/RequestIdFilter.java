package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.s3.S3Controller;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.ext.Provider;

import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Mints the AWS request id of every request before any handler or authorization filter runs, and
 * keeps it on {@link RequestContext}. {@link AwsRequestIdFilter} returns it in the response's
 * request-id headers, so a CloudTrail record of the request carries the {@code requestID} the
 * client received. S3 ids take S3's 16-character uppercase hex form, every other service a UUID.
 */
@Provider
@Priority(Priorities.AUTHENTICATION - 200)
public class RequestIdFilter implements ContainerRequestFilter {

    private final RequestContext requestContext;
    private final ResourceInfo resourceInfo;

    @Inject
    public RequestIdFilter(RequestContext requestContext, @Context ResourceInfo resourceInfo) {
        this.requestContext = requestContext;
        this.resourceInfo = resourceInfo;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        boolean s3 = resourceInfo != null && S3Controller.class.equals(resourceInfo.getResourceClass());
        requestContext.setRequestId(s3 ? s3RequestId() : UUID.randomUUID().toString());
    }

    /** A request id in S3's 16-character uppercase hex form. */
    public static String s3RequestId() {
        return HexFormat.of().withUpperCase().toHexDigits(ThreadLocalRandom.current().nextLong());
    }
}
