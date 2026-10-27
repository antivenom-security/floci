package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.RequestPrincipal;
import io.github.hectorvent.floci.services.iam.ResourcePolicyProvider;
import io.github.hectorvent.floci.services.iam.ResourcePolicyProviders;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Decides a call one AWS service makes to another's resource on its own behalf, such as SES
 * publishing an event notification to an SNS topic. These calls never pass through
 * {@link IamEnforcementFilter}: no IAM principal makes them, so no identity policy, session policy,
 * boundary or SCP applies, and the target's resource policy decides alone. It has to allow the
 * calling service principal, under the conditions the guides tell owners to write against the
 * confused deputy problem: {@code aws:SourceArn} and {@code aws:SourceAccount}, the resource whose
 * configuration triggered the call.
 *
 * <p>The policy comes from the same {@link ResourcePolicyProvider}s the filter reads, picked by the
 * target ARN's service. A target no provider knows has no policy, and a policy that says nothing
 * denies, as on AWS.
 *
 * <p>Only active with IAM enforcement on. With it off, every call is allowed, as every API call is.
 * The decision is returned rather than thrown, because what a refusal means is the caller's to
 * decide: a notification that is not delivered, a delivery that is retried, or an error.
 */
@ApplicationScoped
public class ServiceCallAuthorizer {

    private static final Logger LOG = Logger.getLogger(ServiceCallAuthorizer.class);

    private final EmulatorConfig config;
    private final IamPolicyEvaluator evaluator;
    private final Instance<ResourcePolicyProvider> resourcePolicyProviders;

    @Inject
    public ServiceCallAuthorizer(EmulatorConfig config, IamPolicyEvaluator evaluator,
                                 Instance<ResourcePolicyProvider> resourcePolicyProviders) {
        this.config = config;
        this.evaluator = evaluator;
        this.resourcePolicyProviders = resourcePolicyProviders;
    }

    /**
     * Decides whether {@code service} may perform {@code action} on {@code resourceArn}.
     *
     * @param service       the calling service, such as {@code ses}; its principal is
     *                      {@code ServicePrincipals.of(service)}
     * @param action        the IAM action, such as {@code sns:Publish}
     * @param resourceArn   the target resource
     * @param sourceArn     the resource whose configuration triggered the call, or null
     * @param sourceAccount the account that owns it, or null
     */
    public Decision authorize(String service, String action, String resourceArn,
                              String sourceArn, String sourceAccount) {
        return authorize(service, action, resourceArn, sourceArn, sourceAccount, Map.of());
    }

    /** Like {@link #authorize(String, String, String, String, String)}, with the request's own condition keys, such as {@code s3:x-amz-acl}. */
    public Decision authorize(String service, String action, String resourceArn,
                              String sourceArn, String sourceAccount, Map<String, List<String>> requestContext) {
        if (!config.services().iam().enforcementEnabled()) {
            return Decision.ALLOW;
        }
        String servicePrincipal = ServicePrincipals.of(service);
        List<ResourcePolicyProvider.ResourcePolicy> policies = policiesFor(resourceArn);
        String ownerAccountId = policies.isEmpty() ? null : policies.getFirst().ownerAccountId();
        Map<String, List<String>> context = new LinkedHashMap<>(IamConditionContextResolver.serviceCallContext(
                servicePrincipal, resourceArn, ownerAccountId, sourceArn, sourceAccount));
        context.putAll(requestContext);
        Decision decision = evaluator.evaluateServicePrincipal(
                documents(policies), servicePrincipal, action, resourceArn, context);
        if (decision == Decision.DENY) {
            LOG.infov("IAM enforcement DENY: service={0} action={1} resource={2} source={3}",
                    servicePrincipal, action, resourceArn, sourceArn);
        }
        return decision;
    }

    /**
     * Like {@link #authorize(String, String, String, String, String)}, for a service that acts from an
     * account AWS owns rather than as a service principal, such as the Elastic Load Balancing account
     * a Region's legacy access-log bucket policies name. The policy has to allow that account's root.
     */
    public Decision authorizeAccount(String accountId, String action, String resourceArn,
                                     String sourceArn, String sourceAccount) {
        if (!config.services().iam().enforcementEnabled()) {
            return Decision.ALLOW;
        }
        String partition = AwsArnUtils.isArn(resourceArn) ? AwsArnUtils.parse(resourceArn).partition() : null;
        String principalArn = AwsArnUtils.Arn.global(partition, "iam", accountId, "root").toString();
        List<ResourcePolicyProvider.ResourcePolicy> policies = policiesFor(resourceArn);
        Map<String, List<String>> context = new LinkedHashMap<>();
        context.put("aws:PrincipalAccount", List.of(accountId));
        context.put("aws:PrincipalArn", List.of(principalArn));
        if (sourceArn != null) {
            context.put("aws:SourceArn", List.of(sourceArn));
        }
        if (sourceAccount != null) {
            context.put("aws:SourceAccount", List.of(sourceAccount));
        }
        IamPolicyEvaluator.ResourcePolicyDecision decision = evaluator.evaluateResourcePolicyFor(
                documents(policies), RequestPrincipal.iam(principalArn), action, resourceArn, context);
        return switch (decision) {
            case ALLOW, ALLOW_DIRECT_IAM_USER, ALLOW_ACCOUNT -> Decision.ALLOW;
            default -> Decision.DENY;
        };
    }

    private List<ResourcePolicyProvider.ResourcePolicy> policiesFor(String resourceArn) {
        String targetService = AwsArnUtils.isArn(resourceArn) ? AwsArnUtils.parse(resourceArn).service() : null;
        return ResourcePolicyProviders.policiesFor(resourcePolicyProviders, targetService, resourceArn);
    }

    private static List<String> documents(List<ResourcePolicyProvider.ResourcePolicy> policies) {
        List<String> documents = policies.stream()
                .map(ResourcePolicyProvider.ResourcePolicy::policyDocument)
                .filter(document -> document != null && !document.isBlank())
                .toList();
        return documents.isEmpty() ? null : documents;
    }
}
