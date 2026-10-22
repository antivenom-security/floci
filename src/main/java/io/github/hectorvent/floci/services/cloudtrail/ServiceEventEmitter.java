package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.ServicePrincipals;
import io.github.hectorvent.floci.services.cloudtrail.record.CloudTrailEvent;
import io.github.hectorvent.floci.services.cloudtrail.record.CloudTrailRecordBuilder;
import io.github.hectorvent.floci.services.cloudtrail.record.UserIdentityBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.UUID;

/**
 * Records the API calls AWS services make on their own behalf, with an {@code AWSService} identity
 * whose principal is also the source IP and user agent: ECS assuming a task role, Lambda an
 * execution role, EC2 an instance profile's role.
 */
@ApplicationScoped
public class ServiceEventEmitter {

    private static final Logger LOG = Logger.getLogger(ServiceEventEmitter.class);
    private static final String STS = ServicePrincipals.of("sts");

    private final CloudTrailRecordBuilder recordBuilder;
    private final UserIdentityBuilder userIdentityBuilder;
    private final CloudTrailRecorder recorder;
    private final ObjectMapper mapper;

    @Inject
    public ServiceEventEmitter(CloudTrailRecordBuilder recordBuilder, UserIdentityBuilder userIdentityBuilder,
                               CloudTrailRecorder recorder, ObjectMapper mapper) {
        this.recordBuilder = recordBuilder;
        this.userIdentityBuilder = userIdentityBuilder;
        this.recorder = recorder;
        this.mapper = mapper;
    }

    /**
     * Records {@code service} (such as {@code ecs-tasks}) assuming {@code roleArn} in {@code region}
     * as session {@code sessionName}, issuing the given credentials. {@code expiration} may be null.
     */
    public void assumeRole(String service, String region, String roleArn, String sessionName, String accessKeyId,
                           String sessionToken, String assumedRoleId, Instant expiration) {
        if (!recorder.enabled()) {
            return;
        }
        try {
            String principal = ServicePrincipals.of(service);
            AwsArnUtils.Arn role = AwsArnUtils.parse(roleArn);
            String roleName = role.resource().substring(role.resource().lastIndexOf('/') + 1);
            ObjectNode input = mapper.createObjectNode();
            input.put("RoleArn", roleArn);
            input.put("RoleSessionName", sessionName);
            ObjectNode output = mapper.createObjectNode();
            ObjectNode credentials = output.putObject("Credentials");
            credentials.put("AccessKeyId", accessKeyId);
            credentials.put("SessionToken", sessionToken);
            if (expiration != null) {
                credentials.put("Expiration", expiration.toString());
            }
            ObjectNode assumedRoleUser = output.putObject("AssumedRoleUser");
            assumedRoleUser.put("AssumedRoleId", assumedRoleId);
            assumedRoleUser.put("Arn", AwsArnUtils.Arn.global(role.partition(), "sts", role.accountId(),
                    "assumed-role/" + roleName + "/" + sessionName).toString());
            recorder.record(recordBuilder.build(CloudTrailEvent.builder()
                    .eventSource(STS)
                    .eventName("AssumeRole")
                    .awsRegion(region)
                    .eventTime(Instant.now())
                    .userIdentity(userIdentityBuilder.forService(principal))
                    .sourceIPAddress(principal)
                    .userAgent(principal)
                    .requestParameters(recordBuilder.parameters(STS, "AssumeRole", false, input))
                    .responseElements(recordBuilder.parameters(STS, "AssumeRole", true, output))
                    .requestId(UUID.randomUUID().toString())
                    .recipientAccountId(role.accountId())
                    .build()));
        } catch (RuntimeException e) {
            LOG.warnv(e, "CloudTrail could not record {0} assuming {1}", service, roleArn);
        }
    }
}
