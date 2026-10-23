package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.ServicePrincipals;
import io.github.hectorvent.floci.services.cloudtrail.model.Trail;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.iam.AssumeRolePolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Sends a delivered log file's records to the trail's CloudWatch Logs group, one log event per record,
 * in the stream {@code <account>_CloudTrail_<region>}. CloudTrail writes there as the trail's role:
 * under IAM enforcement the role must trust {@code cloudtrail.amazonaws.com} and allow
 * {@code logs:CreateLogStream} and {@code logs:PutLogEvents}. Records over 256 KB are not sent, as on AWS.
 */
@ApplicationScoped
public class CloudTrailCwlDelivery {

    private static final Logger LOG = Logger.getLogger(CloudTrailCwlDelivery.class);
    static final int MAX_EVENT_BYTES = 256 * 1024;

    private final EmulatorConfig config;
    private final CloudWatchLogsService logs;
    private final IamService iamService;
    private final AssumeRolePolicyEvaluator trustEvaluator;
    private final IamPolicyEvaluator policyEvaluator;
    private final ObjectMapper mapper;

    @Inject
    public CloudTrailCwlDelivery(EmulatorConfig config, CloudWatchLogsService logs, IamService iamService,
                                 AssumeRolePolicyEvaluator trustEvaluator, IamPolicyEvaluator policyEvaluator,
                                 ObjectMapper mapper) {
        this.config = config;
        this.logs = logs;
        this.iamService = iamService;
        this.trustEvaluator = trustEvaluator;
        this.policyEvaluator = policyEvaluator;
        this.mapper = mapper;
    }

    void deliver(Trail trail, String accountId, String eventRegion, List<ObjectNode> records) {
        AwsArnUtils.Arn group = AwsArnUtils.parse(trail.cloudWatchLogsLogGroupArn());
        String groupName = groupName(group.resource());
        String stream = accountId + "_CloudTrail_" + eventRegion;
        String streamArn = AwsArnUtils.Arn.of("logs", group.region(), group.accountId(),
                "log-group:" + groupName + ":log-stream:" + stream).toString();
        authorize(trail.cloudWatchLogsRoleArn(), streamArn);

        List<Map<String, Object>> events = new ArrayList<>(records.size());
        for (ObjectNode record : records) {
            String message = json(record);
            if (message.getBytes(StandardCharsets.UTF_8).length > MAX_EVENT_BYTES) {
                LOG.debugv("CloudTrail event {0} is over 256 KB and is not sent to CloudWatch Logs",
                        record.path("eventID").asText());
                continue;
            }
            events.add(Map.of("timestamp", Instant.parse(record.path("eventTime").asText()).toEpochMilli(),
                    "message", message));
        }
        if (events.isEmpty()) {
            return;
        }
        try {
            logs.createLogStreamForAccount(group.accountId(), groupName, stream, group.region());
        } catch (AwsException e) {
            if (!"ResourceAlreadyExistsException".equals(e.getErrorCode())) {
                throw e;
            }
            LOG.tracev("Log stream {0}/{1} already exists", groupName, stream);
        }
        logs.putLogEventsForAccount(group.accountId(), groupName, stream, events, group.region());
    }

    private void authorize(String roleArn, String streamArn) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }
        AwsArnUtils.Arn role = AwsArnUtils.parse(roleArn);
        Optional<IamRole> found = iamService.findRole(role.accountId(),
                role.resource().substring(role.resource().lastIndexOf('/') + 1));
        if (found.isEmpty() || !roleArn.equals(found.get().getArn())) {
            throw new AwsException("AccessDeniedException", "Role " + roleArn + " does not exist.", 400);
        }
        String cloudTrail = ServicePrincipals.of("cloudtrail");
        if (!trustEvaluator.allowsService(found.get().getAssumeRolePolicyDocument(), cloudTrail)) {
            throw new AwsException("AccessDeniedException",
                    "Role " + roleArn + " does not trust " + cloudTrail + ".", 400);
        }
        CallerContext caller = iamService.resolvePrincipalContext(roleArn);
        for (String action : List.of("logs:CreateLogStream", "logs:PutLogEvents")) {
            if (policyEvaluator.simulatePrincipalPolicy(caller, action, streamArn, Map.of())
                    != IamPolicyEvaluator.SimulationDecision.ALLOWED) {
                throw new AwsException("AccessDeniedException",
                        "Role " + roleArn + " is not allowed to perform " + action + " on " + streamArn + ".", 400);
            }
        }
    }

    private static String groupName(String resource) {
        String name = resource.substring("log-group:".length());
        return name.endsWith(":*") ? name.substring(0, name.length() - 2) : name;
    }

    private String json(ObjectNode record) {
        try {
            return mapper.writeValueAsString(record);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize a CloudTrail record", e);
        }
    }
}
