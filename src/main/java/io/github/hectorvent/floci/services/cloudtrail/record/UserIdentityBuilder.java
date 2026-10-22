package io.github.hectorvent.floci.services.cloudtrail.record;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.IamService.CallerArns;
import io.github.hectorvent.floci.services.iam.IamService.SessionContextInfo;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.regex.Pattern;

/**
 * The {@code userIdentity} of a CloudTrail record, in the forms the CloudTrail userIdentity
 * element reference documents: {@code Root}, {@code IAMUser}, {@code AssumedRole},
 * {@code FederatedUser}, {@code AWSService} and {@code Unknown}.
 *
 * <p>Floci's root stand-in keys, {@code test} and a 12-digit account id, are the account root.
 * Every other key is resolved through IAM: a user's long-term key, an assumed-role session, a
 * GetFederationToken session, or a GetSessionToken session, which acts as the identity that minted
 * it and so takes that identity's form with a {@code sessionContext}.
 */
@ApplicationScoped
public class UserIdentityBuilder {

    private static final Pattern ACCOUNT_ID = Pattern.compile("\\d{12}");

    private final IamService iamService;
    private final RegionResolver regionResolver;
    private final ObjectMapper mapper;

    @Inject
    public UserIdentityBuilder(IamService iamService, RegionResolver regionResolver, ObjectMapper mapper) {
        this.iamService = iamService;
        this.regionResolver = regionResolver;
        this.mapper = mapper;
    }

    /** The identity of a request signed with {@code accessKeyId}; an unsigned request is the account root. */
    public ObjectNode forAccessKey(String accessKeyId) {
        if (accessKeyId == null || accessKeyId.isEmpty()) {
            return root(regionResolver.getAccountId(), null);
        }
        if ("test".equals(accessKeyId) || ACCOUNT_ID.matcher(accessKeyId).matches()) {
            return root(ACCOUNT_ID.matcher(accessKeyId).matches() ? accessKeyId : regionResolver.getAccountId(),
                    accessKeyId);
        }
        CallerArns caller = iamService.resolveCallerArns(accessKeyId).orElse(null);
        if (caller == null || caller.principalType() == null) {
            return unknown(accessKeyId);
        }
        String accountId = AwsArnUtils.accountOrDefault(caller.callerArn(), regionResolver.getAccountId());
        SessionContextInfo session = IamService.isTemporaryAccessKey(accessKeyId)
                ? iamService.findSessionContext(accessKeyId).orElse(null) : null;
        ObjectNode identity = switch (caller.principalType()) {
            case CallerArns.TYPE_ACCOUNT -> root(accountId, accessKeyId);
            case CallerArns.TYPE_USER -> principal("IAMUser", caller.userId(), caller.callerArn(), accountId,
                    accessKeyId, caller.userName());
            case CallerArns.TYPE_ASSUMED_ROLE -> principal("AssumedRole", caller.userId(), caller.callerArn(),
                    accountId, accessKeyId, null);
            case CallerArns.TYPE_FEDERATED_USER -> principal("FederatedUser", caller.userId(),
                    caller.callerArn(), accountId, accessKeyId, null);
            default -> null;
        };
        if (identity == null) {
            return unknown(accessKeyId);
        }
        if (session != null) {
            identity.set("sessionContext", sessionContext(caller, session));
        }
        return identity;
    }

    /** The identity of an action an AWS service took on its own, such as CloudTrail writing its log files. */
    public ObjectNode forService(String servicePrincipal) {
        ObjectNode identity = mapper.createObjectNode();
        identity.put("type", "AWSService");
        identity.put("invokedBy", servicePrincipal);
        return identity;
    }

    private ObjectNode unknown(String accessKeyId) {
        ObjectNode identity = mapper.createObjectNode();
        identity.put("type", "Unknown");
        identity.put("accessKeyId", accessKeyId);
        return identity;
    }

    private ObjectNode root(String accountId, String accessKeyId) {
        ObjectNode identity = mapper.createObjectNode();
        identity.put("type", "Root");
        identity.put("principalId", accountId);
        identity.put("arn", regionResolver.buildGlobalArn("iam", accountId, "root"));
        identity.put("accountId", accountId);
        if (accessKeyId != null) {
            identity.put("accessKeyId", accessKeyId);
        }
        return identity;
    }

    private ObjectNode principal(String type, String principalId, String arn, String accountId,
                                 String accessKeyId, String userName) {
        ObjectNode identity = mapper.createObjectNode();
        identity.put("type", type);
        identity.put("principalId", principalId);
        identity.put("arn", arn);
        identity.put("accountId", accountId);
        identity.put("accessKeyId", accessKeyId);
        if (userName != null) {
            identity.put("userName", userName);
        }
        return identity;
    }

    private ObjectNode sessionContext(CallerArns caller, SessionContextInfo session) {
        ObjectNode context = mapper.createObjectNode();
        ObjectNode issuer = context.putObject("sessionIssuer");
        if (CallerArns.TYPE_ASSUMED_ROLE.equals(caller.principalType())) {
            String roleArn = caller.principalArn();
            String userId = caller.userId() == null ? "" : caller.userId();
            issuer.put("type", "Role");
            issuer.put("principalId", userId.contains(":") ? userId.substring(0, userId.indexOf(':')) : userId);
            issuer.put("arn", roleArn);
            issuer.put("accountId", AwsArnUtils.accountOrDefault(roleArn, regionResolver.getAccountId()));
            issuer.put("userName", roleArn.substring(roleArn.lastIndexOf('/') + 1));
        } else if (CallerArns.TYPE_FEDERATED_USER.equals(caller.principalType()) && session.issuerArn() != null) {
            String issuerArn = session.issuerArn();
            String issuerAccount = AwsArnUtils.accountOrDefault(issuerArn, regionResolver.getAccountId());
            boolean rootIssuer = "root".equals(AwsArnUtils.parse(issuerArn).resource());
            issuer.put("type", rootIssuer ? "Root" : "IAMUser");
            issuer.put("principalId", rootIssuer ? issuerAccount : session.issuerUserId());
            issuer.put("arn", issuerArn);
            issuer.put("accountId", issuerAccount);
            if (!rootIssuer) {
                issuer.put("userName", issuerArn.substring(issuerArn.lastIndexOf('/') + 1));
            }
        }
        context.putObject("webIdFederationData");
        ObjectNode attributes = context.putObject("attributes");
        Instant created = session.creationDate() == null ? Instant.now() : session.creationDate();
        attributes.put("creationDate", DateTimeFormatter.ISO_INSTANT.format(created.truncatedTo(ChronoUnit.SECONDS)));
        attributes.put("mfaAuthenticated", "false");
        return context;
    }
}
