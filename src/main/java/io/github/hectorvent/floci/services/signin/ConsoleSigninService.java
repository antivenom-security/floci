package io.github.hectorvent.floci.services.signin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsPartition;
import io.github.hectorvent.floci.core.common.AwsPartitions;
import io.github.hectorvent.floci.core.common.Base64Url;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.RequestHost;
import io.github.hectorvent.floci.core.common.RequestScopes;
import io.github.hectorvent.floci.core.common.ServicePrincipals;
import io.github.hectorvent.floci.core.common.Totp;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailCaptureFilter;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailRecorder;
import io.github.hectorvent.floci.services.cloudtrail.record.CloudTrailEvent;
import io.github.hectorvent.floci.services.cloudtrail.record.CloudTrailRecordBuilder;
import io.github.hectorvent.floci.services.cloudtrail.record.TlsDetails;
import io.github.hectorvent.floci.services.cloudtrail.record.UserIdentityBuilder;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.IamService.CallerArns;
import io.github.hectorvent.floci.services.iam.model.IamUser;
import io.github.hectorvent.floci.services.iam.model.VirtualMfaDevice;
import io.vertx.core.http.HttpServerRequest;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Console sign-in, which Floci has no console for: a password sign-in for IAM users and AWS's
 * custom identity broker federation endpoint for role and federated sessions. Each attempt is
 * recorded as AWS records it, an {@code AwsConsoleSignIn} event from {@code signin.amazonaws.com}
 * that goes to event history, trails and EventBridge like any management event.
 *
 * <p>The region follows AWS's rule: the region of a regional sign-in host
 * ({@code us-west-2.signin.aws.amazon.com}), otherwise the global endpoint's.
 */
@ApplicationScoped
public class ConsoleSigninService {

    static final String SUCCESS = "Success";
    static final String FAILURE = "Failure";
    static final long SIGNIN_TOKEN_TTL_SECONDS = 15 * 60;
    static final int MIN_SESSION_DURATION = 900;
    static final int MAX_SESSION_DURATION = 43_200;
    private static final Pattern ACCOUNT_ID = Pattern.compile("\\d{12}");
    private static final int MFA_DRIFT_STEPS = 1;

    private final IamService iamService;
    private final RegionResolver regionResolver;
    private final CloudTrailRecordBuilder recordBuilder;
    private final UserIdentityBuilder userIdentityBuilder;
    private final CloudTrailRecorder recorder;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final boolean trustForwardedFor;
    private final SecureRandom random = new SecureRandom();
    private final ConcurrentHashMap<String, SigninToken> signinTokens = new ConcurrentHashMap<>();

    private record SigninToken(String accessKeyId, String accountId, Instant expiresAt) {
    }

    @Inject
    public ConsoleSigninService(IamService iamService, RegionResolver regionResolver,
                                CloudTrailRecordBuilder recordBuilder, UserIdentityBuilder userIdentityBuilder,
                                CloudTrailRecorder recorder, ObjectMapper mapper, Clock clock, EmulatorConfig config) {
        this.iamService = iamService;
        this.regionResolver = regionResolver;
        this.recordBuilder = recordBuilder;
        this.userIdentityBuilder = userIdentityBuilder;
        this.recorder = recorder;
        this.mapper = mapper;
        this.clock = clock;
        this.trustForwardedFor = config.services().cloudtrail().trustForwardedFor();
    }

    /**
     * Signs an IAM user in to {@code account} (an ID or alias) with the user's login profile
     * password and, when the user has an MFA device, its current code. An unknown account is a
     * failure with no record, as there is no account to deliver it to.
     */
    public boolean consoleLogin(String account, String userName, String password, String mfaCode,
                                HttpServerRequest request) {
        String accountId = account == null ? null
                : ACCOUNT_ID.matcher(account).matches() ? account : iamService.findAccountByAlias(account).orElse(null);
        if (accountId == null) {
            return false;
        }
        String region = region(request);
        return RequestScopes.callAs(accountId, region,
                () -> passwordLogin(accountId, region, userName, password, mfaCode, request));
    }

    private boolean passwordLogin(String accountId, String region, String userName, String password, String mfaCode,
                                  HttpServerRequest request) {
        IamUser user = userName == null ? null : iamService.findUser(accountId, userName).orElse(null);
        if (user == null) {
            ObjectNode identity = mapper.createObjectNode();
            identity.put("type", "IAMUser");
            identity.put("accountId", accountId);
            identity.put("accessKeyId", "");
            identity.put("userName", CloudTrailRecordBuilder.HIDDEN);
            consoleLogin(region, accountId, identity, request, false, null, false);
            return false;
        }
        if (!passwordMatches(userName, password)) {
            consoleLogin(region, accountId, attemptIdentity(user, accountId), request, false, null, false);
            return false;
        }
        List<VirtualMfaDevice> devices = iamService.listMfaDevices(userName);
        if (devices.isEmpty()) {
            consoleLogin(region, accountId, signedInIdentity(user, accountId), request, true, null, false);
            return true;
        }
        ObjectNode checked = mapper.createObjectNode().put("CheckMfa", SUCCESS);
        record("CheckMfa", region, accountId, attemptIdentity(user, accountId), request, checked,
                mapper.createObjectNode().put("MfaType", "Virtual MFA"), null);
        if (mfaCode == null || mfaCode.isEmpty()) {
            // AWS writes ConsoleLogin only once the MFA step is answered.
            return false;
        }
        Instant now = Instant.now();
        VirtualMfaDevice device = devices.stream()
                .filter(d -> Totp.matchesCode(d.getBase32Seed(), mfaCode, MFA_DRIFT_STEPS, now))
                .findFirst().orElse(null);
        if (device == null) {
            consoleLogin(region, accountId, attemptIdentity(user, accountId), request, false, null, true);
            return false;
        }
        consoleLogin(region, accountId, signedInIdentity(user, accountId), request, true,
                device.getSerialNumber(), true);
        return true;
    }

    private boolean passwordMatches(String userName, String password) {
        if (password == null) {
            return false;
        }
        try {
            return MessageDigest.isEqual(iamService.getLoginProfile(userName).getPassword()
                    .getBytes(StandardCharsets.UTF_8), password.getBytes(StandardCharsets.UTF_8));
        } catch (AwsException e) {
            return false;
        }
    }

    /**
     * A sign-in token for the role or federated session the {@code Session} JSON names
     * ({@code sessionId}, {@code sessionKey}, {@code sessionToken}), or null when it names no live
     * AssumeRole or GetFederationToken session or {@code sessionDuration} is not allowed for it.
     */
    public String getSigninToken(String sessionJson, String sessionDuration, HttpServerRequest request) {
        JsonNode session = parse(sessionJson);
        String accessKeyId = session.path("sessionId").asText("");
        String secretKey = session.path("sessionKey").asText("");
        String sessionToken = session.path("sessionToken").asText(null);
        if (!IamService.isTemporaryAccessKey(accessKeyId)) {
            return null;
        }
        String accountId = iamService.findAccountForAccessKeyId(accessKeyId).orElse(null);
        if (accountId == null) {
            return null;
        }
        String region = region(request);
        return RequestScopes.callAs(accountId, region, () -> {
            String secret = iamService.findSecretKey(accessKeyId, sessionToken).orElse(null);
            String type = iamService.resolveCallerArns(accessKeyId).map(CallerArns::principalType).orElse(null);
            boolean role = CallerArns.TYPE_ASSUMED_ROLE.equals(type);
            if (secret == null || !MessageDigest.isEqual(secret.getBytes(StandardCharsets.UTF_8),
                    secretKey.getBytes(StandardCharsets.UTF_8))
                    || !(role || CallerArns.TYPE_FEDERATED_USER.equals(type))
                    || (sessionDuration != null && (!role || !validSessionDuration(sessionDuration)))) {
                return null;
            }
            Instant now = clock.instant();
            signinTokens.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
            byte[] bytes = new byte[96];
            random.nextBytes(bytes);
            String token = Base64Url.encode(bytes);
            signinTokens.put(token, new SigninToken(accessKeyId, accountId,
                    now.plusSeconds(SIGNIN_TOKEN_TTL_SECONDS)));
            ObjectNode response = mapper.createObjectNode();
            response.putObject("credentials").put("accessKeyId", accessKeyId);
            response.put("GetSigninToken", SUCCESS);
            record("GetSigninToken", region, accountId, userIdentityBuilder.forAccessKey(accessKeyId), request,
                    response, federatedSignInData(), null);
            return token;
        });
    }

    /** Redeems a sign-in token once, within 15 minutes and while its session lasts. */
    public boolean login(String token, HttpServerRequest request) {
        SigninToken signin = token == null ? null : signinTokens.remove(token);
        Instant now = clock.instant();
        if (signin == null || !signin.expiresAt().isAfter(now)
                || iamService.findSecretKey(signin.accessKeyId()).isEmpty()) {
            return false;
        }
        String region = region(request);
        RequestScopes.runAs(signin.accountId(), region, () -> record("ConsoleLogin", region, signin.accountId(),
                userIdentityBuilder.forAccessKey(signin.accessKeyId()), request,
                mapper.createObjectNode().put("ConsoleLogin", SUCCESS), federatedSignInData(), null));
        return true;
    }

    private static boolean validSessionDuration(String value) {
        try {
            int seconds = Integer.parseInt(value);
            return seconds >= MIN_SESSION_DURATION && seconds <= MAX_SESSION_DURATION;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private JsonNode parse(String json) {
        try {
            JsonNode node = json == null ? null : mapper.readTree(json);
            return node == null ? mapper.createObjectNode() : node;
        } catch (JsonProcessingException e) {
            return mapper.createObjectNode();
        }
    }

    private ObjectNode federatedSignInData() {
        ObjectNode data = mapper.createObjectNode();
        data.put("MobileVersion", "No");
        data.put("MFAUsed", "No");
        return data;
    }

    private void consoleLogin(String region, String accountId, ObjectNode identity, HttpServerRequest request,
                              boolean success, String mfaIdentifier, boolean mfaUsed) {
        ObjectNode data = mapper.createObjectNode();
        AwsPartition partition = AwsPartitions.byId(regionResolver.getPartition());
        if (partition.signinHost() != null) {
            data.put("LoginTo", "https://" + partition.signinHost().replace("{region}.signin.", "console.")
                    + "/console/home");
        }
        data.put("MobileVersion", "No");
        if (mfaIdentifier != null) {
            data.put("MFAIdentifier", mfaIdentifier);
        }
        data.put("MFAUsed", mfaUsed ? "Yes" : "No");
        record("ConsoleLogin", region, accountId, identity, request,
                mapper.createObjectNode().put("ConsoleLogin", success ? SUCCESS : FAILURE), data,
                success ? null : "Failed authentication");
    }

    private void record(String eventName, String region, String accountId, ObjectNode identity,
                        HttpServerRequest request, ObjectNode response, ObjectNode additionalEventData,
                        String errorMessage) {
        recorder.record(recordBuilder.build(CloudTrailEvent.builder()
                .eventSource(ServicePrincipals.of("signin"))
                .eventName(eventName)
                .awsRegion(region)
                .eventTime(Instant.now())
                .userIdentity(identity)
                .sourceIPAddress(CloudTrailCaptureFilter.sourceIp(request, trustForwardedFor))
                .userAgent(request.getHeader("User-Agent"))
                .errorMessage(errorMessage)
                .responseElements(response)
                .additionalEventData(additionalEventData)
                .tlsDetails(TlsDetails.of(request))
                .recipientAccountId(accountId)
                .eventType(CloudTrailRecordBuilder.CONSOLE_SIGN_IN)
                .build()));
    }

    /** The identity of a signed-in IAM user: AWS's success records carry its ARN and no access key. */
    private ObjectNode signedInIdentity(IamUser user, String accountId) {
        ObjectNode identity = mapper.createObjectNode();
        identity.put("type", "IAMUser");
        identity.put("principalId", user.getUserId());
        identity.put("arn", user.getArn());
        identity.put("accountId", accountId);
        identity.put("userName", user.getUserName());
        return identity;
    }

    /** The identity of a known IAM user's attempt that has not signed in (yet): no ARN, an empty access key. */
    private ObjectNode attemptIdentity(IamUser user, String accountId) {
        ObjectNode identity = mapper.createObjectNode();
        identity.put("type", "IAMUser");
        identity.put("principalId", user.getUserId());
        identity.put("accountId", accountId);
        identity.put("accessKeyId", "");
        identity.put("userName", user.getUserName());
        return identity;
    }

    /** The region of a regional sign-in host, else the partition's global one, as AWS records it. */
    private String region(HttpServerRequest request) {
        AwsPartition partition = AwsPartitions.byId(regionResolver.getPartition());
        String host = RequestHost.of(request);
        if (host != null) {
            host = host.replaceFirst(":\\d+$", "");
        }
        return host != null && SigninService.isSigninHost(host, partition)
                ? host.substring(0, host.indexOf('.')) : partition.implicitGlobalRegion();
    }
}
