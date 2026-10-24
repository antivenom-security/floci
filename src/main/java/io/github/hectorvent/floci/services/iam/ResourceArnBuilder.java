package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.AwsQueryServiceResolver;
import io.github.hectorvent.floci.core.common.AwsRegions;
import io.github.hectorvent.floci.core.common.ServicePrincipals;
import io.github.hectorvent.floci.core.common.SigV4CredentialScope;
import io.github.hectorvent.floci.services.cloudwatch.logs.LogGroupTagTarget;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ecs.EcsService;
import io.github.hectorvent.floci.services.lambda.LambdaArnUtils;
import io.github.hectorvent.floci.services.lambda.durable.DurableTokens;
import io.github.hectorvent.floci.services.lambdamicrovms.LambdaMicrovmsService;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Constructs the target resource ARN for a request so the policy evaluator
 * can match it against Resource patterns in policy documents.
 *
 * Returns {@code *} when the resource cannot be determined, which matches
 * permissive wildcard policies.
 */
@ApplicationScoped
public class ResourceArnBuilder {

    /** The only scheme IAM accepts on an OIDC provider URL, and the part its ARN drops. */
    private static final String OIDC_URL_SCHEME = "https://";

    /** What a service-linked role deletion task identifier starts with; see its resolver. */
    private static final String DELETION_TASK_PREFIX = "task" + ServiceLinkedRoles.PATH;

    /** Reads the CBOR bodies the RPC v2 and {@code x-amz-cbor-1.1} paths carry. */
    private static final ObjectMapper CBOR_MAPPER = new ObjectMapper(new CBORFactory());

    /**
     * Stands in for the random suffix of a secret that {@code CreateSecret} has not made yet. Each
     * {@code ?} matches the one character a {@code secret:<name>-??????} policy expects there.
     */
    private static final String UNASSIGNED_SECRET_SUFFIX = "-??????";

    private final ObjectMapper objectMapper;
    /**
     * Looked up lazily through a provider: this builder is constructed by the enforcement filter,
     * which IamService itself does not depend on, and a direct injection would close that loop.
     */
    private final Instance<IamService> iamService;
    /** Looked up lazily for the same reason, to resolve a secret named by its name or a partial ARN. */
    private final Instance<SecretsManagerService> secretsManagerService;
    /** Looked up lazily for the same reason, to read the image a MicroVM runs. */
    private final Instance<LambdaMicrovmsService> microvmsService;
    /** Looked up lazily for the same reason, to find the ECS resource a request acts on. */
    private final Instance<EcsService> ecsService;
    /** Looked up lazily for the same reason, to read the groups a launch template gives an instance. */
    private final Instance<Ec2Service> ec2Service;

    @Inject
    public ResourceArnBuilder(ObjectMapper objectMapper, Instance<IamService> iamService,
                              Instance<SecretsManagerService> secretsManagerService,
                              Instance<LambdaMicrovmsService> microvmsService,
                              Instance<EcsService> ecsService, Instance<Ec2Service> ec2Service) {
        this.objectMapper = objectMapper;
        this.iamService = iamService;
        this.secretsManagerService = secretsManagerService;
        this.microvmsService = microvmsService;
        this.ecsService = ecsService;
        this.ec2Service = ec2Service;
    }

    public ResourceArnBuilder(ObjectMapper objectMapper, Instance<IamService> iamService,
                              Instance<SecretsManagerService> secretsManagerService,
                              Instance<LambdaMicrovmsService> microvmsService) {
        this(objectMapper, iamService, secretsManagerService, microvmsService, null, null);
    }

    public ResourceArnBuilder(ObjectMapper objectMapper, Instance<IamService> iamService,
                              Instance<SecretsManagerService> secretsManagerService) {
        this(objectMapper, iamService, secretsManagerService, null);
    }

    ResourceArnBuilder(ObjectMapper objectMapper, Instance<IamService> iamService) {
        this(objectMapper, iamService, null);
    }

    public ResourceArnBuilder() {
        this(new ObjectMapper(), null, null);
    }

    public ResourceArnBuilder(ObjectMapper objectMapper) {
        this(objectMapper, null, null);
    }

    public String build(String credentialScope, ContainerRequestContext ctx,
                        String region, String accountId) {
        List<String> list = buildResources(credentialScope, ctx, region, accountId);
        return list.isEmpty() ? "*" : list.getFirst();
    }

    public List<String> buildResources(String credentialScope, ContainerRequestContext ctx,
                                       String region, String accountId) {
        return buildResources(credentialScope, ctx, region, accountId, AwsRegions.partitionFor(region));
    }

    /**
     * The resources a request is checked against. Scheduler and Pipes ARNs are minted in {@code partition},
     * the request's, as those services mint theirs, so a Region no partition publishes gets the deployment's
     * partition rather than {@code aws}.
     */
    public List<String> buildResources(String credentialScope, ContainerRequestContext ctx,
                                       String region, String accountId, String partition) {
        if (credentialScope == null) {
            return List.of("*");
        }
        String path = ctx.getUriInfo().getPath();
        return switch (credentialScope) {
            case "s3"             -> List.of(buildS3Arn(path, region));
            case "lambda"         -> List.of(buildLambdaArn(path, ctx, region, accountId));
            case "sqs"            -> List.of(buildSqsArn(ctx, region, accountId));
            case "sns"            -> List.of(buildSnsArn(ctx, region, accountId));
            case "dynamodb"       -> buildDynamoDbArns(ctx, region, accountId);
            case "kinesis"        -> List.of(buildKinesisArn(ctx, region, accountId));
            case "ssm"            -> List.of(buildSsmArn(ctx, region, accountId));
            case "kms"            -> List.of(buildKmsArn(path, region, accountId));
            case "iam"            -> buildIamArns(ctx, region, accountId);
            case "resource-groups" -> List.of(buildResourceGroupArn(ctx, region, accountId));
            case "scheduler"      -> List.of(buildSchedulerArn(path, ctx, region, accountId, partition));
            case "pipes"          -> List.of(buildPipesArn(path, ctx, region, accountId, partition));
            case "ecs"            -> buildEcsArns(ctx, region, accountId, partition);
            case "ec2"            -> buildEc2Arns(ctx, region, accountId, partition);
            default               -> List.of("*");
        };
    }

    private String buildResourceGroupArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode body = readJsonBody(ctx);
        if (body == null) {
            return "*";
        }
        String path = ctx.getUriInfo().getPath();
        boolean create = path.endsWith("/groups") || path.endsWith("/groups/");
        String group = create ? body.path("Name").asText()
                : body.path("Group").asText(body.path("GroupName").asText());
        if (group.isEmpty()) {
            return "*";
        }
        return group.startsWith("arn:") ? group
                : AwsArnUtils.Arn.of("resource-groups", region, accountId, "group/" + group).toString();
    }

    /** Uses the serving operation and the same raw names as the handler. */
    public List<String> buildLogResources(String action, ContainerRequestContext ctx,
                                          String region, String accountId, String partition) {
        boolean stream = "logs:CreateLogStream".equals(action) || "logs:DeleteLogStream".equals(action);
        boolean group = switch (action) {
            case "logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy",
                    "logs:DeleteRetentionPolicy" -> true;
            default -> false;
        };
        if (!stream && !group && !LogGroupTagTarget.supports(action)) {
            return List.of("*");
        }
        JsonNode body = readJsonBody(ctx);
        if (body == null) {
            return List.of("*");
        }
        if (LogGroupTagTarget.supports(action)) {
            return List.of(LogGroupTagTarget.resolve(body.path("resourceArn").asText(), region, accountId, partition).arn());
        }
        String name = body.path("logGroupName").asText();
        String resource = "log-group:" + name + (stream
                ? ":log-stream:" + body.path("logStreamName").asText() : ":*");
        return List.of(new AwsArnUtils.Arn(partition, "logs", region, accountId, resource).toString());
    }

    // ── IAM ─────────────────────────────────────────────────────────────────────

    /** A stored entity's ARN and path, the two things a target ARN is built from. */
    private record StoredEntity(String arn, String path) {}

    /**
     * The request parameter carrying the name of the target, per resource type, for an action on a
     * resource that already exists.
     *
     * <p>Which type an action is authorized against is not decided here: it comes per action from
     * {@link IamActionResources}, which vendors AWS's own authorization metadata, because the
     * resource an IAM action acts on is not in the request. {@code AddUserToGroup} carries a
     * {@code UserName} and a {@code GroupName} and is authorized against the group,
     * {@code AddRoleToInstanceProfile} carries a {@code RoleName} and is authorized against the
     * instance profile, and the MFA actions that take a {@code SerialNumber} are authorized
     * against the user that device belongs to. Keeping the type in vendored data and only the
     * parameter here is what lets {@code make iam-action-resources-verify} check the half that is
     * AWS's against AWS.
     *
     * <p>An action whose type is not in here, and which is not a create or one of the ARN-carrying
     * actions, is evaluated against {@code *}. That is right for the types the reference gives
     * actions Floci does not dispatch, which {@link #UNRESOLVED_TYPES} names.
     */
    static final Map<String, String> NAME_PARAMETERS = Map.of(
            "user", "UserName",
            "role", "RoleName",
            "group", "GroupName",
            "instance-profile", "InstanceProfileName",
            "server-certificate", "ServerCertificateName");

    /**
     * The actions that create their target, with the parameter naming it. Their ARN is minted from
     * the request rather than read back, since there is no stored record yet, and a create is
     * checked against the {@code Path} it asks for, because reading a stored path would authorize
     * a create into a path the policy does not name.
     *
     * <p>Keyed by action rather than by type because a create spells the name its own way:
     * {@code CreateSAMLProvider} takes {@code Name} and {@code CreateOpenIDConnectProvider} takes
     * {@code Url}, where the others take the type's usual parameter. The type itself still comes
     * from the vendored metadata.
     *
     * <p>Package-private, as the other tables here are, so {@code IamActionResourcesTest} can
     * work out which resource types this class covers instead of restating them, which is what
     * catches both a create AWS gives no single type to mint and a type nothing resolves.
     */
    static final Map<String, String> CREATE_PARAMETERS = Map.of(
            "CreateUser", "UserName",
            "CreateRole", "RoleName",
            "CreateGroup", "GroupName",
            "CreateInstanceProfile", "InstanceProfileName",
            "UploadServerCertificate", "ServerCertificateName",
            "CreatePolicy", "PolicyName",
            "CreateVirtualMFADevice", "VirtualMFADeviceName",
            "CreateSAMLProvider", "Name",
            "CreateOpenIDConnectProvider", "Url");

    /**
     * The resource types AWS gives IAM actions that Floci does not resolve, with why. Every one
     * belongs to an action the handler does not dispatch, so there is no request to name a
     * resource for.
     *
     * <p>Declared rather than implied so that a type which is neither resolved nor listed here
     * fails a test naming it, instead of quietly putting that action back on {@code *}. The
     * resolver's fallback for a type it does not know is the permissive answer, so a regeneration
     * that introduces one is only visible if something asserts the set.
     *
     * <p>Package-private because the reason each entry gives is a claim about the handler, not
     * about this class: {@code UnresolvedResourceTypesIntegrationTest} sends each of these actions
     * and holds it to answering {@code UnsupportedOperation}. Dispatching one without resolving
     * its type would leave it evaluated against {@code *}, which is the fail-open this class
     * exists to close.
     */
    static final Map<String, String> UNRESOLVED_TYPES = Map.of(
            "role-template", "GetRoleTemplateVersion is not dispatched");

    /**
     * The IAM actions whose target the request carries as an ARN, and the parameter holding it.
     * Passed through rather than rebuilt: the ARN is the caller's own naming of the resource, and
     * an action naming one that does not exist fails as {@code NoSuchEntity} regardless of what a
     * policy says.
     *
     * <p>This is also the answer for every action AWS gives more than one resource type. The four
     * that take a principal ARN are authorized against whichever of user, role or group that ARN
     * names, and {@code DeleteVirtualMFADevice} against either {@code mfa} or {@code sms-mfa}, so
     * the parameter is the resource and there is nothing to choose.
     */
    static final Map<String, String> IAM_ARN_PARAMETERS = iamArnParameters();

    /**
     * The actions resolved by a branch of their own in {@link #buildIamArns}, because what the
     * request carries is not an IAM entity's name: a service principal for
     * {@code CreateServiceLinkedRole}, an access key id for {@code GetAccessKeyLastUsed}, a
     * deletion task id for {@code GetServiceLinkedRoleDeletionStatus}, an Organizations
     * entity path for {@code GenerateOrganizationsAccessReport}, whose resource lives in another
     * service's tree, and a request id for the five delegation actions that name one.
     *
     * <p>The resolver is the value rather than a branch elsewhere, so this cannot become a list
     * that says an action is handled while the dispatch has nothing for it. The keys are also what
     * {@code IamActionResourcesTest} reads to tell a type one of these covers from a type nothing
     * resolves.
     */
    static final Map<String, DerivedResolver> DERIVED_RESOLVERS = Map.of(
            "CreateServiceLinkedRole", ResourceArnBuilder::serviceLinkedRoleArn,
            "GetAccessKeyLastUsed",
            (self, ctx, region, accountId) -> self.accessKeyOwnerArn(ctx, accountId),
            "GetServiceLinkedRoleDeletionStatus", ResourceArnBuilder::deletionTaskRoleArn,
            "GenerateOrganizationsAccessReport",
            ResourceArnBuilder::organizationsAccessReportArn,
            "AssociateDelegationRequest", ResourceArnBuilder::delegationRequestArn,
            "AcceptDelegationRequest", ResourceArnBuilder::delegationRequestArn,
            "RejectDelegationRequest", ResourceArnBuilder::delegationRequestArn,
            "GetDelegationRequest", ResourceArnBuilder::delegationRequestArn,
            "SendDelegationToken", ResourceArnBuilder::delegationRequestArn);

    /** How one of {@link #DERIVED_RESOLVERS} reads its resource out of the request. */
    interface DerivedResolver {
        List<String> resolve(ResourceArnBuilder self, ContainerRequestContext ctx, String region,
                             String accountId);
    }

    /**
     * The actions that rename or move their target, and the parameter carrying the new name. These
     * name two resources, because AWS requires the principal to be allowed on both: UpdateUser's
     * reference says the requester "must have appropriate permissions on both the source object
     * and the target object", and UpdateGroup's that a principal allowed to update the old group
     * but not the new one has the update fail. The filter authorizes a request once per resource,
     * so naming both is what enforces it.
     */
    private static final Map<String, String> IAM_RENAME_PARAMETERS = Map.of(
            "UpdateUser", "NewUserName",
            "UpdateGroup", "NewGroupName",
            "UpdateServerCertificate", "NewServerCertificateName");

    private static Map<String, String> iamArnParameters() {
        Map<String, String> parameters = new LinkedHashMap<>();
        arnParameter(parameters, "PolicyArn",
                "CreatePolicyVersion", "DeletePolicy", "DeletePolicyVersion", "GetPolicy",
                "GetPolicyVersion", "ListEntitiesForPolicy", "ListPolicyTags", "ListPolicyVersions",
                "SetDefaultPolicyVersion", "TagPolicy", "UntagPolicy");
        arnParameter(parameters, "SerialNumber",
                "DeleteVirtualMFADevice", "ListMFADeviceTags", "TagMFADevice", "UntagMFADevice");
        arnParameter(parameters, "SAMLProviderArn",
                "DeleteSAMLProvider", "GetSAMLProvider", "ListSAMLProviderTags", "TagSAMLProvider",
                "UntagSAMLProvider", "UpdateSAMLProvider");
        arnParameter(parameters, "OpenIDConnectProviderArn",
                "AddClientIDToOpenIDConnectProvider", "DeleteOpenIDConnectProvider",
                "GetOpenIDConnectProvider", "ListOpenIDConnectProviderTags",
                "RemoveClientIDFromOpenIDConnectProvider", "TagOpenIDConnectProvider",
                "UntagOpenIDConnectProvider", "UpdateOpenIDConnectProviderThumbprint");
        arnParameter(parameters, "Arn",
                "GenerateServiceLastAccessedDetails", "ListPoliciesGrantingServiceAccess");
        arnParameter(parameters, "PolicySourceArn",
                "GetContextKeysForPrincipalPolicy", "SimulatePrincipalPolicy");
        return Map.copyOf(parameters);
    }

    private static void arnParameter(Map<String, String> parameters, String parameter,
                                     String... actions) {
        for (String action : actions) {
            parameters.put(action, parameter);
        }
    }

    /**
     * The resource ARN an IAM action is evaluated against, so a policy statement naming one user,
     * role, group, profile, policy, provider, MFA device or certificate binds to it and to nothing
     * else. Everything this cannot name resolves to {@code *}, which is the permissive answer and
     * the one AWS gives for the actions that take no resource.
     *
     * <p>The operation is resolved through {@link AwsQueryServiceResolver#action(String, String)},
     * so the legacy {@code Operation} parameter names the resource exactly as {@code Action} does.
     * Reading {@code Action} alone would let a caller spell the operation the other way and have
     * the request evaluated against {@code *}, skipping a deny that names the resource.
     *
     * <p>An action that defaults to the calling user when its {@code UserName} is omitted, as
     * {@code GetUser} and {@code ChangePassword} do, resolves to that user: the access key id in
     * the credential names the identity, and the stored ARN carries its path and partition. The
     * wildcard stands only when the signer is not an IAM user, an account's root stand-in and a
     * session credential having no user record to name.
     */
    private List<String> buildIamArns(ContainerRequestContext ctx, String region,
                                      String accountId) {
        String action = AwsQueryServiceResolver.action(
                RequestBodyReader.formField(ctx, "Action"),
                RequestBodyReader.formField(ctx, "Operation"));
        if (action == null) {
            return List.of("*");
        }
        String arnParameter = IAM_ARN_PARAMETERS.get(action);
        if (arnParameter != null) {
            // Only an ARN is passed through. A hardware MFA device's SerialNumber is a bare serial
            // rather than an ARN, and naming the request after it would produce a resource no
            // policy can be written against.
            String arn = RequestBodyReader.formField(ctx, arnParameter);
            return arn == null || !AwsArnUtils.isArn(arn) ? List.of("*") : List.of(arn);
        }
        DerivedResolver derived = DERIVED_RESOLVERS.get(action);
        if (derived != null) {
            return derived.resolve(this, ctx, region, accountId);
        }
        String createParameter = CREATE_PARAMETERS.get(action);
        if (createParameter != null) {
            // A create names a resource that does not exist yet, so its ARN is minted from the
            // request: the path it asks for, in the partition it is being created in. Reading a
            // stored path here would authorize a create under /team/ against the root path.
            String created = RequestBodyReader.formField(ctx, createParameter);
            List<String> createdTypes = IamActionResources.typesOf(action);
            // One type is what there is to mint. A create AWS authorizes against none, or against
            // several, has no single ARN to build, so the wildcard stands rather than the request
            // failing on it; IamActionResourcesTest is what says so out loud.
            if (created == null || created.isBlank() || createdTypes.size() != 1) {
                return List.of("*");
            }
            return List.of(mintedIamArn(createdTypes.get(0), created, ctx, region, accountId));
        }
        // Everything else is an action on a resource that exists, named by name. Which type that
        // is comes from AWS's own metadata, and the parameter the name arrives in comes from the
        // type: an action AWS gives a type this resolver has no parameter for, or more than one
        // type, is left at the wildcard rather than guessed at.
        String resourceType = nameableType(action);
        if (resourceType == null) {
            return List.of("*");
        }
        String name = RequestBodyReader.formField(ctx, NAME_PARAMETERS.get(resourceType));
        if (name == null || name.isBlank()) {
            // Nineteen user actions make UserName optional, and AWS then acts on the user who
            // signed the request, so that user is the resource the request names. Resolving it
            // here is what lets a statement scoped to one user reach GetUser, ListAccessKeys and
            // the rest when they are called the way the console calls them, with no UserName.
            return "user".equals(resourceType) ? signingUserArn(ctx, accountId) : List.of("*");
        }
        // Every other action acts on a resource that already exists, so the check uses that
        // resource's own stored ARN instead of deriving one again. The stored ARN carries the path
        // and, more to the point, the partition the resource was created in: a resource stays in
        // its partition, so re-minting from the caller's signing region would name an ARN that no
        // resource has and leave a deny on the real one unmatched.
        Optional<StoredEntity> stored = storedIamEntity(resourceType, name, accountId);
        if (stored.isEmpty()) {
            return List.of("*");
        }
        String storedArn = stored.get().arn();
        String renameParameter = IAM_RENAME_PARAMETERS.get(action);
        if (renameParameter == null) {
            return List.of(storedArn);
        }
        String renamed = renameTargetArn(ctx, stored.get(), resourceType, name,
                renameParameter, region, accountId);
        return storedArn.equals(renamed) ? List.of(storedArn) : List.of(storedArn, renamed);
    }

    /**
     * The ARN a rename or a move would produce, built beside the stored ARN so it keeps the
     * resource's partition and account. Only the path and the name change, and taking the
     * partition from the caller's signing region instead would name a resource in a partition the
     * original does not live in. Returns the stored ARN unchanged when the request renames and
     * moves nothing.
     */
    private String renameTargetArn(ContainerRequestContext ctx, StoredEntity stored,
                                   String resourceType, String name, String renameParameter,
                                   String region, String accountId) {
        String newName = RequestBodyReader.formField(ctx, renameParameter);
        String newPath = RequestBodyReader.formField(ctx, "NewPath");
        String targetName = newName == null || newName.isBlank() ? name : newName;
        String targetPath = newPath == null || newPath.isBlank()
                ? normalizeArnPath(stored.path())
                : normalizeArnPath(newPath);
        String partition = AwsArnUtils.partitionOrDefault(stored.arn(),
                AwsRegions.partitionFor(region));
        String account = AwsArnUtils.accountOrDefault(stored.arn(), accountId);
        return AwsArnUtils.Arn.global(partition, "iam", account,
                resourceType + targetPath + targetName).toString();
    }

    /**
     * The ARN of a resource the request is creating. IAM is global, so it carries no region, and
     * it is minted in the request's partition rather than through a blank-region {@code Arn.of},
     * which would silently mean the commercial one.
     */
    private String mintedIamArn(String resourceType, String name, ContainerRequestContext ctx,
                                String region, String accountId) {
        String resource = switch (resourceType) {
            // A SAML provider's ARN is its bare name and an OIDC provider's is its URL without
            // the scheme, as IAM stores it. Neither format has a path, so Path is not read here.
            case "saml-provider" -> "saml-provider/" + name;
            case "oidc-provider" -> "oidc-provider/" + oidcProviderName(name);
            default -> resourceType
                    + normalizeArnPath(RequestBodyReader.formField(ctx, "Path")) + name;
        };
        return AwsArnUtils.Arn.global(AwsRegions.partitionFor(region), "iam", accountId, resource)
                .toString();
    }

    /**
     * The delegation request a by-id action names.
     *
     * <p>Minted from the request rather than read back: the id is the whole resource name, with no
     * path and no partition of its own to recover, and an id naming no request answers
     * {@code NoSuchEntity} whatever a policy says. That is the same reasoning the ARN-carrying
     * actions use, one step earlier, because this family passes an id where they pass an ARN.
     *
     * <p>{@code CreateDelegationRequest} is not here: IAM mints the id, so the request names no
     * resource and the wildcard is the honest answer. {@code UpdateDelegationRequest} is not here
     * either, AWS publishing no authorizable action for it at all, so it carries no type to
     * resolve.
     */
    private List<String> delegationRequestArn(ContainerRequestContext ctx, String region,
                                              String accountId) {
        String id = RequestBodyReader.formField(ctx, "DelegationRequestId");
        if (id == null || id.isBlank()) {
            return List.of("*");
        }
        return List.of(AwsArnUtils.Arn.global(AwsRegions.partitionFor(region), "iam", accountId,
                "delegation-request/" + id).toString());
    }

    /** An OIDC provider URL as its ARN carries it, which is the URL without its scheme. */
    private static String oidcProviderName(String url) {
        return url.startsWith(OIDC_URL_SCHEME) ? url.substring(OIDC_URL_SCHEME.length()) : url;
    }

    /**
     * The role {@code CreateServiceLinkedRole} would create. Its name is not in the request: AWS
     * derives it from {@code AWSServiceName}, so the table the create itself reads is read here
     * too, and the path is the service-role path carrying the canonical principal. A service with
     * no entry names no role, leaving nothing to authorize against but {@code *}.
     */
    private List<String> serviceLinkedRoleArn(ContainerRequestContext ctx, String region,
                                              String accountId) {
        String serviceName = RequestBodyReader.formField(ctx, "AWSServiceName");
        if (serviceName == null || serviceName.isBlank()) {
            return List.of("*");
        }
        Optional<String> baseName = ServiceLinkedRoles.roleName(serviceName);
        if (baseName.isEmpty()) {
            return List.of("*");
        }
        String suffix = RequestBodyReader.formField(ctx, "CustomSuffix");
        String roleName = baseName.get()
                + (suffix == null || suffix.isBlank() ? "" : "_" + suffix);
        String path = ServiceLinkedRoles.PATH + ServicePrincipals.canonical(serviceName) + "/";
        return List.of(AwsArnUtils.Arn.global(AwsRegions.partitionFor(region), "iam", accountId,
                "role" + path + roleName).toString());
    }

    /**
     * The role {@code GetServiceLinkedRoleDeletionStatus} asks about. The request names no role,
     * but the deletion task does: the action's own reference gives the identifier's format as
     * {@code task/aws-service-role/<service-principal-name>/<role-name>/<task-uuid>}, which is the
     * role's path and name with a prefix in front and a uuid behind, and that is the shape
     * {@code DeleteServiceLinkedRole} mints. Derived rather than looked up because by the time
     * this action is called the role is gone, so there is no stored ARN left to read.
     */
    private List<String> deletionTaskRoleArn(ContainerRequestContext ctx, String region,
                                             String accountId) {
        String taskId = RequestBodyReader.formField(ctx, "DeletionTaskId");
        if (taskId == null || !taskId.startsWith(DELETION_TASK_PREFIX)) {
            return List.of("*");
        }
        int uuidSeparator = taskId.lastIndexOf('/');
        if (uuidSeparator <= DELETION_TASK_PREFIX.length()) {
            return List.of("*");
        }
        String pathAndName = taskId.substring("task".length(), uuidSeparator);
        return List.of(AwsArnUtils.Arn.global(AwsRegions.partitionFor(region), "iam", accountId,
                "role" + pathAndName).toString());
    }

    /**
     * The user who owns the access key {@code GetAccessKeyLastUsed} asks about. The action is
     * evaluated against a user, which is what the IAM User Guide's own {@code iam:*AccessKey*}
     * example scopes to {@code user/${aws:username}}, but the request names only the key, so the
     * owner is resolved from it.
     */
    private List<String> accessKeyOwnerArn(ContainerRequestContext ctx, String accountId) {
        String accessKeyId = RequestBodyReader.formField(ctx, "AccessKeyId");
        if (accessKeyId == null || accessKeyId.isBlank() || iamService == null) {
            return List.of("*");
        }
        return iamService.get().findAccessKeyOwnerInThisAccount(accessKeyId)
                .flatMap(userName -> storedIamEntity("user", userName, accountId))
                .map(stored -> List.of(stored.arn()))
                .orElse(List.of("*"));
    }

    /**
     * The user who signed the request, for the actions whose {@code UserName} is optional. The
     * credential's own key names the identity, which is the same lookup
     * {@code GetAccessKeyLastUsed} makes on a key the request carries as a parameter.
     *
     * <p>The wildcard stands when the signer is not an IAM user: an account's root stand-in and a
     * session credential have no user record, and AWS evaluates those against the identity they
     * belong to rather than against a user ARN this resolver could mint.
     */
    private List<String> signingUserArn(ContainerRequestContext ctx, String accountId) {
        if (iamService == null) {
            return List.of("*");
        }
        return SigV4CredentialScope.accessKeyId(ctx.getHeaderString("Authorization"))
                .flatMap(accessKeyId -> iamService.get().findUserNameByAccessKeyId(accessKeyId))
                .flatMap(userName -> storedIamEntity("user", userName, accountId))
                .map(stored -> List.of(stored.arn()))
                .orElse(List.of("*"));
    }

    /**
     * The report {@code GenerateOrganizationsAccessReport} would produce. The reference spells the
     * type as {@code access-report/${EntityPath}}, so the resource is the Organizations entity
     * path the request carries and there is no IAM {@code Path} to read: the slashes inside it are
     * the organization's own tree, not an IAM path.
     */
    private List<String> organizationsAccessReportArn(ContainerRequestContext ctx, String region,
                                                      String accountId) {
        String entityPath = RequestBodyReader.formField(ctx, "EntityPath");
        if (entityPath == null || entityPath.isBlank()) {
            return List.of("*");
        }
        return List.of(AwsArnUtils.Arn.global(AwsRegions.partitionFor(region), "iam", accountId,
                "access-report/" + entityPath).toString());
    }

    /** A request's Path as it appears in an ARN: slash-delimited, defaulting to a bare slash. */
    private static String normalizeArnPath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        return normalized.endsWith("/") ? normalized : normalized + "/";
    }

    /**
     * The resource type an action names by name, or null when there is none to use: AWS gives the
     * action no type, gives it more than one, or gives it a type this resolver has no name
     * parameter for. More than one type always means the request carries an ARN, which the caller
     * handles before reaching here.
     */
    private static String nameableType(String action) {
        List<String> types = IamActionResources.typesOf(action);
        if (types.size() != 1) {
            return null;
        }
        String resourceType = types.get(0);
        return NAME_PARAMETERS.containsKey(resourceType) ? resourceType : null;
    }

    /**
     * The stored resource of that name in this account, carrying its own ARN and path. Empty when
     * the account holds none, or when the stored record has no ARN to read: the operation fails as
     * {@code NoSuchEntity} either way, and minting an ARN for a resource that is not there would
     * only offer a policy something to match.
     */
    private Optional<StoredEntity> storedIamEntity(String resourceType, String name,
                                                   String accountId) {
        if (iamService == null) {
            return Optional.empty();
        }
        IamService iam = iamService.get();
        Optional<StoredEntity> stored = switch (resourceType) {
            case "user" -> iam.findUser(accountId, name)
                    .map(user -> new StoredEntity(user.getArn(), user.getPath()));
            case "role" -> iam.findRole(accountId, name)
                    .map(role -> new StoredEntity(role.getArn(), role.getPath()));
            case "group" -> iam.findGroup(accountId, name)
                    .map(group -> new StoredEntity(group.getArn(), group.getPath()));
            case "instance-profile" -> iam.findInstanceProfile(accountId, name)
                    .map(profile -> new StoredEntity(profile.getArn(), profile.getPath()));
            case "server-certificate" -> iam.findServerCertificate(name)
                    .map(certificate -> new StoredEntity(certificate.getArn(),
                            certificate.getPath()));
            default -> Optional.empty();
        };
        return stored.filter(entity -> entity.arn() != null && !entity.arn().isBlank());
    }

    // ── ECS ─────────────────────────────────────────────────────────────────────

    /**
     * The ECS actions whose target the request carries as an ARN, and the member holding it.
     * Passed through, as IAM's ARN-carrying actions are: these are also the actions AWS gives
     * every taggable type, so the ARN is what says which one the request names.
     */
    static final Map<String, String> ECS_ARN_PARAMETERS = Map.of(
            "TagResource", "resourceArn",
            "UntagResource", "resourceArn",
            "ListTagsForResource", "resourceArn");

    /**
     * How each ECS resource type is read out of a request body, per type, as IAM's
     * {@link #NAME_PARAMETERS} is. Which types an action is authorized against comes from the
     * vendored {@code aws/ecs-action-resources.json}; the member a type arrives in depends on the
     * action, so each resolver is handed the action too. A type absent from the body contributes
     * nothing, and a request naming nothing at all is evaluated against {@code *}.
     */
    static final Map<String, EcsTypeResolver> ECS_TYPE_RESOLVERS = Map.of(
            "cluster", ResourceArnBuilder::ecsClusterArns,
            "service", ResourceArnBuilder::ecsServiceArns,
            "task", ResourceArnBuilder::ecsTaskArns,
            "task-definition", ResourceArnBuilder::ecsTaskDefinitionArns,
            "container-instance", ResourceArnBuilder::ecsContainerInstanceArns,
            "capacity-provider", ResourceArnBuilder::ecsCapacityProviderArns,
            "task-set", ResourceArnBuilder::ecsTaskSetArns,
            "service-deployment", (self, action, body, scope) -> ecsArnsIn(body, "serviceDeploymentArns"),
            "service-revision", (self, action, body, scope) -> ecsArnsIn(body, "serviceRevisionArns"));

    /**
     * The ECS resource types the reference gives only to actions {@code EcsJsonHandler} does not
     * dispatch, with why, besides the tagging actions, which pass their ARN through whatever type
     * it names. Held to the claim by {@code EcsUnresolvedResourceTypesIntegrationTest}, as
     * {@link #UNRESOLVED_TYPES} is for IAM.
     */
    static final Map<String, String> ECS_UNRESOLVED_TYPES = Map.of(
            "daemon", "the daemon actions are not dispatched",
            "daemon-deployment", "the daemon actions are not dispatched",
            "daemon-revision", "the daemon actions are not dispatched",
            "daemon-task-definition", "the daemon task definition actions are not dispatched",
            "gateway", "the gateway actions are not dispatched",
            "gateway-route", "the gateway actions are not dispatched");

    /** How one of {@link #ECS_TYPE_RESOLVERS} reads its resources out of an ECS request body. */
    interface EcsTypeResolver {
        List<String> resolve(ResourceArnBuilder self, String action, JsonNode body, EcsScope scope);
    }

    /** Where a minted ECS ARN lives: the request's partition, Region and account. */
    record EcsScope(String partition, String region, String accountId) {
        String arn(String resource) {
            return new AwsArnUtils.Arn(partition, "ecs", region, accountId, resource).toString();
        }
    }

    /**
     * The ECS resources a request is authorized against, which are the ones the handler will act
     * on: each reference is resolved through the same {@link EcsService} lookup the handler uses,
     * and the stored resource's ARN is what is checked. A request naming no cluster acts on
     * {@link EcsService#DEFAULT_CLUSTER}. A resource that does not exist is authorized against
     * the ARN the request names, kept in its own partition, Region and account, or one minted from
     * its name, never {@code *}, so a deny on it still matches before the handler answers that it
     * is not there.
     */
    private List<String> buildEcsArns(ContainerRequestContext ctx, String region, String accountId,
                                      String partition) {
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target == null || !target.contains(".")) {
            return List.of("*");
        }
        String action = target.substring(target.lastIndexOf('.') + 1);
        JsonNode body = readJsonBody(ctx);
        if (body == null || !body.isObject()) {
            body = objectMapper.createObjectNode();
        }
        String arnParameter = ECS_ARN_PARAMETERS.get(action);
        if (arnParameter != null) {
            String arn = nodeText(body.path(arnParameter));
            return AwsArnUtils.isArn(arn) ? List.of(arn) : List.of("*");
        }
        EcsScope scope = new EcsScope(partition, region, accountId);
        Set<String> arns = new LinkedHashSet<>();
        for (String resourceType : IamActionResources.forService("ecs").typesOf(action)) {
            EcsTypeResolver resolver = ECS_TYPE_RESOLVERS.get(resourceType);
            if (resolver != null) {
                arns.addAll(resolver.resolve(this, action, body, scope));
            }
        }
        return arns.isEmpty() ? List.of("*") : List.copyOf(arns);
    }

    private List<String> ecsClusterArns(String action, JsonNode body, EcsScope scope) {
        return switch (action) {
            case "CreateCluster" -> List.of(scope.arn("cluster/" + ecsClusterName(text(body, "clusterName"))));
            case "DescribeClusters" -> {
                List<String> clusters = texts(body, "clusters");
                if (clusters.isEmpty()) {
                    yield List.of(ecsClusterArn(null, scope));
                }
                yield clusters.stream().map(cluster -> ecsClusterArn(cluster, scope)).toList();
            }
            default -> List.of(ecsClusterArn(text(body, "cluster"), scope));
        };
    }

    private List<String> ecsServiceArns(String action, JsonNode body, EcsScope scope) {
        String clusterRef = text(body, "cluster");
        return switch (action) {
            case "CreateService" -> {
                String name = text(body, "serviceName");
                yield name == null ? List.of()
                        : List.of(scope.arn("service/" + ecsClusterNameIn(clusterRef, scope) + "/" + name));
            }
            case "UpdateService", "DeleteService" -> {
                // These act on the request's cluster and the name after the reference's last '/',
                // whatever cluster or Region a service ARN names, so that is what is authorized.
                String service = text(body, "service");
                if (service == null) {
                    yield List.of();
                }
                yield List.of(storedEcs(ecs -> ecs.storedServiceArnByName(clusterRef, service, scope.region()))
                        .orElseGet(() -> scope.arn("service/" + ecsClusterNameIn(clusterRef, scope) + "/"
                                + service.substring(service.lastIndexOf('/') + 1))));
            }
            case "DescribeServices" -> texts(body, "services").stream()
                    .map(service -> ecsServiceArn(clusterRef, service, scope)).toList();
            case "DescribeServiceDeployments" -> ecsParentServiceArns(body, "serviceDeploymentArns", scope,
                    EcsService::storedDeploymentServiceArn);
            case "DescribeServiceRevisions" -> ecsParentServiceArns(body, "serviceRevisionArns", scope,
                    EcsService::storedRevisionServiceArn);
            default -> {
                String service = text(body, "service");
                yield service == null ? List.of() : List.of(ecsServiceArn(clusterRef, service, scope));
            }
        };
    }

    private List<String> ecsTaskArns(String action, JsonNode body, EcsScope scope) {
        String clusterRef = text(body, "cluster");
        List<String> tasks = new ArrayList<>();
        String task = text(body, "task");
        if (task != null) {
            tasks.add(task);
        }
        tasks.addAll(texts(body, "tasks"));
        // A task is found by its ARN or trailing id in any cluster and Region, so the stored task
        // is the resource, not one minted under whatever cluster the request names.
        return tasks.stream()
                .map(ref -> storedEcs(ecs -> ecs.storedTaskArn(ref, scope.region()))
                        .orElseGet(() -> ecsGivenOrMinted("task", ref, clusterRef, scope)))
                .toList();
    }

    private List<String> ecsTaskDefinitionArns(String action, JsonNode body, EcsScope scope) {
        return switch (action) {
            case "RegisterTaskDefinition" -> {
                String family = text(body, "family");
                if (family == null) {
                    yield List.of();
                }
                // A registration names a revision that does not exist yet, so it is minted as the
                // one the registration would make, the way an IAM create is minted from its request.
                String revision = ecsService == null || !ecsService.isResolvable() ? "*"
                        : String.valueOf(ecsService.get().nextTaskDefinitionRevision(family, scope.region()));
                yield List.of(scope.arn("task-definition/" + family + ":" + revision));
            }
            case "DeleteTaskDefinitions" -> texts(body, "taskDefinitions").stream()
                    .map(ref -> ecsTaskDefinitionArn(ref, scope)).toList();
            default -> {
                String ref = text(body, "taskDefinition");
                yield ref == null ? List.of() : List.of(ecsTaskDefinitionArn(ref, scope));
            }
        };
    }

    private List<String> ecsContainerInstanceArns(String action, JsonNode body, EcsScope scope) {
        String clusterRef = text(body, "cluster");
        List<String> refs = new ArrayList<>();
        if ("PutAttributes".equals(action) || "DeleteAttributes".equals(action)) {
            for (JsonNode attribute : body.path("attributes")) {
                String targetType = nodeText(attribute.path("targetType"));
                String targetId = nodeText(attribute.path("targetId"));
                if ((targetType.isEmpty() || "container-instance".equals(targetType)) && !targetId.isBlank()) {
                    refs.add(targetId);
                }
            }
        } else {
            String instance = text(body, "containerInstance");
            if (instance != null) {
                refs.add(instance);
            }
            refs.addAll(texts(body, "containerInstances"));
        }
        return refs.stream()
                .map(ref -> storedEcs(ecs -> ecs.storedContainerInstanceArn(clusterRef, ref, scope.region()))
                        .orElseGet(() -> ecsGivenOrMinted("container-instance", ref, clusterRef, scope)))
                .toList();
    }

    private List<String> ecsCapacityProviderArns(String action, JsonNode body, EcsScope scope) {
        if ("CreateCapacityProvider".equals(action)) {
            String name = text(body, "name");
            return name == null ? List.of() : List.of(scope.arn("capacity-provider/" + name));
        }
        List<String> refs = switch (action) {
            case "DeleteCapacityProvider" -> optional(text(body, "capacityProvider"));
            case "DescribeCapacityProviders" -> texts(body, "capacityProviders");
            default -> optional(text(body, "name"));
        };
        return refs.stream()
                .map(ref -> storedEcs(ecs -> ecs.storedCapacityProviderArn(ref))
                        .orElseGet(() -> AwsArnUtils.isArnFor(ref, "ecs") ? ref
                                : scope.arn("capacity-provider/" + ref)))
                .toList();
    }

    private List<String> ecsTaskSetArns(String action, JsonNode body, EcsScope scope) {
        String clusterRef = text(body, "cluster");
        String service = text(body, "service");
        if (service == null) {
            return List.of();
        }
        String prefix = ecsTaskSetPrefix(ecsServiceArn(clusterRef, service, scope), clusterRef, scope);
        List<String> taskSets = switch (action) {
            // A create names a task set whose id ECS has yet to assign, as CreateSecurityGroup does,
            // and a describe naming none asks about every one the service has.
            case "CreateTaskSet" -> List.of("*");
            case "DescribeTaskSets" -> {
                List<String> named = texts(body, "taskSets");
                yield named.isEmpty() ? List.of("*") : named;
            }
            default -> optional(text(body, "taskSet"));
        };
        return taskSets.stream()
                .map(taskSet -> "*".equals(taskSet) ? prefix + "/*"
                        : storedEcs(ecs -> ecs.storedTaskSetArn(clusterRef, service, taskSet, scope.region()))
                                .orElseGet(() -> AwsArnUtils.isArnFor(taskSet, "ecs") ? taskSet
                                        : prefix + "/" + taskSet))
                .toList();
    }

    /**
     * The services a list of deployment or revision ARNs belongs to: the stored one when the ARN
     * names a stored deployment or revision, otherwise the {@code <type>/<cluster>/<service>/<id>}
     * ARN's own parent, in that ARN's partition, Region and account.
     */
    private List<String> ecsParentServiceArns(JsonNode body, String field, EcsScope scope,
                                              BiFunction<EcsService, String, Optional<String>> stored) {
        List<String> services = new ArrayList<>();
        for (String arn : ecsArnsIn(body, field)) {
            Optional<String> storedService = storedEcs(ecs -> stored.apply(ecs, arn));
            if (storedService.isPresent()) {
                services.add(storedService.get());
                continue;
            }
            AwsArnUtils.Arn parsed = AwsArnUtils.parse(arn);
            String[] segments = parsed.resource().split("/");
            if (segments.length >= 3) {
                services.add(new AwsArnUtils.Arn(parsed.partition(), "ecs", parsed.region(), parsed.accountId(),
                        "service/" + segments[1] + "/" + segments[2]).toString());
            }
        }
        return services;
    }

    /** The ECS ARNs a list member carries, as given. */
    private static List<String> ecsArnsIn(JsonNode body, String field) {
        return texts(body, field).stream().filter(arn -> AwsArnUtils.isArnFor(arn, "ecs")).toList();
    }

    /**
     * The cluster a reference names, as the handlers find it: the stored cluster by name in the
     * request's Region or by ARN in any, the default one when it names none. A cluster that is
     * not there is its ARN as given, or one minted from its name.
     */
    private String ecsClusterArn(String clusterRef, EcsScope scope) {
        return storedEcs(ecs -> ecs.storedClusterArn(clusterRef, scope.region()))
                .orElseGet(() -> clusterRef != null && AwsArnUtils.isArnFor(clusterRef, "ecs") ? clusterRef
                        : scope.arn("cluster/" + ecsClusterName(clusterRef)));
    }

    /** The name of the cluster a request acts in: the stored cluster's, or the name it gives. */
    private String ecsClusterNameIn(String clusterRef, EcsScope scope) {
        return storedEcs(ecs -> ecs.storedClusterArn(clusterRef, scope.region()))
                .map(ResourceArnBuilder::ecsClusterName)
                .orElseGet(() -> ecsClusterName(clusterRef));
    }

    /**
     * The service a reference names, as {@code resolveService} finds it: in the request's
     * cluster, then by ARN or name in any. A service that is not there is its ARN as given, or one
     * minted under the request's cluster.
     */
    private String ecsServiceArn(String clusterRef, String serviceRef, EcsScope scope) {
        return storedEcs(ecs -> ecs.storedServiceArn(clusterRef, serviceRef, scope.region()))
                .orElseGet(() -> ecsGivenOrMinted("service", serviceRef, clusterRef, scope));
    }

    /** A resource's ARN as given when it is one, kept in its own partition, Region and account; otherwise minted under the request's cluster. */
    private String ecsGivenOrMinted(String resourceType, String ref, String clusterRef, EcsScope scope) {
        if (AwsArnUtils.isArnFor(ref, "ecs")) {
            return ref;
        }
        return scope.arn(resourceType + "/" + ecsClusterNameIn(clusterRef, scope) + "/" + ref);
    }

    /** {@code task-set/<cluster>/<service>} beside a service ARN, in that ARN's partition, Region and account. */
    private String ecsTaskSetPrefix(String serviceArn, String clusterRef, EcsScope scope) {
        AwsArnUtils.Arn parsed = AwsArnUtils.parse(serviceArn);
        String[] segments = parsed.resource().split("/");
        String path = segments.length >= 3 ? segments[1] + "/" + segments[2]
                : ecsClusterNameIn(clusterRef, scope) + "/" + segments[segments.length - 1];
        return new AwsArnUtils.Arn(parsed.partition(), "ecs", parsed.region(), parsed.accountId(),
                "task-set/" + path).toString();
    }

    /**
     * The task definition a reference names, as every launch and lookup finds it: the stored
     * definition a {@code family:revision}, an ARN or a bare family resolves to. One that is not
     * there is its ARN as given, its {@code family:revision}, or {@code family:*} for a bare family,
     * the caller's naming, so a deny over the family still matches.
     */
    private String ecsTaskDefinitionArn(String ref, EcsScope scope) {
        Optional<String> stored = storedEcs(ecs -> ecs.storedTaskDefinitionArn(ref, scope.region()));
        if (stored.isPresent()) {
            return stored.get();
        }
        if (AwsArnUtils.isArnFor(ref, "ecs")) {
            return ref;
        }
        return scope.arn("task-definition/" + (ref.contains(":") ? ref : ref + ":*"));
    }

    /** A lookup against the ECS store, or empty when the builder has none to read. */
    private Optional<String> storedEcs(Function<EcsService, Optional<String>> lookup) {
        return ecsService == null || !ecsService.isResolvable() ? Optional.empty() : lookup.apply(ecsService.get());
    }

    private static String ecsClusterName(String ref) {
        if (ref == null) {
            return EcsService.DEFAULT_CLUSTER;
        }
        return AwsArnUtils.resourceIfArnFor(ref, "ecs")
                .filter(resource -> resource.startsWith("cluster/"))
                .map(resource -> resource.substring("cluster/".length()))
                .orElse(ref);
    }

    private static String text(JsonNode body, String field) {
        String value = nodeText(body.path(field));
        return value.isBlank() ? null : value;
    }

    private static List<String> texts(JsonNode body, String field) {
        List<String> values = new ArrayList<>();
        for (JsonNode value : body.path(field)) {
            String text = nodeText(value);
            if (!text.isBlank()) {
                values.add(text);
            }
        }
        return values;
    }

    /**
     * A member as {@code EcsJsonHandler} reads it, with {@code asText()}: a JSON {@code null} is the
     * string {@code "null"}, which the handler then looks up, and a missing member is empty.
     */
    private static String nodeText(JsonNode node) {
        return node.isNull() ? "null" : node.asText("");
    }

    private static List<String> optional(String value) {
        return value == null ? List.of() : List.of(value);
    }

    // ── EC2 security groups ─────────────────────────────────────────────────────

    /**
     * The EC2 actions that act on a security group and on nothing else AWS checks, so the groups
     * they name are their whole resource. Every other action in {@code aws/ec2-action-resources.json}
     * is authorized by AWS against other types as well (an instance, a network interface, an
     * endpoint, a VPC, a prefix list), which that file does not vendor, so those keep {@code *}
     * beside the groups they name: a deny on a group binds, and an allow on the group alone does
     * not grant them.
     */
    static final Set<String> EC2_GROUP_ONLY_ACTIONS = Set.of(
            "AuthorizeSecurityGroupEgress", "AuthorizeSecurityGroupIngress",
            "RevokeSecurityGroupEgress", "RevokeSecurityGroupIngress",
            "DeleteSecurityGroup",
            "UpdateSecurityGroupRuleDescriptionsEgress", "UpdateSecurityGroupRuleDescriptionsIngress",
            "DescribeSecurityGroupReferences");

    /**
     * The Query members, list indices written as {@code N}, in which {@code Ec2QueryHandler}
     * reads the security groups each dispatched action acts on, so the groups authorized are the
     * groups the handler uses. Read exactly rather than by suffix: {@code IpPermissions.N.Groups.N.GroupId}
     * names the group a rule refers to, which is not a resource the call acts on. An action not
     * listed reads its groups from {@code GroupId} and {@code GroupId.N}, as AWS's own model has
     * the actions Floci does not dispatch.
     */
    static final Map<String, Set<String>> EC2_GROUP_MEMBERS = Map.of(
            "RunInstances", Set.of("SecurityGroupId.N", "NetworkInterface.N.SecurityGroupId.N"),
            "CreateNetworkInterface", Set.of("SecurityGroupId.N", "Groups.SecurityGroupId.N"),
            "CreateVpcEndpoint", Set.of("SecurityGroupId.N"),
            "ModifyVpcEndpoint", Set.of("AddSecurityGroupId.N", "RemoveSecurityGroupId.N"),
            "RequestSpotInstances", Set.of("LaunchSpecification.SecurityGroupId.N",
                    "LaunchSpecification.NetworkInterface.N.SecurityGroupId.N"),
            "ModifyInstanceAttribute", Set.of("GroupId.N"),
            "ModifyNetworkInterfaceAttribute", Set.of("SecurityGroupId.N"),
            "CreateTags", Set.of(),
            "DeleteTags", Set.of());

    private static final Set<String> EC2_DEFAULT_GROUP_MEMBERS = Set.of("GroupId", "GroupId.N");

    private static final Pattern QUERY_LIST_INDEX = Pattern.compile("\\.\\d+(?=\\.|$)");

    /**
     * The security groups an EC2 request names, for the actions AWS authorizes against a security
     * group. {@code CreateSecurityGroup} is authorized against {@code security-group/*}, the group's
     * id not existing yet, the tagging actions against each {@code sg-} resource they name, and a
     * {@code RunInstances} naming no group against the groups its launch template gives it, as the
     * handler launches with them. An action naming no group stays on {@code *}, as does every
     * action outside the vendored map.
     */
    private List<String> buildEc2Arns(ContainerRequestContext ctx, String region, String accountId,
                                      String partition) {
        String action = AwsQueryServiceResolver.action(
                RequestBodyReader.formField(ctx, "Action"),
                RequestBodyReader.formField(ctx, "Operation"));
        if (action == null || !IamActionResources.forService("ec2").typesOf(action).contains("security-group")) {
            return List.of("*");
        }
        Set<String> arns = new LinkedHashSet<>();
        if ("CreateSecurityGroup".equals(action)) {
            arns.add(securityGroupArn("*", region, accountId, partition));
        }
        boolean tagging = "CreateTags".equals(action) || "DeleteTags".equals(action);
        Set<String> members = EC2_GROUP_MEMBERS.getOrDefault(action, EC2_DEFAULT_GROUP_MEMBERS);
        String groupName = null;
        Map<String, String> launchTemplate = new LinkedHashMap<>();
        for (Map.Entry<String, String> field : RequestBodyReader.formFields(ctx)) {
            String member = QUERY_LIST_INDEX.matcher(field.getKey()).replaceAll(".N");
            String value = field.getValue();
            if (value == null || value.isBlank()) {
                continue;
            }
            if (members.contains(member)
                    || tagging && "ResourceId.N".equals(member) && value.startsWith("sg-")) {
                arns.add(securityGroupArn(value, region, accountId, partition));
            } else if ("GroupName".equals(member)) {
                // The handler reads each single-valued member with getFirst, so the first wins here too.
                if (groupName == null) {
                    groupName = value;
                }
            } else if (member.startsWith("LaunchTemplate.")) {
                launchTemplate.putIfAbsent(member, value);
            }
        }
        if (arns.isEmpty() && groupName != null && "DeleteSecurityGroup".equals(action)) {
            // The handler deletes the group its GroupName names when no GroupId is given, reading
            // the name as the id, so the resource is read the same way.
            arns.add(securityGroupArn(groupName, region, accountId, partition));
        }
        if (arns.isEmpty() && "RunInstances".equals(action) && !launchTemplate.isEmpty()) {
            for (String groupId : launchTemplateGroups(launchTemplate, region)) {
                arns.add(securityGroupArn(groupId, region, accountId, partition));
            }
        }
        if (arns.isEmpty()) {
            return List.of("*");
        }
        if (!EC2_GROUP_ONLY_ACTIONS.contains(action)) {
            arns.add("*");
        }
        return List.copyOf(arns);
    }

    /**
     * The groups a launch template gives a {@code RunInstances} that names none, read the way the
     * handler reads them: the template version the request names, its own group ids, else those
     * of its interfaces. Read without seeding or changing anything, since the call may yet be
     * denied. Empty when there is no store to read or the template is not there, in which case
     * the launch fails before it starts anything.
     */
    private List<String> launchTemplateGroups(Map<String, String> launchTemplate, String region) {
        String id = launchTemplate.get("LaunchTemplate.LaunchTemplateId");
        String name = launchTemplate.get("LaunchTemplate.LaunchTemplateName");
        if (ec2Service == null || !ec2Service.isResolvable() || id == null && name == null) {
            return List.of();
        }
        return ec2Service.get().launchTemplateSecurityGroupIds(region, id, name,
                launchTemplate.get("LaunchTemplate.Version"));
    }

    private static String securityGroupArn(String groupId, String region, String accountId, String partition) {
        return new AwsArnUtils.Arn(partition, "ec2", region, accountId, "security-group/" + groupId).toString();
    }

    // ── S3 ──────────────────────────────────────────────────────────────────────
    // Minted in the request's partition; IamEnforcementFilter re-mints an existing bucket's ARN
    // in the bucket's own partition through S3ResourcePolicyProvider before any policy sees it.
    private String buildS3Arn(String path, String region) {
        // path: /bucket or /bucket/key
        String partition = AwsRegions.partitionFor(region);
        String stripped = path.startsWith("/") ? path.substring(1) : path;
        if (stripped.isEmpty()) {
            return AwsArnUtils.Arn.global(partition, "s3", "", "*").toString();
        }
        // S3VirtualHostFilter rewrites a bucket-level virtual-hosted request (GET /) to
        // /bucket/, and the empty key after that separator is not part of the resource.
        // A policy names the bucket as arn:<partition>:s3:::bucket, so the trailing slash has to
        // go or a bucket-level ARN never matches. A key that itself ends in a slash
        // (a folder marker such as folder/) keeps it, because there the slash is key data.
        int firstSlash = stripped.indexOf('/');
        if (firstSlash == stripped.length() - 1) {
            stripped = stripped.substring(0, firstSlash);
        }
        return AwsArnUtils.Arn.global(partition, "s3", "", stripped).toString();
    }

    // ── Lambda ──────────────────────────────────────────────────────────────────

    /**
     * The function a Lambda request acts on, as an IAM policy names it. An invoke runs the function
     * in the account and Region its full or partial ARN names, so it is evaluated against that
     * function, and against the version or alias it names in the function name or in
     * {@code Qualifier}, since Lambda authorizes a qualified call against the qualified ARN (Lambda
     * Developer Guide, "Referencing functions in the Resource section of policies"). The reads
     * {@link #readsInTheAccountItNames} names act in the account a qualified ARN names too. Every
     * other route acts on the caller's own function of that name, whatever account an ARN names.
     * Those are evaluated unqualified, because not every one of them acts on the qualifier it is
     * given.
     */
    private String buildLambdaArn(String path, ContainerRequestContext ctx, String region, String accountId) {
        String webFunctionArn = webFunctionArn(path, region, accountId);
        if (webFunctionArn != null) {
            return webFunctionArn;
        }
        String microvmArn = microvmArn(path, ctx, region, accountId);
        if (microvmArn != null) {
            return microvmArn;
        }
        // TagResource, ListTags and UntagResource name the tagged function, image or other resource by its ARN.
        if (path.startsWith("/2017-03-31/tags/")) {
            return lambdaTaggedArn(path.substring("/2017-03-31/tags/".length()), accountId);
        }
        String executionArn = durableExecutionArn(path);
        if (executionArn == null) {
            executionArn = durableCallbackExecutionArn(path);
        }
        if (executionArn != null) {
            return executionArn;
        }
        // path: /2015-03-31/functions/name or similar
        String name = extractSegmentAfter(path, "functions");
        if (name == null) return "*";
        boolean invoke = path.endsWith("/functions/" + name + "/invocations")
                || path.endsWith("/functions/" + name + "/response-streaming-invocations");
        try {
            if (!invoke) {
                LambdaArnUtils.ResolvedFunctionRef ref = LambdaArnUtils.resolve(name);
                boolean namedAccount = readsInTheAccountItNames(path, name, ref, ctx);
                return AwsArnUtils.Arn.of("lambda",
                        namedAccount ? ref.region() : region,
                        namedAccount ? ref.account() : accountId,
                        "function:" + ref.name()).toString();
            }
            LambdaArnUtils.ResolvedFunctionRef ref = LambdaArnUtils.resolveWithQualifier(
                    name, ctx.getUriInfo().getQueryParameters().getFirst("Qualifier"));
            String resource = ref.qualifier() != null
                    ? "function:" + ref.name() + ":" + ref.qualifier()
                    : "function:" + ref.name();
            return AwsArnUtils.Arn.of("lambda",
                    ref.region() != null ? ref.region() : region,
                    ref.account() != null ? ref.account() : accountId,
                    resource).toString();
        } catch (AwsException e) {
            // A reference Lambda refuses, which its handler answers with a 400 before acting on anything.
            return AwsArnUtils.Arn.of("lambda", region, accountId, "function:" + name).toString();
        }
    }

    /**
     * The resource of a Lambda MicroVM or network connector route, as the Service Reference gives it:
     * {@code microvm-image:<name>} for an action on an image, its versions and builds, and
     * {@code network-connector:<id>} for one on a connector. An identifier given as an ARN is taken for
     * its trailing name, in the request's account and Region, since that is the resource the service
     * looks up and acts on, whatever account or Region the ARN names. {@code RunMicrovm} is checked
     * against the image its {@code imageIdentifier} names, read the same way, an action on a running
     * MicroVM against the image that MicroVM runs, and a managed image's versions against the managed
     * image. Creating an image or a connector, listing them and listing MicroVMs name no resource, so
     * they are {@code *}, as is a MicroVM the account does not hold. Null for every other Lambda route.
     */
    private String microvmArn(String path, ContainerRequestContext ctx, String region, String accountId) {
        if (path.startsWith("/2025-09-09/")) {
            String image = segmentAfterPrefix(path, "/2025-09-09/microvm-images/");
            if (image != null) {
                return microvmImageArn(region, accountId, image);
            }
            String managed = segmentAfterPrefix(path, "/2025-09-09/managed-microvm-images/");
            if (managed != null) {
                return LambdaMicrovmsService.namesManagedImage(managed)
                        ? LambdaMicrovmsService.managedImageArn(region) : "*";
            }
            String microvm = segmentAfterPrefix(path, "/2025-09-09/microvms/");
            if (microvm != null) {
                return runningMicrovmImageArn(region, microvm);
            }
            if (path.equals("/2025-09-09/microvms") && "POST".equalsIgnoreCase(ctx.getMethod())) {
                JsonNode body = readJsonBody(ctx);
                String identifier = body == null ? null : body.path("imageIdentifier").asText(null);
                return identifier == null || identifier.isBlank() ? "*" : microvmImageArn(region, accountId, identifier);
            }
            return "*";
        }
        if (path.startsWith("/2026-04-04/")) {
            String connector = segmentAfterPrefix(path, "/2026-04-04/network-connectors/");
            return connector == null ? "*"
                    : AwsArnUtils.Arn.of("lambda", region, accountId,
                            "network-connector:" + trailingName(connector)).toString();
        }
        return null;
    }

    private static String microvmImageArn(String region, String accountId, String identifier) {
        return AwsArnUtils.Arn.of("lambda", region, accountId, "microvm-image:" + trailingName(identifier)).toString();
    }

    /** The image the caller's MicroVM runs, or {@code *} when the account holds no such MicroVM to act on. */
    private String runningMicrovmImageArn(String region, String microvmId) {
        if (microvmsService == null) {
            return "*";
        }
        return microvmsService.get().findMicrovm(region, microvmId)
                .map(vm -> vm.imageArn)
                .filter(arn -> arn != null && !arn.isBlank())
                .orElse("*");
    }

    /** An identifier's name: an ARN's part after its last {@code :}, as the MicroVM service unwraps it. */
    private static String trailingName(String identifier) {
        return identifier.startsWith("arn:") ? identifier.substring(identifier.lastIndexOf(':') + 1) : identifier;
    }

    /**
     * The resource a Lambda tag route acts on, from the ARN it names. Tagging looks a function up by the
     * ARN's Region and name, and a MicroVM image or network connector by the ARN's Region and trailing
     * name, in the caller's own account whatever account the ARN names, so that resource is the one
     * checked. The MicroVM tag handler takes any target holding {@code :microvm-image:} or
     * {@code :network-connector:}, an {@code arn:} prefix or not, so the target is read as it reads it.
     * Any other ARN, an event source mapping's included, has to name its resource exactly or is
     * refused, so it is checked as written.
     */
    private static String lambdaTaggedArn(String tagged, String accountId) {
        if (LambdaMicrovmsService.ownsArn(tagged)) {
            // Read as LambdaTagController and LambdaMicrovmsService read it: the Region is the fourth field,
            // the name what follows the last colon.
            String[] fields = tagged.split(":");
            String region = fields.length > 3 ? fields[3] : "";
            String type = tagged.contains(":microvm-image:") ? "microvm-image:"
                    : tagged.contains(":network-connector:") ? "network-connector:" : null;
            if (type != null && !region.isBlank()) {
                return AwsArnUtils.Arn.of("lambda", region, accountId,
                        type + tagged.substring(tagged.lastIndexOf(':') + 1)).toString();
            }
        }
        if (!tagged.startsWith("arn:")) {
            return "*";
        }
        try {
            LambdaArnUtils.ResolvedFunctionRef ref = LambdaArnUtils.resolve(tagged);
            return ref.qualifier() != null ? tagged
                    : AwsArnUtils.Arn.of("lambda", ref.region(), accountId, "function:" + ref.name()).toString();
        } catch (AwsException e) {
            // Not a function ARN Lambda takes, which it tags only when the ARN names the resource exactly.
            return tagged;
        }
    }

    /**
     * The resource of an EventBridge Scheduler route: {@code schedule/<group>/<name>}, the group read where
     * Scheduler reads it, the body's {@code GroupName} on a create or an update and {@code groupName}
     * otherwise, and {@code default} when the request names none; {@code schedule-group/<name>}; or the
     * ARN a tagging route names. The list routes name no resource.
     */
    private String buildSchedulerArn(String path, ContainerRequestContext ctx, String region, String accountId,
                                     String partition) {
        String schedule = segmentAfterPrefix(path, "/schedules/");
        if (schedule != null) {
            String group;
            if ("POST".equalsIgnoreCase(ctx.getMethod()) || "PUT".equalsIgnoreCase(ctx.getMethod())) {
                JsonNode body = readJsonBody(ctx);
                group = body == null ? null : body.path("GroupName").asText(null);
            } else {
                group = ctx.getUriInfo().getQueryParameters().getFirst("groupName");
            }
            if (group == null || group.isBlank()) {
                group = "default";
            }
            return new AwsArnUtils.Arn(partition, "scheduler", region, accountId,
                    "schedule/" + group + "/" + schedule).toString();
        }
        String scheduleGroup = segmentAfterPrefix(path, "/schedule-groups/");
        if (scheduleGroup != null) {
            return new AwsArnUtils.Arn(partition, "scheduler", region, accountId,
                    "schedule-group/" + scheduleGroup).toString();
        }
        return taggedResource(ctx);
    }

    /** The resource of an EventBridge Pipes route: {@code pipe/<name>}, or the ARN a tagging route names. */
    private String buildPipesArn(String path, ContainerRequestContext ctx, String region, String accountId,
                                 String partition) {
        String pipe = segmentAfterPrefix(path, "/v1/pipes/");
        if (pipe != null) {
            return new AwsArnUtils.Arn(partition, "pipes", region, accountId, "pipe/" + pipe).toString();
        }
        return taggedResource(ctx);
    }

    /** The ARN a shared tagging route names, or {@code *} for any other route. */
    private String taggedResource(ContainerRequestContext ctx) {
        String arn = taggedArn(ctx);
        return arn != null && arn.startsWith("arn:") ? arn : "*";
    }

    /**
     * The ARN a shared tagging route acts on, read where its controller reads it: after {@code /tags/} or
     * {@code /v1/tags/} in the path; on {@code POST /tags}, the body's {@code resourceArn}; and on the other
     * bare routes, the {@code resourceArn} query parameter. Null for any other route, or when the request
     * names none.
     */
    public String taggedArn(ContainerRequestContext ctx) {
        String path = ctx.getUriInfo().getPath();
        for (String route : List.of("/tags", "/v1/tags")) {
            if (path.startsWith(route + "/")) {
                return path.substring(route.length() + 1);
            }
        }
        if ("/tags".equals(path) && "POST".equalsIgnoreCase(ctx.getMethod())) {
            JsonNode body = readJsonBody(ctx);
            return body == null ? null : body.path("resourceArn").asText(null);
        }
        if ("/tags".equals(path) || "/v1/tags".equals(path)) {
            return ctx.getUriInfo().getQueryParameters().getFirst("resourceArn");
        }
        return null;
    }

    /** The path segment right after {@code prefix}, or null when the path doesn't start with it or names none. */
    private static String segmentAfterPrefix(String path, String prefix) {
        if (!path.startsWith(prefix)) {
            return null;
        }
        String rest = path.substring(prefix.length());
        int slash = rest.indexOf('/');
        String segment = slash < 0 ? rest : rest.substring(0, slash);
        return segment.isEmpty() ? null : segment;
    }

    /**
     * The resource of a Lambda Web Functions route. An action on a revision or an endpoint is evaluated
     * against that child's ARN; an action on the function, a create of a revision or endpoint, the list of
     * either, and the tag and resource-policy routes against the function's (Lambda Developer Guide,
     * "Lambda Web Function permissions"). ListWebFunctions, GetWebAccountSettings and CreateWebFunction
     * name no resource. Null for every other Lambda route.
     */
    private static String webFunctionArn(String path, String region, String accountId) {
        if (!path.startsWith("/2025-03-07/")) {
            return null;
        }
        String rest = path.substring("/2025-03-07/".length());
        if (rest.startsWith("tags/") || rest.startsWith("resource-policy/")) {
            String arn = rest.substring(rest.indexOf('/') + 1);
            return arn.startsWith("arn:") ? arn : "*";
        }
        if (!rest.startsWith("web-functions/")) {
            return "*";
        }
        List<String> segments = new ArrayList<>(List.of(rest.substring("web-functions/".length()).split("/")));
        if (segments.isEmpty() || segments.getFirst().isEmpty()) {
            return "*";
        }
        String functionArn;
        if (segments.getFirst().startsWith("arn:") && segments.size() > 1) {
            // A function ARN carries one slash: arn:...:web-function/<name>.
            functionArn = segments.get(0) + "/" + segments.get(1);
            segments.subList(0, 2).clear();
        } else {
            functionArn = AwsArnUtils.Arn.of("lambda", region, accountId,
                    "web-function/" + segments.getFirst()).toString();
            segments.removeFirst();
        }
        if (segments.size() >= 2 && ("revisions".equals(segments.get(0)) || "endpoints".equals(segments.get(0)))) {
            String child = "revisions".equals(segments.get(0)) ? "revision" : "endpoint";
            String id = String.join("/", segments.subList(1, segments.size()));
            if (id.startsWith("arn:") && id.contains("/" + child + "/")) {
                // A revision or endpoint ARN ends in its id: arn:...:web-function/<name>/revision/<id>.
                id = id.substring(id.lastIndexOf('/') + 1);
            }
            return functionArn + "/" + child + "/" + id;
        }
        return functionArn;
    }

    /**
     * {@code GetFunction}, {@code GetFunctionConfiguration} and {@code ListDurableExecutionsByFunction}
     * read a function named by a qualified full ARN in the account the ARN names, where the version or
     * alias is resolved ({@code LambdaService.getFunction(region, name, qualifier)}). Unqualified, or
     * by partial ARN, they read the caller's own function of that name, as every other route acts.
     */
    private static boolean readsInTheAccountItNames(String path, String name,
                                                    LambdaArnUtils.ResolvedFunctionRef ref,
                                                    ContainerRequestContext ctx) {
        if (!"GET".equals(ctx.getMethod()) || !name.startsWith("arn:")) {
            return false;
        }
        String route = path.substring(path.indexOf("/functions/" + name) + "/functions/".length() + name.length());
        if (!route.isEmpty() && !route.equals("/configuration") && !route.equals("/durable-executions")) {
            return false;
        }
        String qualifier = ctx.getUriInfo().getQueryParameters().getFirst("Qualifier");
        return ref.qualifier() != null || (qualifier != null && !qualifier.isBlank());
    }

    /** Durable execution actions are authorized against the execution ARN, which carries the version. */
    private static String durableExecutionArn(String path) {
        String prefix = "/durable-executions/";
        int executions = path.indexOf(prefix);
        if (executions < 0) {
            return null;
        }
        Matcher matcher = LambdaArnUtils.DURABLE_EXECUTION_ARN.matcher(path.substring(executions + prefix.length()));
        return matcher.lookingAt() ? matcher.group() : null;
    }

    /** A callback id carries its execution ARN, so the callback actions are authorized against that execution. */
    private static String durableCallbackExecutionArn(String path) {
        String prefix = "/durable-execution-callbacks/";
        int callbacks = path.indexOf(prefix);
        int action = path.lastIndexOf('/');
        if (callbacks < 0 || action <= callbacks + prefix.length()) {
            return null;
        }
        return DurableTokens.callbackExecutionArn(path.substring(callbacks + prefix.length(), action))
                .filter(arn -> LambdaArnUtils.DURABLE_EXECUTION_ARN.matcher(arn).matches())
                .orElse(null);
    }

    // ── SQS ─────────────────────────────────────────────────────────────────────
    private String buildSqsArn(ContainerRequestContext ctx, String region, String accountId) {
        String queueUrl = ctx.getUriInfo().getQueryParameters().getFirst("QueueUrl");
        if (queueUrl == null) {
            // Try form param for Query-protocol
            queueUrl = firstFormParam(ctx, "QueueUrl");
        }
        if (queueUrl == null) {
            JsonNode json = readJsonBody(ctx);
            if (json != null && json.isObject()) {
                if (json.hasNonNull("QueueUrl")) {
                    queueUrl = json.get("QueueUrl").asText().trim();
                } else if (json.hasNonNull("QueueName")) {
                    String queueName = json.get("QueueName").asText().trim();
                    if (!queueName.isEmpty()) {
                        return AwsArnUtils.Arn.of("sqs", region, accountId, queueName).toString();
                    }
                }
            }
        }
        if (queueUrl != null && !queueUrl.isEmpty()) {
            String queueName = queueUrl.substring(queueUrl.lastIndexOf('/') + 1);
            return AwsArnUtils.Arn.of("sqs", region, accountId, queueName).toString();
        }
        return AwsArnUtils.Arn.of("sqs", region, accountId, "*").toString();
    }

    // ── SNS ─────────────────────────────────────────────────────────────────────
    private String buildSnsArn(ContainerRequestContext ctx, String region, String accountId) {
        String topicArn = firstFormParam(ctx, "TopicArn");
        if (topicArn == null) {
            JsonNode json = readJsonBody(ctx);
            if (json != null && json.isObject() && json.hasNonNull("TopicArn")) {
                topicArn = json.get("TopicArn").asText().trim();
            }
        }
        return (topicArn != null && !topicArn.isEmpty())
                ? topicArn
                : AwsArnUtils.Arn.of("sns", region, accountId, "*").toString();
    }

    // ── DynamoDB ─────────────────────────────────────────────────────────────────
    private String buildDynamoDbArn(ContainerRequestContext ctx, String region, String accountId) {
        List<String> arns = buildDynamoDbArns(ctx, region, accountId);
        return arns.isEmpty() ? "*" : arns.getFirst();
    }

    private List<String> buildDynamoDbArns(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode json = readJsonBody(ctx);
        if (json != null && json.isObject()) {
            if (json.hasNonNull("TableName")) {
                String tableName = json.get("TableName").asText().trim();
                if (!tableName.isEmpty()) {
                    return List.of(toDynamoDbTableArn(tableName, region, accountId));
                }
            }
            if (json.path("TableCreationParameters").hasNonNull("TableName")) {
                String tableName = json.path("TableCreationParameters").get("TableName").asText().trim();
                if (!tableName.isEmpty()) {
                    return List.of(toDynamoDbTableArn(tableName, region, accountId));
                }
            }
            if (json.hasNonNull("ResourceArn")) {
                String resourceArn = json.get("ResourceArn").asText().trim();
                if (!resourceArn.isEmpty()) {
                    return List.of(resourceArn);
                }
            }
            if (json.hasNonNull("TableArn")) {
                String tableArn = json.get("TableArn").asText().trim();
                if (!tableArn.isEmpty()) {
                    return List.of(tableArn);
                }
            }
            if (json.hasNonNull("StreamArn")) {
                String streamArn = json.get("StreamArn").asText().trim();
                if (!streamArn.isEmpty()) {
                    return List.of(streamArn);
                }
            }
            if (json.hasNonNull("ExportArn")) {
                String exportArn = json.get("ExportArn").asText().trim();
                if (!exportArn.isEmpty()) {
                    return List.of(exportArn);
                }
            }
            if (json.hasNonNull("ImportArn")) {
                String importArn = json.get("ImportArn").asText().trim();
                if (!importArn.isEmpty()) {
                    return List.of(importArn);
                }
            }
            // AWS authorizes RestoreTableToPointInTime on its source table.
            if (json.hasNonNull("SourceTableArn")) {
                String sourceTableArn = json.get("SourceTableArn").asText().trim();
                if (!sourceTableArn.isEmpty()) {
                    return List.of(sourceTableArn);
                }
            }
            if (json.hasNonNull("SourceTableName")) {
                String sourceTableName = json.get("SourceTableName").asText().trim();
                if (!sourceTableName.isEmpty()) {
                    return List.of(toDynamoDbTableArn(sourceTableName, region, accountId));
                }
            }
            if (json.hasNonNull("RequestItems") && json.get("RequestItems").isObject()) {
                Set<String> arns = new LinkedHashSet<>();
                Iterator<String> fieldNames = json.get("RequestItems").fieldNames();
                while (fieldNames.hasNext()) {
                    String table = fieldNames.next().trim();
                    if (!table.isEmpty()) {
                        arns.add(toDynamoDbTableArn(table, region, accountId));
                    }
                }
                if (!arns.isEmpty()) {
                    return new ArrayList<>(arns);
                }
            }
            if (json.hasNonNull("TransactItems") && json.get("TransactItems").isArray()) {
                Set<String> arns = new LinkedHashSet<>();
                JsonNode items = json.get("TransactItems");
                for (JsonNode item : items) {
                    String t = null;
                    if (item.hasNonNull("Put") && item.get("Put").hasNonNull("TableName")) {
                        t = item.get("Put").get("TableName").asText();
                    } else if (item.hasNonNull("Delete") && item.get("Delete").hasNonNull("TableName")) {
                        t = item.get("Delete").get("TableName").asText();
                    } else if (item.hasNonNull("Update") && item.get("Update").hasNonNull("TableName")) {
                        t = item.get("Update").get("TableName").asText();
                    } else if (item.hasNonNull("ConditionCheck") && item.get("ConditionCheck").hasNonNull("TableName")) {
                        t = item.get("ConditionCheck").get("TableName").asText();
                    } else if (item.hasNonNull("Get") && item.get("Get").hasNonNull("TableName")) {
                        t = item.get("Get").get("TableName").asText();
                    }
                    if (t != null) {
                        t = t.trim();
                        if (!t.isEmpty()) {
                            arns.add(toDynamoDbTableArn(t, region, accountId));
                        }
                    }
                }
                if (!arns.isEmpty()) {
                    return new ArrayList<>(arns);
                }
            }
            if (json.hasNonNull("Statement")) {
                String stmt = json.get("Statement").asText().trim();
                String table = extractDynamoDbTableFromPartiQL(stmt);
                if (table != null && !table.isEmpty()) {
                    return List.of(toDynamoDbTableArn(table, region, accountId));
                }
            }
            if (json.hasNonNull("Statements") && json.get("Statements").isArray()) {
                Set<String> arns = new LinkedHashSet<>();
                for (JsonNode s : json.get("Statements")) {
                    if (s.hasNonNull("Statement")) {
                        String table = extractDynamoDbTableFromPartiQL(s.get("Statement").asText());
                        if (table != null && !table.isEmpty()) {
                            arns.add(toDynamoDbTableArn(table, region, accountId));
                        }
                    }
                }
                if (!arns.isEmpty()) {
                    return new ArrayList<>(arns);
                }
            }
            if (json.hasNonNull("TransactStatements") && json.get("TransactStatements").isArray()) {
                Set<String> arns = new LinkedHashSet<>();
                for (JsonNode s : json.get("TransactStatements")) {
                    if (s.hasNonNull("Statement")) {
                        String table = extractDynamoDbTableFromPartiQL(s.get("Statement").asText());
                        if (table != null && !table.isEmpty()) {
                            arns.add(toDynamoDbTableArn(table, region, accountId));
                        }
                    }
                }
                if (!arns.isEmpty()) {
                    return new ArrayList<>(arns);
                }
            }
        }
        return List.of("*");
    }

    private static String extractDynamoDbTableFromPartiQL(String statement) {
        return io.github.hectorvent.floci.services.dynamodb.DynamoDbPartiQLParser.extractTable(statement);
    }

    public static String toDynamoDbTableArn(String tableName, String region, String accountId) {
        if (AwsArnUtils.isArnFor(tableName, "dynamodb")) {
            return tableName;
        }
        return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/" + tableName).toString();
    }

    // ── Kinesis ──────────────────────────────────────────────────────────────────
    private String buildKinesisArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode json = readJsonBody(ctx);
        if (json != null && json.isObject()) {
            if (json.hasNonNull("StreamARN")) {
                String streamArn = json.get("StreamARN").asText().trim();
                if (!streamArn.isEmpty()) {
                    return streamArn;
                }
            }
            if (json.hasNonNull("StreamName")) {
                String streamName = json.get("StreamName").asText().trim();
                if (!streamName.isEmpty()) {
                    if (AwsArnUtils.isArnFor(streamName, "kinesis")) {
                        return streamName;
                    }
                    return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/" + streamName).toString();
                }
            }
            if (json.hasNonNull("ResourceARN")) {
                String resourceArn = json.get("ResourceARN").asText().trim();
                if (!resourceArn.isEmpty()) {
                    return resourceArn;
                }
            }
        }
        return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/*").toString();
    }

    // ── Secrets Manager ──────────────────────────────────────────────────────────

    /**
     * Uses the serving operation, as {@link #buildLogResources} does: {@code CreateSecret}
     * names the secret in {@code Name} and every other operation in {@code SecretId}, so a field the
     * handler does not read cannot choose the resource. A minted ARN takes the request's partition,
     * the one the secret is created in, which a region Floci does not know cannot be mapped to.
     */
    public List<String> buildSecretsManagerResources(String action, ContainerRequestContext ctx,
                                                     String region, String accountId, String partition) {
        return List.of(buildSecretsManagerArn(action, ctx, region, accountId, partition));
    }

    /**
     * A secret named by its name or a partial ARN is authorized against its full ARN, random suffix
     * included, so a {@code secret:<name>-??????} policy matches it as it does on AWS. The suffix of
     * the secret {@code CreateSecret} is making is not assigned until it is created.
     */
    private String buildSecretsManagerArn(String action, ContainerRequestContext ctx, String region,
                                          String accountId, String partition) {
        JsonNode json = readJsonBody(ctx);
        if (json != null && json.isObject()) {
            if ("secretsmanager:CreateSecret".equals(action)) {
                if (json.hasNonNull("Name")) {
                    String name = json.get("Name").asText().trim();
                    if (!name.isEmpty()) {
                        return secretArn(name + UNASSIGNED_SECRET_SUFFIX, region, accountId, partition);
                    }
                }
            } else if (json.hasNonNull("SecretId")) {
                String secretId = json.get("SecretId").asText().trim();
                if (!secretId.isEmpty()) {
                    Optional<String> stored = storedSecretArn(secretId, region, accountId);
                    if (AwsArnUtils.isArnFor(secretId, "secretsmanager")) {
                        return stored.orElse(secretId);
                    }
                    return stored.orElseGet(() -> secretArn(secretId, region, accountId, partition));
                }
            }
        }
        return secretArn("*", region, accountId, partition);
    }

    private Optional<String> storedSecretArn(String secretId, String region, String accountId) {
        if (secretsManagerService == null) {
            return Optional.empty();
        }
        return secretsManagerService.get().findArn(accountId, secretId, region);
    }

    private static String secretArn(String name, String region, String accountId, String partition) {
        return new AwsArnUtils.Arn(partition, "secretsmanager", region, accountId, "secret:" + name).toString();
    }

    // ── SSM ──────────────────────────────────────────────────────────────────────
    private String buildSsmArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode json = readJsonBody(ctx);
        if (json != null && json.isObject()) {
            if (json.hasNonNull("Name")) {
                String name = json.get("Name").asText().trim();
                if (!name.isEmpty()) {
                    if (AwsArnUtils.isArnFor(name, "ssm")) {
                        return name;
                    }
                    String paramResource = name.startsWith("/") ? "parameter" + name : "parameter/" + name;
                    return AwsArnUtils.Arn.of("ssm", region, accountId, paramResource).toString();
                }
            }
        }
        return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/*").toString();
    }

    // ── KMS ──────────────────────────────────────────────────────────────────────
    private String buildKmsArn(String path, String region, String accountId) {
        String keyId = extractSegmentAfter(path, "keys");
        if (keyId == null) return AwsArnUtils.Arn.of("kms", region, accountId, "key/*").toString();
        return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyId).toString();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    /** The request's JSON or CBOR body, buffered so the handler still reads it, or null when it has none. */
    public JsonNode readJsonBody(ContainerRequestContext ctx) {
        Object cached = ctx.getProperty("floci.bufferedJsonBody");
        if (cached instanceof JsonNode node) {
            return node;
        }
        InputStream in = ctx.getEntityStream();
        if (in == null) {
            return null;
        }
        byte[] body;
        try {
            body = in.readAllBytes();
        } catch (IOException e) {
            ctx.setEntityStream(new ByteArrayInputStream(new byte[0]));
            return null;
        }
        ctx.setEntityStream(new ByteArrayInputStream(body));
        if (body.length == 0) {
            return null;
        }
        try {
            JsonNode node = (isCbor(ctx.getMediaType()) ? CBOR_MAPPER : objectMapper).readTree(body);
            ctx.setProperty("floci.bufferedJsonBody", node);
            return node;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * A CBOR body, which names its resources in the same members a JSON body does. Both CBOR
     * content types arrive as {@code application/cbor}: {@code AwsCborContentTypeFilter} rewrites
     * {@code x-amz-cbor-1.1} before routing.
     */
    private static boolean isCbor(MediaType mediaType) {
        return mediaType != null
                && "application".equalsIgnoreCase(mediaType.getType())
                && ("cbor".equalsIgnoreCase(mediaType.getSubtype())
                        || "x-amz-cbor-1.1".equalsIgnoreCase(mediaType.getSubtype()));
    }

    private String extractSegmentAfter(String path, String segment) {
        String marker = "/" + segment + "/";
        int idx = path.indexOf(marker);
        if (idx < 0) return null;
        String after = path.substring(idx + marker.length());
        // take only the first segment (stop at next /)
        int slash = after.indexOf('/');
        return slash > 0 ? after.substring(0, slash) : after;
    }

    private String firstFormParam(ContainerRequestContext ctx, String name) {
        // Form params are typically available as query params in REST-Assured / JAX-RS
        String v = ctx.getUriInfo().getQueryParameters().getFirst(name);
        return v;
    }
}
