package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testing.EnforcementFixtures;
import io.github.hectorvent.floci.testing.IamEnforcementProfile;
import io.github.hectorvent.floci.testing.PartitionCleanup;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.IpPermission;
import software.amazon.awssdk.services.ec2.model.IpRange;
import software.amazon.awssdk.services.ecs.EcsClient;
import software.amazon.awssdk.services.ecs.model.Compatibility;
import software.amazon.awssdk.services.ecs.model.LaunchType;
import software.amazon.awssdk.services.ecs.model.NetworkMode;

import java.net.URI;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Under enforcement, a policy naming one ECS service or one security group binds to that resource
 * and no other. Before these were resolved, every ECS and EC2 call reached the evaluator as
 * {@code *}, so a Deny naming a service or a group never matched and a scoped policy silently
 * failed open. Driven through the SDKs, so the request is what a real client sends.
 */
@QuarkusTest
@TestProfile(IamEnforcementProfile.class)
class EcsEc2ResourceScopedEnforcementIntegrationTest {

    private static final String ACCOUNT_ID = "000000000000";
    private static final String ECS_ARN = "arn:aws:ecs:us-east-1:" + ACCOUNT_ID + ":";
    private static final String EC2_ARN = "arn:aws:ec2:us-east-1:" + ACCOUNT_ID + ":";

    @RegisterExtension
    final PartitionCleanup cleanup = new PartitionCleanup();

    @TestHTTPResource("/")
    URI baseUri;

    @Test
    void aDenyNamingOneServiceLeavesTheOthersAlone() {
        String suffix = suffix();
        String cluster = "c1-" + suffix;
        seedServices(cluster, "s1", "s2");
        try (EcsClient ecs = ecs(userWith("""
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"ecs:*","Resource":"*"},
                  {"Effect":"Deny","Action":"ecs:UpdateService","Resource":"%s"}]}"""
                .formatted(ECS_ARN + "service/" + cluster + "/s2")))) {
            ecs.updateService(r -> r.cluster(cluster).service("s1").desiredCount(0));
            assertDenied(() -> ecs.updateService(r -> r.cluster(cluster).service("s2").desiredCount(0)));
            // Named by its ARN, the denied service is the same resource.
            assertDenied(() -> ecs.updateService(r -> r.cluster(ECS_ARN + "cluster/" + cluster)
                    .service(ECS_ARN + "service/" + cluster + "/s2").desiredCount(0)));
        }
    }

    @Test
    void anAllowScopedToOneClusterDoesNotReachAnother() {
        String suffix = suffix();
        String inside = "c1-" + suffix;
        String outside = "c2-" + suffix;
        seedServices(inside, "s1");
        seedServices(outside, "s1");
        try (EcsClient ecs = ecs(userWith("""
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"ecs:UpdateService","Resource":"%s"}]}"""
                .formatted(ECS_ARN + "service/" + inside + "/*")))) {
            ecs.updateService(r -> r.cluster(inside).service("s1").desiredCount(0));
            assertDenied(() -> ecs.updateService(r -> r.cluster(outside).service("s1").desiredCount(0)));
        }
    }

    @Test
    void describeServicesNamingOneDeniedServiceIsDeniedAsAWhole() {
        String suffix = suffix();
        String cluster = "c1-" + suffix;
        seedServices(cluster, "s1", "s2");
        try (EcsClient ecs = ecs(userWith("""
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"ecs:*","Resource":"*"},
                  {"Effect":"Deny","Action":"ecs:DescribeServices","Resource":"%s"}]}"""
                .formatted(ECS_ARN + "service/" + cluster + "/s2")))) {
            assertEquals(1, ecs.describeServices(r -> r.cluster(cluster).services("s1")).services().size());
            assertDenied(() -> ecs.describeServices(r -> r.cluster(cluster).services("s1", "s2")));
        }
    }

    @Test
    void aDenyNamingOneSecurityGroupLeavesTheOthersAlone() {
        String suffix = suffix();
        String groupA = createSecurityGroup("sg-a-" + suffix);
        String groupB = createSecurityGroup("sg-b-" + suffix);
        try (Ec2Client ec2 = ec2(userWith("""
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"ec2:*","Resource":"*"},
                  {"Effect":"Deny","Action":"ec2:RevokeSecurityGroupEgress","Resource":"%s"}]}"""
                .formatted(EC2_ARN + "security-group/" + groupB)))) {
            ec2.revokeSecurityGroupEgress(r -> r.groupId(groupA).ipPermissions(allTraffic()));
            assertEc2Denied(() -> ec2.revokeSecurityGroupEgress(r -> r.groupId(groupB).ipPermissions(allTraffic())));
        }
    }

    /**
     * A task is found by its id in any cluster, so a deny on c1's task binds however the request
     * names the cluster: not at all, or as another one.
     */
    @Test
    void aDenyNamingOneTaskBindsWhateverClusterTheRequestNames() {
        String suffix = suffix();
        String cluster = "c1-" + suffix;
        String other = "c2-" + suffix;
        seedServices(other);
        String denied = runTask(cluster);
        String deniedId = denied.substring(denied.lastIndexOf('/') + 1);
        String kept = runTask(cluster);
        try (EcsClient ecs = ecs(userWith(denyingEcs("StopTask", denied)))) {
            assertDenied(() -> ecs.stopTask(r -> r.task(deniedId)));
            assertDenied(() -> ecs.stopTask(r -> r.cluster(other).task(deniedId)));
            assertDenied(() -> ecs.stopTask(r -> r.cluster(cluster).task(deniedId)));
            ecs.stopTask(r -> r.cluster(cluster).task(kept));
        }
    }

    /**
     * UpdateService acts on the request's cluster and the ARN's last segment, so an ARN naming
     * another cluster still reaches the denied service.
     */
    @Test
    void aServiceArnNamingAnotherClusterStillReachesTheDeniedService() {
        String suffix = suffix();
        String cluster = "c1-" + suffix;
        seedServices(cluster, "s2");
        try (EcsClient ecs = ecs(userWith(denyingEcs("UpdateService", ECS_ARN + "service/" + cluster + "/s2")))) {
            assertDenied(() -> ecs.updateService(r -> r.cluster(cluster)
                    .service(ECS_ARN + "service/elsewhere-" + suffix + "/s2").desiredCount(0)));
        }
    }

    /** DescribeServices finds a service by name in any cluster, so naming no cluster does not dodge a deny. */
    @Test
    void aServiceNamedWithoutItsClusterIsStillTheDeniedOne() {
        String suffix = suffix();
        String cluster = "c1-" + suffix;
        String service = "only-" + suffix;
        seedServices(cluster, service);
        try (EcsClient ecs = ecs(userWith(denyingEcs("DescribeServices",
                ECS_ARN + "service/" + cluster + "/" + service)))) {
            assertDenied(() -> ecs.describeServices(r -> r.services(service)));
            assertDenied(() -> ecs.describeServices(r -> r.cluster("default").services(service)));
        }
    }

    /** A cluster is found by ARN in any Region, so its ARN is authorized as it is, not re-minted here. */
    @Test
    void aClusterArnFromAnotherRegionIsAuthorizedInThatRegion() {
        String cluster = "west-" + suffix();
        EcsClient west = ecs(new EnforcementFixtures.UserCredentials("test", "test"), Region.US_WEST_2);
        cleanup.register(west::close);
        String westArn = west.createCluster(r -> r.clusterName(cluster)).cluster().clusterArn();
        cleanup.register(() -> west.deleteCluster(r -> r.cluster(cluster)));
        try (EcsClient ecs = ecs(userWith(denyingEcs("DeleteCluster", westArn)))) {
            assertDenied(() -> ecs.deleteCluster(r -> r.cluster(westArn)));
        }
    }

    /** CreateNetworkInterface also takes its groups as Groups.SecurityGroupId.N, which the handler reads. */
    @Test
    void aGroupNamedInTheGroupsFormIsStillTheDeniedOne() {
        String groupB = createSecurityGroup("sg-b-" + suffix());
        String akid = userWith("""
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"ec2:*","Resource":"*"},
                  {"Effect":"Deny","Action":"ec2:CreateNetworkInterface","Resource":"%s"}]}"""
                .formatted(EC2_ARN + "security-group/" + groupB)).accessKeyId();
        given().header("Authorization", EnforcementFixtures.auth(akid, "ec2"))
                .formParam("Action", "CreateNetworkInterface")
                .formParam("Version", "2016-11-15")
                .formParam("SubnetId", "subnet-default-us-east-1-a")
                .formParam("Groups.SecurityGroupId.1", groupB)
            .when().post(baseUri)
            .then().statusCode(403).body(containsString("UnauthorizedOperation"));
    }

    /** AWS also checks the VPC for CreateSecurityGroup, so an Allow on the group alone does not grant it. */
    @Test
    void anAllowOnGroupsAloneDoesNotGrantCreateSecurityGroup() {
        try (Ec2Client ec2 = ec2(userWith("""
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"ec2:CreateSecurityGroup","Resource":"%s"}]}"""
                .formatted(EC2_ARN + "security-group/*")))) {
            String name = "widen-" + suffix();
            assertEc2Denied(() -> ec2.createSecurityGroup(r -> r.groupName(name).description(name)));
        }
    }

    /**
     * A bare family is the revision the handler launches, which is the family's latest even once
     * it is deregistered, so a deny on that revision binds a RunTask naming the family alone.
     */
    @Test
    void aBareFamilyIsAuthorizedAsTheRevisionTheHandlerLaunches() {
        String cluster = "c1-" + suffix();
        String family = "fam-" + cluster;
        EcsClient admin = ecs(new EnforcementFixtures.UserCredentials("test", "test"));
        cleanup.register(admin::close);
        cleanup.register(() -> admin.deleteCluster(r -> r.cluster(cluster)));
        admin.createCluster(r -> r.clusterName(cluster));
        registerFargate(admin, family);
        String latest = registerFargate(admin, family);
        admin.deregisterTaskDefinition(r -> r.taskDefinition(latest));
        try (EcsClient ecs = ecs(userWith(denyingEcs("RunTask", latest)))) {
            assertDenied(() -> ecs.runTask(r -> r.cluster(cluster).taskDefinition(family)
                    .launchType(LaunchType.FARGATE)
                    .networkConfiguration(n -> n.awsvpcConfiguration(a -> a.subnets("subnet-default-us-east-1-a")))));
        }
    }

    /**
     * The handler reads LaunchTemplate.LaunchTemplateId with getFirst, so a second copy naming a
     * template that does not exist does not hide the first one's groups.
     */
    @Test
    void aRepeatedLaunchTemplateIdIsReadAsTheHandlerReadsIt() {
        String suffix = suffix();
        String groupB = createSecurityGroup("sg-b-" + suffix);
        Ec2Client admin = ec2(new EnforcementFixtures.UserCredentials("test", "test"));
        cleanup.register(admin::close);
        String templateId = admin.createLaunchTemplate(r -> r.launchTemplateName("lt-" + suffix)
                        .launchTemplateData(d -> d.securityGroupIds(groupB)))
                .launchTemplate().launchTemplateId();
        cleanup.register(() -> admin.deleteLaunchTemplate(r -> r.launchTemplateId(templateId)));
        String akid = userWith("""
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"ec2:*","Resource":"*"},
                  {"Effect":"Deny","Action":"ec2:RunInstances","Resource":"%s"}]}"""
                .formatted(EC2_ARN + "security-group/" + groupB)).accessKeyId();
        given().header("Authorization", EnforcementFixtures.auth(akid, "ec2"))
                .formParam("Action", "RunInstances")
                .formParam("Version", "2016-11-15")
                .formParam("MinCount", "1")
                .formParam("MaxCount", "1")
                .formParam("LaunchTemplate.LaunchTemplateId", templateId, "lt-0123456789abcdef0")
            .when().post(baseUri)
            .then().statusCode(403).body(containsString("UnauthorizedOperation"));
    }

    // ── Fixtures ────────────────────────────────────────────────────────────────

    private static IpPermission allTraffic() {
        return IpPermission.builder().ipProtocol("-1").ipRanges(IpRange.builder().cidrIp("0.0.0.0/0").build())
                .build();
    }

    /** ECS speaks JSON 1.1, where AccessDeniedException is a 400. */
    private static void assertDenied(Runnable call) {
        AwsServiceException denied = assertThrows(AwsServiceException.class, call::run);
        assertEquals("AccessDeniedException", denied.awsErrorDetails().errorCode(), denied.getMessage());
    }

    /** EC2 answers a denial with UnauthorizedOperation in its own envelope, which the SDK parses. */
    private static void assertEc2Denied(Runnable call) {
        AwsServiceException denied = assertThrows(AwsServiceException.class, call::run);
        assertEquals(403, denied.statusCode(), denied.getMessage());
        assertEquals("UnauthorizedOperation", denied.awsErrorDetails().errorCode(), denied.getMessage());
        assertTrue(denied.awsErrorDetails().errorMessage()
                .contains("not authorized to perform: ec2:"), denied.getMessage());
    }

    /** A cluster holding one empty service per name, all on one task definition, removed after the test. */
    private void seedServices(String cluster, String... services) {
        String family = "fam-" + cluster;
        EcsClient admin = ecs(new EnforcementFixtures.UserCredentials("test", "test"));
        cleanup.register(admin::close);
        cleanup.register(() -> admin.deleteCluster(r -> r.cluster(cluster)));
        admin.createCluster(r -> r.clusterName(cluster));
        String taskDefinition = admin.registerTaskDefinition(r -> r.family(family)
                        .containerDefinitions(c -> c.name("web").image("nginx").memory(128)))
                .taskDefinition().taskDefinitionArn();
        cleanup.register(() -> admin.deregisterTaskDefinition(r -> r.taskDefinition(taskDefinition)));
        for (String service : services) {
            cleanup.register(() -> admin.deleteService(r -> r.cluster(cluster).service(service).force(true)));
            admin.createService(r -> r.cluster(cluster).serviceName(service)
                    .taskDefinition(taskDefinition).desiredCount(0));
        }
    }

    private String createSecurityGroup(String name) {
        Ec2Client admin = ec2(new EnforcementFixtures.UserCredentials("test", "test"));
        cleanup.register(admin::close);
        String groupId = admin.createSecurityGroup(r -> r.groupName(name).description(name)).groupId();
        cleanup.register(() -> admin.deleteSecurityGroup(r -> r.groupId(groupId)));
        return groupId;
    }

    private EnforcementFixtures.UserCredentials userWith(String policy) {
        String user = "ecs-ec2-" + suffix();
        String adminAuth = EnforcementFixtures.auth(ACCOUNT_ID, "iam");
        EnforcementFixtures.UserCredentials credentials =
                EnforcementFixtures.createUser(cleanup, baseUri.getPort(), adminAuth, user);
        EnforcementFixtures.putUserPolicy(baseUri.getPort(), adminAuth, user, "p", policy);
        return credentials;
    }

    private static String denyingEcs(String action, String resource) {
        return """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"ecs:*","Resource":"*"},
                  {"Effect":"Deny","Action":"ecs:%s","Resource":"%s"}]}""".formatted(action, resource);
    }

    private static String registerFargate(EcsClient admin, String family) {
        return admin.registerTaskDefinition(r -> r.family(family)
                        .requiresCompatibilities(Compatibility.FARGATE).networkMode(NetworkMode.AWSVPC)
                        .cpu("256").memory("512")
                        .containerDefinitions(c -> c.name("web").image("nginx")))
                .taskDefinition().taskDefinitionArn();
    }

    /** Runs one Fargate task in {@code cluster}, created if needed, and returns its ARN; ECS runs in mock mode here. */
    private String runTask(String cluster) {
        EcsClient admin = ecs(new EnforcementFixtures.UserCredentials("test", "test"));
        cleanup.register(admin::close);
        if (admin.describeClusters(r -> r.clusters(cluster)).clusters().isEmpty()) {
            cleanup.register(() -> admin.deleteCluster(r -> r.cluster(cluster)));
            admin.createCluster(r -> r.clusterName(cluster));
        }
        String taskDefinition = admin.registerTaskDefinition(r -> r.family("task-" + cluster)
                        .requiresCompatibilities(Compatibility.FARGATE).networkMode(NetworkMode.AWSVPC)
                        .cpu("256").memory("512")
                        .containerDefinitions(c -> c.name("web").image("nginx")))
                .taskDefinition().taskDefinitionArn();
        cleanup.register(() -> admin.deregisterTaskDefinition(r -> r.taskDefinition(taskDefinition)));
        String taskArn = admin.runTask(r -> r.cluster(cluster).taskDefinition(taskDefinition)
                        .launchType(LaunchType.FARGATE)
                        .networkConfiguration(n -> n.awsvpcConfiguration(a -> a.subnets("subnet-default-us-east-1-a"))))
                .tasks().getFirst().taskArn();
        cleanup.register(() -> admin.stopTask(r -> r.cluster(cluster).task(taskArn)));
        return taskArn;
    }

    private EcsClient ecs(EnforcementFixtures.UserCredentials credentials) {
        return ecs(credentials, Region.US_EAST_1);
    }

    private EcsClient ecs(EnforcementFixtures.UserCredentials credentials, Region region) {
        return EcsClient.builder().endpointOverride(baseUri).region(region)
                .credentialsProvider(provider(credentials))
                .httpClient(UrlConnectionHttpClient.create()).build();
    }

    private Ec2Client ec2(EnforcementFixtures.UserCredentials credentials) {
        return Ec2Client.builder().endpointOverride(baseUri).region(Region.US_EAST_1)
                .credentialsProvider(provider(credentials))
                .httpClient(UrlConnectionHttpClient.create()).build();
    }

    private static StaticCredentialsProvider provider(EnforcementFixtures.UserCredentials credentials) {
        return StaticCredentialsProvider.create(
                AwsBasicCredentials.create(credentials.accessKeyId(), credentials.secretAccessKey()));
    }

    private static String suffix() {
        return UUID.randomUUID().toString().substring(0, 8);
    }
}
