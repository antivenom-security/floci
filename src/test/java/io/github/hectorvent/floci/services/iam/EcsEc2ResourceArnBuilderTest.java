package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ecs.EcsService;
import jakarta.enterprise.inject.Instance;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The ECS and EC2 security-group resolution rules: what a request names is what it is authorized
 * against, however it names it.
 */
class EcsEc2ResourceArnBuilderTest {

    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String ECS = "arn:aws:ecs:us-east-1:000000000000:";
    private static final String EC2 = "arn:aws:ec2:us-east-1:000000000000:";

    private ContainerRequestContext ctx;
    private Map<String, Object> contextProperties;
    private EcsService ecsService;
    private Ec2Service ec2Service;
    private ResourceArnBuilder builder;

    @BeforeEach
    void setUp() {
        ctx = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
        contextProperties = new HashMap<>();
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMethod()).thenReturn("POST");
        when(uriInfo.getPath()).thenReturn("/");
        when(uriInfo.getQueryParameters()).thenReturn(queryParams);
        when(ctx.getProperty(any())).thenAnswer(inv -> contextProperties.get(inv.getArgument(0)));
        doAnswer(inv -> {
            contextProperties.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(ctx).setProperty(any(), any());

        ecsService = mock(EcsService.class);
        @SuppressWarnings("unchecked")
        Instance<EcsService> instance = mock(Instance.class);
        when(instance.get()).thenReturn(ecsService);
        when(instance.isResolvable()).thenReturn(true);
        ec2Service = mock(Ec2Service.class);
        @SuppressWarnings("unchecked")
        Instance<Ec2Service> ec2Instance = mock(Instance.class);
        when(ec2Instance.get()).thenReturn(ec2Service);
        when(ec2Instance.isResolvable()).thenReturn(true);
        builder = new ResourceArnBuilder(new ObjectMapper(), null, null, null, instance, ec2Instance);
    }

    private List<String> ecs(String action, String json) {
        setBody(json, MediaType.valueOf("application/x-amz-json-1.1"));
        when(ctx.getHeaderString("X-Amz-Target")).thenReturn("AmazonEC2ContainerServiceV20141113." + action);
        return builder.buildResources("ecs", ctx, REGION, ACCOUNT);
    }

    private List<String> ec2(String form) {
        setBody(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        return builder.buildResources("ec2", ctx, REGION, ACCOUNT);
    }

    private void setBody(String body, MediaType mediaType) {
        contextProperties.clear();
        when(ctx.getMediaType()).thenReturn(mediaType);
        when(ctx.getEntityStream()).thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        doAnswer(inv -> {
            InputStream newIn = inv.getArgument(0);
            when(ctx.getEntityStream()).thenReturn(newIn);
            return null;
        }).when(ctx).setEntityStream(any(InputStream.class));
    }

    // ── ECS ─────────────────────────────────────────────────────────────────────

    @Test
    void anUpdateIsAuthorizedAgainstTheServiceTheHandlerUpdates() {
        // UpdateService and DeleteService act on the request's cluster, or the default one, and
        // the name after the reference's last '/', whatever cluster a service ARN names.
        List<String> expected = List.of(ECS + "service/c1/s1");
        assertEquals(expected, ecs("UpdateService", "{\"cluster\":\"c1\",\"service\":\"s1\"}"));
        assertEquals(expected, ecs("UpdateService",
                "{\"cluster\":\"" + ECS + "cluster/c1\",\"service\":\"s1\"}"));
        assertEquals(expected, ecs("UpdateService",
                "{\"cluster\":\"c1\",\"service\":\"" + ECS + "service/s1\"}"));
        assertEquals(expected, ecs("UpdateService",
                "{\"cluster\":\"c1\",\"service\":\"" + ECS + "service/c2/s1\"}"));
        assertEquals(List.of(ECS + "service/default/s1"),
                ecs("DeleteService", "{\"service\":\"" + ECS + "service/c1/s1\"}"));
    }

    @Test
    void aStoredServiceIsAuthorizedByItsOwnArn() {
        when(ecsService.storedServiceArnByName("c1", "s1", REGION)).thenReturn(Optional.of(ECS + "service/c1/s1"));
        assertEquals(List.of(ECS + "service/c1/s1"),
                ecs("UpdateService", "{\"cluster\":\"c1\",\"service\":\"s1\"}"));
        // DescribeServices and the task-set actions find a service by name in any cluster.
        when(ecsService.storedServiceArn(null, "s2", REGION)).thenReturn(Optional.of(ECS + "service/c1/s2"));
        assertEquals(List.of(ECS + "service/c1/s2"), ecs("DescribeServices", "{\"services\":[\"s2\"]}"));
        assertEquals(List.of(ECS + "task-set/c1/s2/*"),
                ecs("CreateTaskSet", "{\"service\":\"s2\",\"taskDefinition\":\"web:1\"}"));
    }

    @Test
    void aStoredTaskIsAuthorizedByItsOwnArnWhateverClusterTheRequestNames() {
        when(ecsService.storedTaskArn("t1", REGION)).thenReturn(Optional.of(ECS + "task/c1/t1"));
        assertEquals(List.of(ECS + "task/c1/t1"), ecs("StopTask", "{\"task\":\"t1\"}"));
        assertEquals(List.of(ECS + "task/c1/t1"), ecs("StopTask", "{\"cluster\":\"c2\",\"task\":\"t1\"}"));
        assertEquals(List.of(ECS + "task/c1/t1"), ecs("DescribeTasks", "{\"tasks\":[\"t1\"]}"));
    }

    @Test
    void anArnFromAnotherRegionKeepsItsRegion() {
        String west = "arn:aws:ecs:us-west-2:000000000000:cluster/c1";
        assertEquals(List.of(west), ecs("DeleteCluster", "{\"cluster\":\"" + west + "\"}"));
        when(ecsService.storedClusterArn(west, REGION)).thenReturn(Optional.of(west));
        assertEquals(List.of(west), ecs("UpdateCluster", "{\"cluster\":\"" + west + "\"}"));
        // A service is keyed by the request's Region, so one under that cluster is minted there.
        assertEquals(List.of(ECS + "service/c1/s1"),
                ecs("UpdateService", "{\"cluster\":\"" + west + "\",\"service\":\"s1\"}"));
        String westTask = "arn:aws:ecs:us-west-2:000000000000:task/c1/t9";
        assertEquals(List.of(westTask), ecs("StopTask", "{\"task\":\"" + westTask + "\"}"));
    }

    @Test
    void aRequestNamingNoClusterActsOnTheDefaultCluster() {
        assertEquals(List.of(ECS + "service/default/s1"), ecs("DeleteService", "{\"service\":\"s1\"}"));
        assertEquals(List.of(ECS + "cluster/default"), ecs("DeleteCluster", "{}"));
        assertEquals(List.of(ECS + "cluster/default"), ecs("DescribeClusters", "{}"));
        assertEquals(List.of(ECS + "cluster/default"), ecs("CreateCluster", "{}"));
        assertEquals(List.of(ECS + "task/default/abc"), ecs("StopTask", "{\"task\":\"abc\"}"));
    }

    @Test
    void aMissingResourceIsAuthorizedAgainstTheArnItsNamingMints() {
        // Nothing is stored, and the answer is still never the wildcard: a deny naming it binds.
        assertEquals(List.of(ECS + "service/nope/ghost"),
                ecs("UpdateService", "{\"cluster\":\"nope\",\"service\":\"ghost\"}"));
        assertEquals(List.of(ECS + "task-definition/ghost:*"),
                ecs("RunTask", "{\"taskDefinition\":\"ghost\"}"));
    }

    @Test
    void describeServicesNamesEveryServiceItAsksAbout() {
        assertEquals(List.of(ECS + "service/c1/s1", ECS + "service/c1/s2", ECS + "service/c2/s3"),
                ecs("DescribeServices", "{\"cluster\":\"c1\",\"services\":[\"s1\",\"" + ECS
                        + "service/c1/s2\",\"" + ECS + "service/c2/s3\"]}"));
    }

    @Test
    void describeClustersNamesEveryCluster() {
        assertEquals(List.of(ECS + "cluster/a", ECS + "cluster/b"),
                ecs("DescribeClusters", "{\"clusters\":[\"a\",\"" + ECS + "cluster/b\"]}"));
    }

    @Test
    void aBareFamilyIsTheRevisionTheHandlerLaunches() {
        when(ecsService.storedTaskDefinitionArn("web", REGION))
                .thenReturn(Optional.of(ECS + "task-definition/web:4"));
        assertEquals(List.of(ECS + "task-definition/web:4"), ecs("RunTask", "{\"taskDefinition\":\"web\"}"));
        assertEquals(List.of(ECS + "task-definition/web:2"), ecs("RunTask", "{\"taskDefinition\":\"web:2\"}"));
        assertEquals(List.of(ECS + "task-definition/web:2"),
                ecs("StartTask", "{\"taskDefinition\":\"" + ECS + "task-definition/web:2\"}"));
    }

    @Test
    void aRegistrationIsMintedAsTheRevisionItWouldMake() {
        when(ecsService.nextTaskDefinitionRevision("web", REGION)).thenReturn(5);
        assertEquals(List.of(ECS + "task-definition/web:5"),
                ecs("RegisterTaskDefinition", "{\"family\":\"web\",\"containerDefinitions\":[]}"));
    }

    @Test
    void aCreateIsMintedFromItsRequest() {
        assertEquals(List.of(ECS + "service/c1/new"),
                ecs("CreateService", "{\"cluster\":\"c1\",\"serviceName\":\"new\"}"));
        assertEquals(List.of(ECS + "cluster/fresh"), ecs("CreateCluster", "{\"clusterName\":\"fresh\"}"));
        assertEquals(List.of(ECS + "task-set/c1/s1/*"),
                ecs("CreateTaskSet", "{\"cluster\":\"c1\",\"service\":\"s1\",\"taskDefinition\":\"web:1\"}"));
        assertEquals(List.of(ECS + "capacity-provider/cp"), ecs("CreateCapacityProvider", "{\"name\":\"cp\"}"));
    }

    @Test
    void anActionOnSeveralTypesNamesEach() {
        assertEquals(List.of(ECS + "cluster/c1", ECS + "task/c1/t1"),
                ecs("ExecuteCommand", "{\"cluster\":\"c1\",\"task\":\"t1\",\"command\":\"ls\"}"));
        String deployment = ECS + "service-deployment/c1/s1/d1";
        assertEquals(List.of(ECS + "service/c1/s1", deployment),
                ecs("DescribeServiceDeployments", "{\"serviceDeploymentArns\":[\"" + deployment + "\"]}"));
        String revision = ECS + "service-revision/c1/s1/r1";
        assertEquals(List.of(ECS + "service/c1/s1", revision),
                ecs("DescribeServiceRevisions", "{\"serviceRevisionArns\":[\"" + revision + "\"]}"));
    }

    @Test
    void tasksAndContainerInstancesTakeTheirClusterFromTheirArn() {
        assertEquals(List.of(ECS + "task/c1/t1", ECS + "task/c2/t2"),
                ecs("DescribeTasks", "{\"cluster\":\"c1\",\"tasks\":[\"t1\",\"" + ECS + "task/c2/t2\"]}"));
        assertEquals(List.of(ECS + "container-instance/c1/i1"),
                ecs("PutAttributes", "{\"cluster\":\"c1\",\"attributes\":[{\"name\":\"a\","
                        + "\"targetType\":\"container-instance\",\"targetId\":\"i1\"}]}"));
    }

    @Test
    void theTaggingActionsPassTheirArnThrough() {
        String daemon = ECS + "daemon/c1/d1";
        assertEquals(List.of(daemon), ecs("TagResource", "{\"resourceArn\":\"" + daemon + "\",\"tags\":[]}"));
        assertEquals(List.of(daemon), ecs("ListTagsForResource", "{\"resourceArn\":\"" + daemon + "\"}"));
    }

    @Test
    void aJsonNullIsReadAsTheHandlerReadsIt() {
        // EcsJsonHandler reads members with asText(), so a null service is the service "null".
        assertEquals(List.of(ECS + "service/c1/null"),
                ecs("UpdateService", "{\"cluster\":\"c1\",\"service\":null}"));
        assertEquals(List.of(ECS + "cluster/null"), ecs("DeleteCluster", "{\"cluster\":null}"));
    }

    @Test
    void anUnresolvableStoreFallsBackToTheRequestsNaming() {
        @SuppressWarnings("unchecked")
        Instance<EcsService> unresolvable = mock(Instance.class);
        when(unresolvable.isResolvable()).thenReturn(false);
        builder = new ResourceArnBuilder(new ObjectMapper(), null, null, null, unresolvable, null);
        assertEquals(List.of(ECS + "task/default/t1"), ecs("StopTask", "{\"task\":\"t1\"}"));
        assertEquals(List.of(ECS + "task-definition/web:*"),
                ecs("RegisterTaskDefinition", "{\"family\":\"web\"}"));
    }

    @Test
    void anActionAwsGivesNoResourceIsTheWildcard() {
        assertEquals(List.of("*"), ecs("ListClusters", "{}"));
        assertEquals(List.of("*"), ecs("DescribeTaskDefinition", "{\"taskDefinition\":\"web\"}"));
        assertEquals(List.of("*"), ecs("ListServices", "{\"cluster\":\"c1\"}"));
    }

    // ── EC2 ─────────────────────────────────────────────────────────────────────

    @Test
    void aSecurityGroupActionIsAuthorizedAgainstTheGroup() {
        assertEquals(List.of(EC2 + "security-group/sg-b"),
                ec2("Action=RevokeSecurityGroupEgress&GroupId=sg-b&IpPermissions.1.IpProtocol=-1"));
    }

    @Test
    void aGroupARuleRefersToIsNotTheResource() {
        assertEquals(List.of(EC2 + "security-group/sg-a"),
                ec2("Action=AuthorizeSecurityGroupIngress&GroupId=sg-a"
                        + "&IpPermissions.1.IpProtocol=-1&IpPermissions.1.Groups.1.GroupId=sg-src"));
    }

    @Test
    void aCreateIsAuthorizedAgainstEveryGroupAndTheVpcItIsCreatedIn() {
        // AWS also checks the VPC, which is not vendored, so the wildcard stays beside the group.
        assertEquals(List.of(EC2 + "security-group/*", "*"),
                ec2("Action=CreateSecurityGroup&GroupName=n&Description=d"));
    }

    @Test
    void aNetworkInterfaceNamesItsGroupsEitherWay() {
        assertEquals(List.of(EC2 + "security-group/sg-b", "*"),
                ec2("Action=CreateNetworkInterface&SubnetId=subnet-1&Groups.SecurityGroupId.1=sg-b"));
        assertEquals(List.of(EC2 + "security-group/sg-a", "*"),
                ec2("Action=CreateNetworkInterface&SubnetId=subnet-1&SecurityGroupId.1=sg-a"));
    }

    @Test
    void anActionOnOtherResourcesTooKeepsTheWildcardBesideTheGroups() {
        assertEquals(List.of(EC2 + "security-group/sg-a", EC2 + "security-group/sg-b", "*"),
                ec2("Action=RunInstances&ImageId=ami-1&MinCount=1&MaxCount=1"
                        + "&SecurityGroupId.1=sg-a&NetworkInterface.1.SecurityGroupId.1=sg-b"));
        assertEquals(List.of(EC2 + "security-group/sg-a", "*"),
                ec2("Action=CreateTags&ResourceId.1=sg-a&ResourceId.2=i-1&Tag.1.Key=k&Tag.1.Value=v"));
    }

    @Test
    void aLaunchNamingNoGroupIsAuthorizedAgainstItsTemplatesGroups() {
        when(ec2Service.launchTemplateSecurityGroupIds(REGION, "lt-1", null, "2")).thenReturn(List.of("sg-t"));
        assertEquals(List.of(EC2 + "security-group/sg-t", "*"),
                ec2("Action=RunInstances&MinCount=1&MaxCount=1"
                        + "&LaunchTemplate.LaunchTemplateId=lt-1&LaunchTemplate.Version=2"));
        // Groups named on the request win over the template's, as they do in the handler.
        assertEquals(List.of(EC2 + "security-group/sg-a", "*"),
                ec2("Action=RunInstances&MinCount=1&MaxCount=1&SecurityGroupId.1=sg-a"
                        + "&LaunchTemplate.LaunchTemplateId=lt-1&LaunchTemplate.Version=2"));
    }

    @Test
    void aRepeatedSingleValuedMemberIsReadFirstAsTheHandlerReadsIt() {
        when(ec2Service.launchTemplateSecurityGroupIds(REGION, "lt-real", null, null)).thenReturn(List.of("sg-t"));
        assertEquals(List.of(EC2 + "security-group/sg-t", "*"),
                ec2("Action=RunInstances&MinCount=1&MaxCount=1"
                        + "&LaunchTemplate.LaunchTemplateId=lt-real&LaunchTemplate.LaunchTemplateId=lt-other"));
        assertEquals(List.of(EC2 + "security-group/first"),
                ec2("Action=DeleteSecurityGroup&GroupName=first&GroupName=second"));
    }

    @Test
    void anActionNamingNoGroupStaysOnTheWildcard() {
        assertEquals(List.of("*"), ec2("Action=CreateTags&ResourceId.1=i-1&Tag.1.Key=k&Tag.1.Value=v"));
        assertEquals(List.of("*"), ec2("Action=RunInstances&ImageId=ami-1&MinCount=1&MaxCount=1"));
        assertEquals(List.of("*"), ec2("Action=DescribeSecurityGroups&GroupId.1=sg-a"));
        assertEquals(List.of("*"), ec2("Action=CreateVpc&CidrBlock=10.0.0.0/16"));
    }
}
