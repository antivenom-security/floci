package io.github.hectorvent.floci.services.ec2;

import com.github.dockerjava.api.DockerClient;
import io.github.hectorvent.floci.core.common.docker.ContainerExec;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.cloudwatch.logs.model.LogStream;
import io.github.hectorvent.floci.services.ecs.EcsService;
import io.github.hectorvent.floci.services.ecs.model.AwsVpcConfiguration;
import io.github.hectorvent.floci.services.ecs.model.ContainerDefinition;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.github.hectorvent.floci.services.ecs.model.NetworkConfiguration;
import io.github.hectorvent.floci.services.ecs.model.NetworkMode;
import io.github.hectorvent.floci.services.ecs.model.RunTaskRequest;
import io.github.hectorvent.floci.services.ecs.model.TaskDefinition;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.github.hectorvent.floci.testing.TestImages;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.ValidatableResponse;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Observed flow logs end to end: two awsvpc tasks talk through their security groups, a third
 * stays idle, and the delivered S3 records and CloudWatch Logs streams show what the packets did.
 */
@QuarkusTest
@TestProfile(FlowLogObservedDockerIntegrationTest.ObservedProfile.class)
class FlowLogObservedDockerIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String SUBNET = "subnet-default-us-east-1-a";
    private static final String AUTH = "AWS4-HMAC-SHA256 Credential=test/20261022/us-east-1/ec2/aws4_request";
    private static final String FORMAT = "${version} ${vpc-id} ${ecs-task-id} ${flow-direction} ${interface-id} "
            + "${srcaddr} ${dstaddr} ${dstport} ${action} ${log-status}";

    /** Real task containers, and short ticks so one 60 second window closes within the test. */
    public static final class ObservedProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.ecs.mock", "false",
                    "floci.services.ec2.flow-logs.capture-tick-seconds", "2",
                    "floci.services.ec2.flow-logs.s3-publish-interval-seconds", "1");
        }
    }

    @Inject EcsService ecsService;
    @Inject S3Service s3Service;
    @Inject CloudWatchLogsService logsService;
    @Inject SecurityGroupFirewallManager firewall;
    @Inject DockerClient docker;

    @Test
    @Timeout(value = 5, unit = TimeUnit.MINUTES)
    void acceptRejectAndNodataAreObservedAtEachEni() throws Exception {
        Assumptions.assumeTrue(firewall.enabled());
        try {
            Assumptions.assumeTrue("linux".equalsIgnoreCase(docker.infoCmd().exec().getOsType()));
        } catch (RuntimeException e) {
            Assumptions.abort("Docker daemon is unavailable");
        }
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String vpcId = ec2("DescribeSubnets", "SubnetId.1", SUBNET).statusCode(200)
                .extract().path("DescribeSubnetsResponse.subnetSet.item.vpcId");
        String sgA = securityGroup("flow-a-" + suffix, vpcId);
        String sgB = securityGroup("flow-b-" + suffix, vpcId);
        ec2("AuthorizeSecurityGroupIngress", "GroupId", sgA, "IpPermissions.1.IpProtocol", "tcp",
                "IpPermissions.1.FromPort", "8080", "IpPermissions.1.ToPort", "8080",
                "IpPermissions.1.Groups.1.GroupId", sgB).statusCode(200);
        String bucket = "flow-" + suffix;
        s3Service.createBucket(bucket, REGION);
        String group = "/flow/" + suffix;
        List<String> flowLogIds = List.of(
                ec2("CreateFlowLogs", "ResourceType", "VPC", "ResourceId.1", vpcId, "TrafficType", "ALL",
                        "LogDestinationType", "s3", "LogDestination", "arn:aws:s3:::" + bucket,
                        "LogFormat", FORMAT, "MaxAggregationInterval", "60").statusCode(200)
                        .extract().path("CreateFlowLogsResponse.flowLogIdSet.item"),
                ec2("CreateFlowLogs", "ResourceType", "VPC", "ResourceId.1", vpcId, "TrafficType", "ALL",
                        "LogDestinationType", "cloud-watch-logs", "LogGroupName", group,
                        "DeliverLogsPermissionArn", "arn:aws:iam::000000000000:role/flow-logs",
                        "MaxAggregationInterval", "60").statusCode(200)
                        .extract().path("CreateFlowLogsResponse.flowLogIdSet.item"));

        String cluster = "flow-" + suffix;
        ecsService.createCluster(cluster, REGION);
        ContainerDefinition app = new ContainerDefinition();
        app.setName("app");
        app.setImage(TestImages.BUSYBOX);
        app.setCommand(List.of("httpd", "-f", "-p", "8080", "-h", "/"));
        TaskDefinition definition = ecsService.registerTaskDefinition("flow-" + suffix, List.of(app),
                NetworkMode.awsvpc, null, null, null, null, null, REGION);
        List<EcsTask> tasks = new ArrayList<>();
        try {
            EcsTask a = runTask(cluster, definition, sgA);
            tasks.add(a);
            EcsTask b = runTask(cluster, definition, sgB);
            tasks.add(b);
            EcsTask c = runTask(cluster, definition, sgB);
            tasks.add(c);
            String transportA = transport(a);
            String transportB = transport(b);

            exec(b, "wget -q -T 3 -O /dev/null http://" + transportA + ":8080/ || true");
            exec(a, "nc -w 2 " + transportB + " 9090 </dev/null || true");

            String eniA = a.getNetworkInterfaceId();
            String eniB = b.getNetworkInterfaceId();
            String eniC = c.getNetworkInterfaceId();
            String ipA = a.getPrivateIpAddress();
            String ipB = b.getPrivateIpAddress();
            String idA = taskId(a);
            String idB = taskId(b);
            Set<String> expected = Set.of(
                    "7 " + vpcId + " " + idA + " ingress " + eniA + " " + ipB + " " + ipA + " 8080 ACCEPT OK",
                    "7 " + vpcId + " " + idB + " egress " + eniB + " " + ipB + " " + ipA + " 8080 ACCEPT OK",
                    "7 " + vpcId + " " + idB + " ingress " + eniB + " " + ipA + " " + ipB + " 9090 REJECT OK",
                    "7 - - - " + eniC + " - - - - NODATA");
            Set<String> rows = new LinkedHashSet<>();
            for (int attempt = 0; attempt < 75 && !rows.containsAll(expected); attempt++) {
                Thread.sleep(2000);
                rows.addAll(deliveredRows(bucket));
            }
            assertTrue(rows.containsAll(expected), "missing " + expected + " in " + rows);
            assertTrue(rows.stream().anyMatch(row -> row.startsWith("7 " + vpcId + " " + idA + " egress " + eniA
                    + " " + ipA + " " + ipB + " ") && row.endsWith(" ACCEPT OK")), "A's reply to B: " + rows);
            assertTrue(rows.stream().anyMatch(row -> row.startsWith("7 " + vpcId + " " + idB + " ingress " + eniB
                    + " " + ipA + " " + ipB + " ") && row.endsWith(" ACCEPT OK")), "B's reply from A: " + rows);

            List<String> streams = new ArrayList<>();
            for (int attempt = 0; attempt < 30 && streams.size() < 3; attempt++) {
                streams = logsService.logGroupExists(group, REGION)
                        ? logsService.describeLogStreams(group, null, REGION).stream()
                                .map(LogStream::getLogStreamName).sorted().toList()
                        : List.of();
                Thread.sleep(1000);
            }
            assertEquals(List.of(eniA + "-all", eniB + "-all", eniC + "-all").stream().sorted().toList(), streams);
        } finally {
            for (EcsTask task : tasks) {
                ecsService.stopTask(cluster, task.getTaskArn(), "test teardown", REGION);
            }
            for (String id : flowLogIds) {
                ec2("DeleteFlowLogs", "FlowLogId.1", id);
            }
        }
    }

    private List<String> deliveredRows(String bucket) throws Exception {
        List<String> rows = new ArrayList<>();
        for (S3Object listed : s3Service.listObjects(bucket, "AWSLogs/", null, 1000)) {
            assertTrue(listed.getKey().matches("AWSLogs/000000000000/vpcflowlogs/us-east-1/\\d{4}/\\d{2}/\\d{2}/"
                    + "000000000000_vpcflowlogs_us-east-1_fl-[0-9a-f]{17}_\\d{8}T\\d{4}Z_[0-9a-f]{8}\\.log\\.gz"),
                    listed.getKey());
            byte[] data = s3Service.getObject(bucket, listed.getKey()).getData();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data))) {
                List<String> lines = List.of(new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n"));
                assertEquals("version vpc-id ecs-task-id flow-direction interface-id srcaddr dstaddr dstport "
                        + "action log-status", lines.getFirst());
                rows.addAll(lines.subList(1, lines.size()));
            }
        }
        return rows;
    }

    private EcsTask runTask(String cluster, TaskDefinition definition, String securityGroup) throws Exception {
        AwsVpcConfiguration awsvpc = new AwsVpcConfiguration();
        awsvpc.setSubnets(List.of(SUBNET));
        awsvpc.setSecurityGroups(List.of(securityGroup));
        NetworkConfiguration network = new NetworkConfiguration();
        network.setAwsvpcConfiguration(awsvpc);
        RunTaskRequest request = new RunTaskRequest();
        request.setCluster(cluster);
        request.setTaskDefinition(definition.getTaskDefinitionArn());
        request.setNetworkConfiguration(network);
        String taskArn = ecsService.runTask(request, REGION).getFirst().getTaskArn();
        for (int attempt = 0; attempt < 60; attempt++) {
            EcsTask task = ecsService.describeTasks(cluster, List.of(taskArn), REGION).getFirst();
            if ("RUNNING".equals(task.getLastStatus())) {
                return task;
            }
            Thread.sleep(1000);
        }
        throw new AssertionError("task " + taskArn + " did not reach RUNNING");
    }

    private String transport(EcsTask task) {
        return firewall.protectedEndpoints().stream()
                .filter(endpoint -> endpoint.endpoint().eniId().equals(task.getNetworkInterfaceId()))
                .findFirst().orElseThrow().endpoint().transportAddress();
    }

    private void exec(EcsTask task, String command) {
        ContainerExec.run(docker, task.getContainers().getFirst().getDockerId(),
                new String[]{"sh", "-c", command}, 15);
    }

    private static String taskId(EcsTask task) {
        return task.getTaskArn().substring(task.getTaskArn().lastIndexOf('/') + 1);
    }

    private static String securityGroup(String name, String vpcId) {
        return ec2("CreateSecurityGroup", "GroupName", name, "GroupDescription", name, "VpcId", vpcId)
                .statusCode(200).extract().path("CreateSecurityGroupResponse.groupId");
    }

    private static ValidatableResponse ec2(String action, String... params) {
        RequestSpecification request = given().header("Authorization", AUTH).formParam("Action", action);
        for (int i = 0; i < params.length; i += 2) {
            request = request.formParam(params[i], params[i + 1]);
        }
        return request.when().post("/").then();
    }
}
