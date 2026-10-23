package io.github.hectorvent.floci.core.common.dns;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.dockerjava.api.DockerClient;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.SecurityGroupFirewallManager;
import io.github.hectorvent.floci.services.ecs.EcsService;
import io.github.hectorvent.floci.services.ecs.container.EcsContainerManager;
import io.github.hectorvent.floci.services.ecs.model.AwsVpcConfiguration;
import io.github.hectorvent.floci.services.ecs.model.ContainerDefinition;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.github.hectorvent.floci.services.ecs.model.NetworkConfiguration;
import io.github.hectorvent.floci.services.ecs.model.NetworkMode;
import io.github.hectorvent.floci.services.ecs.model.RunTaskRequest;
import io.github.hectorvent.floci.services.ecs.model.TaskDefinition;
import io.github.hectorvent.floci.services.route53.Route53Service;
import io.github.hectorvent.floci.services.route53.model.ResourceRecord;
import io.github.hectorvent.floci.services.route53.model.ResourceRecordSet;
import io.github.hectorvent.floci.services.route53.model.VpcAssociation;
import io.github.hectorvent.floci.services.route53resolver.QueryLogWriter;
import io.github.hectorvent.floci.services.route53resolver.Route53ResolverService;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.github.hectorvent.floci.testing.TestImages;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.Vertx;
import io.vertx.core.datagram.DatagramSocket;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Query logging end to end inside one Floci: a real awsvpc ECS task behind its security-group
 * namespace, queries arriving at the embedded DNS server from that namespace's address, and the
 * records landing in S3 under the task VPC's path. The DNS server only listens when Floci runs in a
 * container, so the queries are handed to its packet handler with the task's source address.
 */
@QuarkusTest
@TestProfile(QueryLogDnsDockerIntegrationTest.DockerEcsProfile.class)
class QueryLogDnsDockerIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";
    private static final String SUBNET = "subnet-default-us-east-1-a";
    private static final List<String> R53_EX_KEYS = List.of("version", "account_id", "region", "vpc_id",
            "query_timestamp", "query_name", "query_type", "query_class", "rcode", "answers", "srcaddr",
            "srcport", "transport", "srcids");

    public static final class DockerEcsProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.services.ecs.mock", "false");
        }
    }

    @Inject EcsService ecsService;
    @Inject EcsContainerManager containerManager;
    @Inject Ec2Service ec2Service;
    @Inject SecurityGroupFirewallManager firewall;
    @Inject DockerClient docker;
    @Inject EmbeddedDnsServer dns;
    @Inject Route53Service route53;
    @Inject Route53ResolverService resolver;
    @Inject QueryLogWriter writer;
    @Inject S3Service s3;
    @Inject ObjectMapper mapper;
    @Inject Vertx vertx;

    @Test
    void taskQueriesLandInS3UnderTheVpcOnlyWhileAssociated() throws Exception {
        Assumptions.assumeTrue(firewall.enabled());
        try {
            Assumptions.assumeTrue("linux".equalsIgnoreCase(docker.infoCmd().exec().getOsType()));
        } catch (Exception e) {
            Assumptions.abort("Docker daemon is unavailable");
        }
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String vpcId = ec2Service.describeSubnets(REGION, List.of(SUBNET), Map.of()).getFirst().getVpcId();
        String zone = "p7-" + suffix + ".internal";
        String zoneId = route53.createHostedZone(zone, suffix, null, new VpcAssociation(vpcId, REGION)).zone().getId();
        ResourceRecordSet api = new ResourceRecordSet();
        api.setName("api." + zone);
        api.setType("A");
        api.setTtl(60L);
        api.setRecords(List.of(new ResourceRecord("10.9.0.10")));
        route53.changeResourceRecordSets(zoneId, List.of(Map.of("action", "CREATE", "rrs", api)), null);

        String bucket = "query-logs-" + suffix;
        s3.createBucket(bucket, REGION);
        ObjectNode create = mapper.createObjectNode().put("Name", "p7").put("CreatorRequestId", suffix)
                .put("DestinationArn", "arn:aws:s3:::" + bucket + "/dns");
        String configId = resolver.createResolverQueryLogConfig(create, REGION, ACCOUNT).get("Id").asText();
        ObjectNode association = mapper.createObjectNode().put("ResolverQueryLogConfigId", configId)
                .put("ResourceId", vpcId);
        resolver.associateResolverQueryLogConfig(association);

        String cluster = "ql-" + suffix;
        ecsService.createCluster(cluster, REGION);
        EcsTask task = runTask(cluster, suffix);
        try {
            assertEquals("RUNNING", task.getLastStatus(), "the task must start: " + task.getStoppedReason());
            String source = containerManager.resolvePeerAddress(task.getContainers().getFirst()).orElseThrow();
            String prefix = "dns/AWSLogs/" + ACCOUNT + "/vpcdnsquerylogs/" + vpcId + "/";

            ask(source, "api." + zone);
            ask(source, "missing." + zone);
            List<JsonNode> records = awaitRecords(bucket, prefix, 2);

            JsonNode found = records.stream().filter(r -> r.get("query_name").asText().startsWith("api."))
                    .findFirst().orElseThrow();
            JsonNode missing = records.stream().filter(r -> r.get("query_name").asText().startsWith("missing."))
                    .findFirst().orElseThrow();
            List<String> keys = new ArrayList<>();
            found.fieldNames().forEachRemaining(keys::add);
            assertEquals(R53_EX_KEYS, keys);
            assertEquals("1.100000", found.get("version").asText());
            assertEquals("api." + zone + ".", found.get("query_name").asText());
            assertEquals("NOERROR", found.get("rcode").asText());
            assertEquals(mapper.readTree("[{\"Rdata\":\"10.9.0.10\",\"Type\":\"A\",\"Class\":\"IN\"}]"),
                    found.get("answers"));
            assertEquals(vpcId, found.get("vpc_id").asText());
            assertEquals(task.getPrivateIpAddress(), found.get("srcaddr").asText());
            assertEquals("53000", found.get("srcport").asText());
            assertEquals("NXDOMAIN", missing.get("rcode").asText());
            assertEquals(0, missing.get("answers").size());

            resolver.disassociateResolverQueryLogConfig(association);
            ask(source, "api." + zone);
            Thread.sleep(500);
            writer.flushNow();
            assertEquals(2, readRecords(bucket, prefix).size(), "an unassociated VPC must log nothing");
        } finally {
            ecsService.stopTask(cluster, task.getTaskArn(), "test teardown", REGION);
        }
    }

    private EcsTask runTask(String cluster, String suffix) {
        ContainerDefinition app = new ContainerDefinition();
        app.setName("app");
        app.setImage(TestImages.BUSYBOX);
        app.setCommand(List.of("sleep", "120"));
        TaskDefinition definition = ecsService.registerTaskDefinition("ql-" + suffix, List.of(app),
                NetworkMode.awsvpc, null, null, null, null, null, REGION);
        AwsVpcConfiguration awsvpc = new AwsVpcConfiguration();
        awsvpc.setSubnets(List.of(SUBNET));
        NetworkConfiguration network = new NetworkConfiguration();
        network.setAwsvpcConfiguration(awsvpc);
        RunTaskRequest request = new RunTaskRequest();
        request.setCluster(cluster);
        request.setTaskDefinition(definition.getTaskDefinitionArn());
        request.setCount(1);
        request.setNetworkConfiguration(network);
        return ecsService.runTask(request, REGION).getFirst();
    }

    private void ask(String source, String name) throws Exception {
        DatagramSocket socket = vertx.createDatagramSocket();
        try {
            socket.listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
            byte[] encoded = DnsRecord.encodeName(name);
            byte[] query = ByteBuffer.allocate(16 + encoded.length).putShort((short) 0x5151).putShort((short) 0x0100)
                    .putShort((short) 1).putShort((short) 0).putShort((short) 0).putShort((short) 0)
                    .put(encoded).putShort((short) 1).putShort((short) 1).array();
            dns.handleQuery(vertx, socket, query, source, 53000, "127.0.0.1");
            Thread.sleep(200);
        } finally {
            socket.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        }
    }

    private List<JsonNode> awaitRecords(String bucket, String prefix, int count) throws Exception {
        List<JsonNode> records = List.of();
        for (int attempt = 0; attempt < 50 && records.size() < count; attempt++) {
            writer.flushNow();
            records = readRecords(bucket, prefix);
            Thread.sleep(100);
        }
        assertTrue(records.size() >= count, "expected " + count + " records under " + prefix + ", got " + records);
        return records;
    }

    private List<JsonNode> readRecords(String bucket, String prefix) throws IOException {
        List<JsonNode> records = new ArrayList<>();
        for (S3Object listed : s3.listObjects(bucket, prefix, null, 1000)) {
            assertTrue(listed.getKey().matches(Pattern.quote(prefix)
                    + "\\d{4}/\\d{2}/\\d{2}/vpc-[0-9a-z-]+_vpcdnsquerylogs_" + ACCOUNT
                    + "_\\d{8}T\\d{4}Z_[0-9a-f]{8}\\.log\\.gz"), listed.getKey());
            byte[] data = s3.getObject(bucket, listed.getKey()).getData();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data))) {
                for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
                    if (!line.isBlank()) {
                        records.add(mapper.readTree(line));
                    }
                }
            }
        }
        return records;
    }
}
