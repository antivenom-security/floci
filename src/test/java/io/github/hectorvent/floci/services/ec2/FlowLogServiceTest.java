package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.core.common.AvailabilityZoneIds;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.ec2.FlowLogService.FlowEni;
import io.github.hectorvent.floci.services.ec2.FlowLogService.FlowKey;
import io.github.hectorvent.floci.services.ec2.FlowLogService.FlowObservation;
import io.github.hectorvent.floci.services.ec2.model.FlowLog;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.Placement;
import io.github.hectorvent.floci.services.ec2.model.Reservation;
import io.github.hectorvent.floci.services.s3.S3Service;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class FlowLogServiceTest {

    private FlowLogService flowLogService;

    @BeforeEach
    void setUp() {
        flowLogService = serviceCallingAs("000000000000");
    }

    /** A service whose EC2 dependency resolves the caller to {@code accountId}. */
    private FlowLogService serviceCallingAs(String accountId) {
        Ec2Service ec2Service = mock(Ec2Service.class);
        when(ec2Service.callerAccountId()).thenReturn(accountId);
        when(ec2Service.describeInstances(any(), any(), anyMap())).thenReturn(List.of());
        when(ec2Service.endpointNetworkInterfaces(any())).thenReturn(List.of());
        return new FlowLogService(ec2Service, mock(S3Service.class), mock(CloudWatchLogsService.class),
                new InMemoryStorage<>(), "synthetic", 300);
    }

    @Test
    void createFlowLogRecordsTheCallingAccountNotTheDefault() {
        // The account lands in the delivered record's account-id field and in the S3 key prefix
        // (AWSLogs/{account}/vpcflowlogs/...), so a flow log created by a non-default caller must
        // carry that caller. Before issue #3775 this was pinned to the configured default account.
        FlowLog fl = serviceCallingAs("444444444444").createFlowLog("us-east-1", "vpc-123", "VPC",
                "ALL", "s3", "arn:aws:s3:::flow-bucket", null, null, 600);

        assertEquals("444444444444", fl.getAccountId());
    }

    @Test
    void deleteFlowLogsIsScopedToTheRequestRegion() {
        FlowLog fl = flowLogService.createFlowLog("us-east-1", "vpc-123", "VPC", "ALL",
                "s3", "arn:aws:s3:::flow-bucket", null, null, 600);

        List<String> otherRegion = flowLogService.deleteFlowLogs("eu-west-1", List.of(fl.getFlowLogId()));

        assertTrue(otherRegion.isEmpty(), "delete must not cross regions");
        assertEquals(1, flowLogService.describeFlowLogs("us-east-1", List.of()).size());

        List<String> sameRegion = flowLogService.deleteFlowLogs("us-east-1", List.of(fl.getFlowLogId()));

        assertEquals(List.of(fl.getFlowLogId()), sameRegion);
        assertTrue(flowLogService.describeFlowLogs("us-east-1", List.of()).isEmpty());
    }

    @Test
    void createFlowLogKeepsTheDeliverLogsPermissionArn() {
        FlowLog fl = flowLogService.createFlowLog("us-east-1", "vpc-123", "VPC", "ALL",
                "cloud-watch-logs", "arn:aws:logs:us-east-1:000000000000:log-group:flows",
                "arn:aws:iam::000000000000:role/flow-logs-role", null, 600);

        FlowLog described = flowLogService.describeFlowLogs("us-east-1", List.of(fl.getFlowLogId())).get(0);

        assertEquals("arn:aws:iam::000000000000:role/flow-logs-role", described.getDeliverLogsPermissionArn());
    }

    @Test
    void deleteFlowLogsIgnoresUnknownIds() {
        assertTrue(flowLogService.deleteFlowLogs("us-east-1", List.of("fl-doesnotexist")).isEmpty());
    }

    /**
     * The delivered records follow the flow log's LogFormat.
     *
     * <p>record used to emit all 29 available fields in alphabetical order whatever the format
     * said, so a custom format produced a short header line above long rows and a reader following
     * the header took the wrong value for every column.
     */
    @Test
    void aCustomFormatDeliversThoseFieldsInThatOrder() throws Exception {
        List<String> lines = deliver("${srcaddr} ${dstaddr} ${action}");

        assertEquals("srcaddr dstaddr action", lines.get(0));
        for (String row : records(lines)) {
            assertEquals(3, row.split(" ").length, "row does not match the header: " + row);
            assertTrue(row.endsWith(" ACCEPT"), "action is not the last field: " + row);
        }
    }

    /** A flow log with no LogFormat delivers the version 2 fields, and reports version 2. */
    @Test
    void noCustomFormatDeliversTheVersion2Default() throws Exception {
        List<String> lines = deliver(null);

        assertEquals(String.join(" ", FlowLogService.DEFAULT_FIELDS), lines.get(0));
        for (String row : records(lines)) {
            String[] columns = row.split(" ");
            assertEquals(FlowLogService.DEFAULT_FIELDS.size(), columns.length,
                    "row does not match the header: " + row);
            assertEquals("2", columns[0], "version is not the version 2 default: " + row);
        }
    }

    /** The version a record reports is the highest its fields belong to, not a fixed 5. */
    @Test
    void aVersion5FieldRaisesTheReportedVersion() throws Exception {
        List<String> lines = deliver("${version} ${flow-direction}");

        assertEquals("version flow-direction", lines.get(0));
        for (String row : records(lines)) {
            assertEquals("5", row.split(" ")[0], "version did not follow the fields: " + row);
        }
    }

    /** A version 7 field the synthetic generator has no value for keeps its column as a dash. */
    @Test
    void aVersion7FieldKeepsItsColumnAsADashAndReportsVersion7() throws Exception {
        List<String> lines = deliver("${version} ${ecs-cluster-arn} ${action}");

        assertEquals("version ecs-cluster-arn action", lines.get(0));
        for (String row : records(lines)) {
            assertEquals("7 - ACCEPT", row);
        }
    }

    /** EC2-CFL: a LogFormat naming a field AWS does not define, or a later version's, is refused. */
    @Test
    void anUnknownFieldIsRejected() {
        AwsException e = assertThrows(AwsException.class, () -> flowLogService.createFlowLog("us-east-1",
                "vpc-123", "VPC", "ALL", "s3", "arn:aws:s3:::flow-bucket", null, "${srcaddr} ${DSTADDR}", 600));

        assertEquals("InvalidParameter", e.getErrorCode());
        assertTrue(e.getMessage().contains("${DSTADDR}"), e.getMessage());
    }

    @Test
    void firehoseAnOddIntervalAndParquetAreRefused() {
        assertEquals("UnsupportedOperation", assertThrows(AwsException.class, () -> flowLogService.createFlowLog(
                "us-east-1", "vpc-123", "VPC", "ALL", "kinesis-data-firehose", "arn:aws:firehose:us-east-1:000000000000:deliverystream/x",
                null, null, 600)).getErrorCode());
        assertEquals("InvalidParameterValue", assertThrows(AwsException.class, () -> flowLogService.createFlowLog(
                "us-east-1", "vpc-123", "VPC", "ALL", "s3", "arn:aws:s3:::b", null, null, 120)).getErrorCode());
        assertEquals("UnsupportedOperation", assertThrows(AwsException.class, () -> flowLogService.createFlowLog(
                "us-east-1", "vpc-123", "VPC", "ALL", "s3", "arn:aws:s3:::b", null, null, null, 600,
                "parquet", false, false)).getErrorCode());
        assertEquals("InvalidParameter", assertThrows(AwsException.class, () -> flowLogService.createFlowLog(
                "us-east-1", "vpc-123", "VPC", "ALL", "cloud-watch-logs", null, "flows", null, null, 600,
                null, false, false)).getErrorCode());
    }

    /**
     * A record's az-id is the zone id subnets and DescribeAvailabilityZones publish for the same
     * zone. FlowLogService once derived its own, with a different rule ({@code cnnorth1-az1} for
     * China), so the two did not agree.
     */
    @Test
    void azIdMatchesTheZoneIdEc2PublishesForTheZone() throws Exception {
        for (String region : List.of("us-east-1", "cn-north-1", "us-gov-west-1")) {
            List<String> lines = deliver(region, "${az-id}");

            assertEquals("az-id", lines.get(0));
            for (String row : records(lines)) {
                assertEquals(AvailabilityZoneIds.forZoneName(region, region + "a"), row, "in " + region);
            }
        }
    }

    /** The record lines of a delivered file, which must not be empty. */
    private static List<String> records(List<String> lines) {
        assertFalse(lines.size() < 2, "delivery carried a header and no records");
        return lines.subList(1, lines.size());
    }

    /** Deliver one file for a flow log with this LogFormat and return its lines. */
    private List<String> deliver(String logFormat) throws Exception {
        return deliver("us-east-1", logFormat);
    }

    /** Deliver one file for a flow log in {@code region} with this LogFormat and return its lines. */
    private List<String> deliver(String region, String logFormat) throws Exception {
        Ec2Service ec2Service = mock(Ec2Service.class);
        when(ec2Service.callerAccountId()).thenReturn("000000000000");
        when(ec2Service.describeInstances(any(), any(), anyMap()))
                .thenReturn(List.of(reservation(region)));
        when(ec2Service.endpointNetworkInterfaces(any())).thenReturn(List.of());
        S3Service s3Service = mock(S3Service.class);
        FlowLogService service = new FlowLogService(ec2Service, s3Service, mock(CloudWatchLogsService.class),
                new InMemoryStorage<>(), "synthetic", 300);

        FlowLog fl = service.createFlowLog(region, "vpc-123", "VPC", "ALL", "s3",
                "arn:aws:s3:::flow-bucket", null, logFormat, 600);
        service.generateAndDeliver(fl);

        // createFlowLog delivers once on creation, so take the file from the explicit call.
        ArgumentCaptor<byte[]> body = ArgumentCaptor.forClass(byte[].class);
        verify(s3Service, atLeastOnce()).putObject(eq("flow-bucket"), anyString(), body.capture(),
                anyString(), any(Map.class));
        return List.of(gunzip(body.getValue()).split("\n"));
    }

    private static Reservation reservation(String region) {
        Reservation reservation = new Reservation();
        reservation.setInstances(List.of(instance("i-aaa", "10.0.0.4", region), instance("i-bbb", "10.0.0.5", region)));
        return reservation;
    }

    private static Instance instance(String instanceId, String privateIp, String region) {
        Instance instance = new Instance();
        instance.setInstanceId(instanceId);
        instance.setPrivateIpAddress(privateIp);
        instance.setVpcId("vpc-123");
        instance.setSubnetId("subnet-123");
        Placement placement = new Placement();
        placement.setAvailabilityZone(region + "a");
        instance.setPlacement(placement);
        return instance;
    }

    private static String gunzip(byte[] gz) throws Exception {
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
    }

    @Test
    void bucketComesFromTheS3ArnEvenWhenThePrefixHasAColon() {
        assertEquals("bkt", FlowLogService.bucketFromArn("arn:aws:s3:::bkt/logs:2024/"));
        assertEquals("bkt", FlowLogService.bucketFromArn("arn:aws-cn:s3:::bkt"));
        assertEquals("bkt", FlowLogService.bucketFromArn("bkt/prefix"));
    }

    private static final Instant T0 = Instant.ofEpochSecond(1_700_000_000);

    private static FlowLogService observed(Ec2Service ec2Service, S3Service s3Service, CloudWatchLogsService logs) {
        when(ec2Service.callerAccountId()).thenReturn("000000000000");
        return new FlowLogService(ec2Service, s3Service, logs, new InMemoryStorage<>(), "observed", 0);
    }

    private static FlowEni eni(String eniId, String vpcId, Map<String, String> ecs) {
        return new FlowEni(eniId, "000000000000", "us-east-1", vpcId, "subnet-1", null, "us-east-1a", ecs);
    }

    @Test
    void observedModeNeverRunsTheGenerator() {
        Ec2Service ec2Service = mock(Ec2Service.class);
        S3Service s3Service = mock(S3Service.class);
        FlowLogService service = observed(ec2Service, s3Service, mock(CloudWatchLogsService.class));

        service.createFlowLog("us-east-1", "vpc-1", "VPC", "ALL", "s3", "arn:aws:s3:::bkt", null, null, 60);

        verifyNoInteractions(s3Service);
        verify(ec2Service, never()).describeInstances(any(), any(), anyMap());
    }

    @Test
    void anObservedWindowDeliversAggregatedRecordsAndNodataForIdleEnis() throws Exception {
        S3Service s3Service = mock(S3Service.class);
        FlowLogService service = observed(mock(Ec2Service.class), s3Service, mock(CloudWatchLogsService.class));
        FlowLog fl = service.createFlowLog("us-east-1", "vpc-1", "VPC", "ALL", "s3", "arn:aws:s3:::bkt/pre", null,
                "${version} ${interface-id} ${srcaddr} ${dstaddr} ${packets} ${start} ${end} ${action} "
                        + "${log-status} ${ecs-task-id}", 60);
        List<FlowEni> enis = List.of(eni("eni-a", "vpc-1", Map.of("ecs-task-id", "t1")),
                eni("eni-b", "vpc-1", Map.of()), eni("eni-c", "vpc-2", Map.of()));
        FlowKey key = new FlowKey("eni-a", "10.0.0.5", "10.0.0.6", 40000, 8080, 6, "egress", "ACCEPT", null, "1");

        service.ingest(T0, enis, List.of());
        service.ingest(T0.plusSeconds(10), enis, List.of(new FlowObservation(key, 3, 180, 2)));
        service.ingest(T0.plusSeconds(20), enis, List.of(new FlowObservation(key, 2, 120, 1)));
        service.ingest(T0.plusSeconds(60), enis, List.of());

        ArgumentCaptor<String> s3Key = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<byte[]> body = ArgumentCaptor.forClass(byte[].class);
        verify(s3Service).putObject(eq("bkt"), s3Key.capture(), body.capture(), anyString(), any(Map.class));
        assertTrue(s3Key.getValue().matches("pre/AWSLogs/000000000000/vpcflowlogs/us-east-1/2023/11/14/"
                + "000000000000_vpcflowlogs_us-east-1_" + fl.getFlowLogId() + "_20231114T2214Z_[0-9a-f]{8}\\.log\\.gz"),
                s3Key.getValue());
        assertEquals(List.of(
                "version interface-id srcaddr dstaddr packets start end action log-status ecs-task-id",
                "7 eni-a 10.0.0.5 10.0.0.6 5 1700000010 1700000020 ACCEPT OK t1",
                "7 eni-b - - - 1700000000 1700000060 - NODATA -"), List.of(gunzip(body.getValue()).split("\n")));
    }

    @Test
    void cloudWatchGetsOneStreamPerEniStampedAtTheRecordStart() {
        CloudWatchLogsService logs = mock(CloudWatchLogsService.class);
        FlowLogService service = observed(mock(Ec2Service.class), mock(S3Service.class), logs);
        service.createFlowLog("us-east-1", "vpc-1", "VPC", "REJECT", "cloud-watch-logs",
                "arn:aws:logs:us-east-1:000000000000:log-group:flows:*", null, "arn:aws:iam::000000000000:role/r",
                null, 60, null, false, false);
        List<FlowEni> enis = List.of(eni("eni-a", "vpc-1", Map.of()));
        FlowKey rejected = new FlowKey("eni-a", "10.0.0.6", "10.0.0.5", 40001, 9090, 6, "ingress", "REJECT", null, null);
        FlowKey accepted = new FlowKey("eni-a", "10.0.0.6", "10.0.0.5", 40002, 8080, 6, "ingress", "ACCEPT", null, null);

        service.ingest(T0, enis, List.of());
        service.ingest(T0.plusSeconds(10), enis,
                List.of(new FlowObservation(rejected, 1, 60, 2), new FlowObservation(accepted, 4, 400, 2)));
        service.ingest(T0.plusSeconds(60), enis, List.of());

        verify(logs).createLogGroupForAccount("000000000000", "flows", null, Map.of(), "us-east-1");
        verify(logs).createLogStreamForAccount("000000000000", "flows", "eni-a-reject", "us-east-1");
        ArgumentCaptor<List<Map<String, Object>>> events = ArgumentCaptor.forClass(List.class);
        verify(logs).putLogEventsForAccount(eq("000000000000"), eq("flows"), eq("eni-a-reject"),
                events.capture(), eq("us-east-1"));
        assertEquals(List.of(Map.of("timestamp", 1_700_000_010_000L, "message",
                "2 000000000000 eni-a 10.0.0.6 10.0.0.5 40001 9090 6 1 60 1700000010 1700000010 REJECT OK")),
                events.getValue());
    }

    @Test
    void hiveAndHourPartitionsFollowTheS3Layout() {
        FlowLog fl = new FlowLog();
        fl.setFlowLogId("fl-1");
        fl.setAccountId("000000000000");
        fl.setRegion("us-east-1");
        fl.setLogDestination("arn:aws:s3:::bkt");
        fl.setHiveCompatiblePartitions(true);
        fl.setPerHourPartition(true);

        assertTrue(flowLogService.s3Key(fl, T0).startsWith("AWSLogs/aws-account-id=000000000000/aws-service=vpcflowlogs/"
                + "aws-region=us-east-1/year=2023/month=11/day=14/hour=22/000000000000_vpcflowlogs_us-east-1_fl-1_"
                + "20231114T2213Z_"));
    }
}
