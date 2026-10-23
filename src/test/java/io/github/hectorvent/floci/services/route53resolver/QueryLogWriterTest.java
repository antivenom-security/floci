package io.github.hectorvent.floci.services.route53resolver;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.dns.DnsQueryObserver;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsService;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ec2.SecurityGroupFirewallManager;
import io.github.hectorvent.floci.services.ec2.SecurityGroupNftCompiler;
import io.github.hectorvent.floci.services.ec2.model.NetworkInterfaceListResult;
import io.github.hectorvent.floci.services.s3.S3Service;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class QueryLogWriterTest {

    private static final String SOURCE = "172.18.0.9";
    private static final String S3_DESTINATION = "arn:aws:s3:::logs";
    private static final String LOGS_DESTINATION = "arn:aws:logs:us-east-1:000000000000:log-group:dns";

    private final Route53ResolverService resolver = mock(Route53ResolverService.class);
    private final S3Service s3 = mock(S3Service.class);
    private final CloudWatchLogsService logs = mock(CloudWatchLogsService.class);
    private QueryLogWriter writer;

    @BeforeEach
    void setUp() {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().route53resolver().enabled()).thenReturn(true);
        SecurityGroupFirewallManager firewall = mock(SecurityGroupFirewallManager.class);
        when(firewall.enabled()).thenReturn(true);
        when(firewall.endpointAt(SOURCE)).thenReturn(Optional.of(new SecurityGroupNftCompiler.Endpoint(
                "000000000000", "us-east-1", "vpc-1", "eni-1", "10.0.0.5", SOURCE, Set.of(), List.of())));
        Ec2Service ec2 = mock(Ec2Service.class);
        when(ec2.describeNetworkInterfaces(anyString(), anyString(), anyList(), anyMap()))
                .thenReturn(new NetworkInterfaceListResult(List.of(), null));
        writer = new QueryLogWriter(config, resolver, firewall, ec2, s3, logs, new ObjectMapper());
    }

    @Test
    void eachRecordIsFiledUnderItsOwnSlotNotTheFlushTime() {
        when(resolver.queryLogDestinationsFor("000000000000", "us-east-1", "vpc-1"))
                .thenReturn(List.of(S3_DESTINATION, LOGS_DESTINATION));
        writer.observe(query("2026-10-22T23:58:10Z"));
        writer.observe(query("2026-10-23T00:01:30Z"));

        writer.flushNow();

        ArgumentCaptor<String> keys = ArgumentCaptor.forClass(String.class);
        verify(s3, times(2)).putObject(eq("logs"), keys.capture(), any(), anyString(), anyMap());
        assertTrue(keys.getAllValues().stream().anyMatch(key ->
                key.contains("/2026/10/22/vpc-1_vpcdnsquerylogs_000000000000_20261022T2355Z_")), keys.getAllValues().toString());
        assertTrue(keys.getAllValues().stream().anyMatch(key ->
                key.contains("/2026/10/23/vpc-1_vpcdnsquerylogs_000000000000_20261023T0000Z_")), keys.getAllValues().toString());
        verify(logs).putLogEventsForAccount(eq("000000000000"), eq("dns"), eq("vpc-1_20261022T2358Z_eni-1"),
                anyList(), eq("us-east-1"));
        verify(logs).putLogEventsForAccount(eq("000000000000"), eq("dns"), eq("vpc-1_20261023T0001Z_eni-1"),
                anyList(), eq("us-east-1"));
    }

    @Test
    void aTargetHoldsAtMostTheCapAndCountsTheRest() throws IOException {
        when(resolver.queryLogDestinationsFor("000000000000", "us-east-1", "vpc-1"))
                .thenReturn(List.of(S3_DESTINATION));
        for (int i = 0; i < QueryLogWriter.MAX_PENDING_PER_TARGET + 5; i++) {
            writer.observe(query("2026-10-22T23:58:10Z"));
        }

        writer.flushNow();

        assertEquals(5, writer.droppedRecords());
        assertEquals(QueryLogWriter.MAX_PENDING_PER_TARGET, deliveredLines(1).length);
    }

    @Test
    void aFailedDeliveryIsRetriedOnTheNextFlush() throws IOException {
        when(resolver.queryLogDestinationsFor("000000000000", "us-east-1", "vpc-1"))
                .thenReturn(List.of(S3_DESTINATION));
        when(s3.putObject(anyString(), anyString(), any(), anyString(), anyMap()))
                .thenThrow(new IllegalStateException("NoSuchBucket")).thenReturn(null);
        writer.observe(query("2026-10-22T23:58:10Z"));

        writer.flushNow();
        writer.flushNow();

        String[] lines = deliveredLines(2);
        assertEquals(1, lines.length);
        assertTrue(lines[0].contains("\"query_name\":\"api.example.\""));
    }

    private String[] deliveredLines(int calls) throws IOException {
        ArgumentCaptor<byte[]> bodies = ArgumentCaptor.forClass(byte[].class);
        verify(s3, times(calls)).putObject(anyString(), anyString(), bodies.capture(), anyString(), anyMap());
        try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(bodies.getValue()))) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n");
        }
    }

    private static DnsQueryObserver.Query query(String timestamp) {
        return new DnsQueryObserver.Query(Instant.parse(timestamp), SOURCE, 40000, "api.example", 1, 1, 0,
                List.of(new DnsQueryObserver.Answer("10.0.0.10", 1, 1)));
    }
}
