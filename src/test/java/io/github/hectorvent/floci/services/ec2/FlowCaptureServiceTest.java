package io.github.hectorvent.floci.services.ec2;

import io.github.hectorvent.floci.services.ec2.FlowLogService.FlowKey;
import io.github.hectorvent.floci.services.ec2.FlowLogService.FlowObservation;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FlowCaptureServiceTest {

    private static final SecurityGroupNftCompiler.Endpoint A = new SecurityGroupNftCompiler.Endpoint(
            "000000000000", "us-east-1", "vpc-1", "eni-a", "10.0.0.5", "192.168.215.2", Set.of(), List.of());
    private static final SecurityGroupNftCompiler.Endpoint B = new SecurityGroupNftCompiler.Endpoint(
            "000000000000", "us-east-1", "vpc-1", "eni-b", "10.0.0.6", "192.168.215.3", Set.of(), List.of());
    private static final Map<String, SecurityGroupNftCompiler.Endpoint> PEERS =
            Map.of(A.transportAddress(), A, B.transportAddress(), B);

    /** Captured on OrbStack: B connected to A:8080 and was then dropped twice on 9090. */
    private static String poll(long origPackets, long rejectPackets) {
        return "tcp      6 117 TIME_WAIT src=192.168.215.3 dst=192.168.215.2 sport=44809 dport=8080 packets="
                + origPackets + " bytes=326 src=192.168.215.2 dst=192.168.215.3 sport=8080 dport=44809 packets=4 "
                + "bytes=222 [ASSURED] mark=0 use=1\n"
                + "udp      17 20 src=192.168.215.2 dst=192.168.215.9 sport=33000 dport=53 packets=1 bytes=60 "
                + "src=192.168.215.9 dst=192.168.215.2 sport=53 dport=33000 packets=1 bytes=90 mark=0 use=1\n"
                + "tcp      6 50 ESTABLISHED src=192.168.215.2 dst=192.168.215.1 sport=40000 dport=4566 packets=9 "
                + "bytes=900 src=192.168.215.1 dst=192.168.215.2 sport=4566 dport=40000 packets=9 bytes=900 mark=0 use=1\n"
                + "@@flow@@\n"
                + "{\"nftables\": [{\"metainfo\": {\"version\": \"1.1.1\"}}, {\"set\": {\"family\": \"inet\", \"name\": "
                + "\"fl_rej4\", \"elem\": [{\"elem\": {\"val\": {\"concat\": [\"192.168.215.3\", 44249, "
                + "\"192.168.215.2\", 9090, \"tcp\"]}, \"expires\": 299, \"counter\": {\"packets\": " + rejectPackets
                + ", \"bytes\": 120}}}]}}]}\n"
                + "{\"nftables\": [{\"metainfo\": {\"version\": \"1.1.1\"}}, {\"set\": {\"family\": \"inet\", \"name\": "
                + "\"fl_rej6\"}}]}\n"
                + "@@flow@@\n"
                + "default via 192.168.215.1 dev eth0\n";
    }

    @Test
    void acceptedFlowsYieldBothDirectionsAndRejectsTheirIngressAtLogicalAddresses() {
        Map<String, long[]> next = new HashMap<>();

        List<FlowObservation> observations = FlowCaptureService.observe(A, poll(6, 2), Map.of(), next, PEERS,
                "192.168.215.9");

        assertEquals(List.of(
                new FlowObservation(new FlowKey("eni-a", "10.0.0.6", "10.0.0.5", 44809, 8080, 6, "ingress", "ACCEPT",
                        null, null), 6, 326, 2 | 1),
                new FlowObservation(new FlowKey("eni-a", "10.0.0.5", "10.0.0.6", 8080, 44809, 6, "egress", "ACCEPT",
                        null, "1"), 4, 222, 18 | 1),
                new FlowObservation(new FlowKey("eni-a", "10.0.0.6", "10.0.0.5", 44249, 9090, 6, "ingress", "REJECT",
                        null, null), 2, 120, 2)), observations);
    }

    @Test
    void laterPollsReportOnlyTheGrowthSinceThePreviousOne() {
        Map<String, long[]> first = new HashMap<>();
        FlowCaptureService.observe(A, poll(6, 2), Map.of(), first, PEERS, "192.168.215.9");
        Map<String, long[]> second = new HashMap<>();

        List<FlowObservation> observations = FlowCaptureService.observe(A, poll(8, 3), first, second, PEERS,
                "192.168.215.9");

        assertEquals(List.of(
                new FlowObservation(new FlowKey("eni-a", "10.0.0.6", "10.0.0.5", 44809, 8080, 6, "ingress", "ACCEPT",
                        null, null), 2, 0, 1),
                new FlowObservation(new FlowKey("eni-a", "10.0.0.6", "10.0.0.5", 44249, 9090, 6, "ingress", "REJECT",
                        null, null), 1, 0, 2)), observations);
    }

    private static String rejectSet(String elements) {
        return "@@flow@@\n{\"nftables\": [{\"set\": {\"name\": \"fl_rej4\", \"elem\": [" + elements + "]}}]}\n@@flow@@\n";
    }

    private static String rejected(String sport, String dport, String protocol, long packets) {
        return "{\"elem\": {\"val\": {\"concat\": [\"192.168.215.3\", " + sport + ", \"192.168.215.2\", " + dport
                + ", \"" + protocol + "\"]}, \"counter\": {\"packets\": " + packets + ", \"bytes\": " + packets * 84 + "}}}";
    }

    /** Pings repeated across polls keep counting, whether the set holds one element or one per checksum. */
    @Test
    void repeatedRejectedPingsAreCountedOnEveryPoll() {
        Map<String, long[]> first = new HashMap<>();
        FlowCaptureService.observe(A, rejectSet(rejected("0", "0", "icmp", 3)), Map.of(), first, PEERS, null);
        Map<String, long[]> second = new HashMap<>();

        List<FlowObservation> later = FlowCaptureService.observe(A, rejectSet(rejected("0", "0", "icmp", 5) + ", "
                + rejected("2048", "41000", "icmp", 1) + ", " + rejected("2048", "42000", "icmp", 1)),
                first, second, PEERS, null);

        FlowKey ping = new FlowKey("eni-a", "10.0.0.6", "10.0.0.5", 0, 0, 1, "ingress", "REJECT", null, null);
        assertEquals(List.of(new FlowObservation(ping, 2, 168, 0), new FlowObservation(ping, 1, 84, 0),
                new FlowObservation(ping, 1, 84, 0)), later);
    }

    /** Two ping sessions differ only by their ICMP id, and each keeps its own counters. */
    @Test
    void acceptedPingSessionsAreCountedApart() {
        String sessions = "icmp     1 29 src=192.168.215.3 dst=192.168.215.2 type=8 code=0 id=7 packets=2 bytes=168 "
                + "src=192.168.215.2 dst=192.168.215.3 type=0 code=0 id=7 packets=2 bytes=168 mark=0 use=1\n"
                + "icmp     1 29 src=192.168.215.3 dst=192.168.215.2 type=8 code=0 id=9 packets=1 bytes=84 "
                + "src=192.168.215.2 dst=192.168.215.3 type=0 code=0 id=9 packets=1 bytes=84 mark=0 use=1\n";
        Map<String, long[]> first = new HashMap<>();

        FlowCaptureService.observe(A, sessions, Map.of(), first, PEERS, null);

        assertEquals(2, first.size());
    }

    /** Any smaller counter means a new entry with the same key, not negative traffic. */
    @Test
    void aShrinkingCounterIsAFreshEntry() {
        Map<String, long[]> first = new HashMap<>();
        FlowCaptureService.observe(A, rejectSet(rejected("44249", "9090", "tcp", 2)), Map.of(), first, PEERS, null);
        first.values().forEach(counts -> counts[1] = 10_000);
        Map<String, long[]> second = new HashMap<>();

        List<FlowObservation> later = FlowCaptureService.observe(A, rejectSet(rejected("44249", "9090", "tcp", 3)),
                first, second, PEERS, null);

        assertEquals(List.of(new FlowObservation(new FlowKey("eni-a", "10.0.0.6", "10.0.0.5", 44249, 9090, 6,
                "ingress", "REJECT", null, null), 3, 252, 2)), later);
    }
}
