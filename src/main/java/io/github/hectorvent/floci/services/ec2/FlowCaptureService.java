package io.github.hectorvent.floci.services.ec2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.DockerClient;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.dns.EmbeddedDnsServer;
import io.github.hectorvent.floci.core.common.docker.ContainerExec;
import io.github.hectorvent.floci.services.ec2.FlowLogService.FlowEni;
import io.github.hectorvent.floci.services.ec2.FlowLogService.FlowKey;
import io.github.hectorvent.floci.services.ec2.FlowLogService.FlowObservation;
import io.github.hectorvent.floci.services.ec2.model.NetworkInterface;
import io.github.hectorvent.floci.services.ecs.EcsService;
import io.github.hectorvent.floci.services.ecs.model.Container;
import io.github.hectorvent.floci.services.ecs.model.EcsTask;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.CRC32;

/**
 * Observes the traffic of every managed ENI inside the namespace its security-group helper owns:
 * accepted flows from conntrack accounting, rejected ones from the counter sets the policy drop
 * updates. Each tick hands the per-direction deltas to {@link FlowLogService#ingest}.
 */
@ApplicationScoped
public class FlowCaptureService {

    private static final Logger LOG = Logger.getLogger(FlowCaptureService.class);
    private static final String SECTION = "@@flow@@";
    private static final String POLL = "conntrack -L -f ipv4 2>/dev/null; conntrack -L -f ipv6 2>/dev/null; "
            + "echo " + SECTION + "; nft -j list set inet floci_sg fl_rej4; nft -j list set inet floci_sg fl_rej6; "
            + "echo " + SECTION + "; ip -4 route show default; ip -6 route show default";
    private static final Set<String> CLOSING = Set.of("FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE");
    private static final Set<String> LINK_LOCAL_SERVICES = Set.of("169.254.169.254", "169.254.169.123");
    private static final ObjectMapper JSON = new ObjectMapper();

    private final FlowLogService flowLogService;
    private final SecurityGroupFirewallManager firewallManager;
    private final Ec2Service ec2Service;
    private final EcsService ecsService;
    private final DockerClient dockerClient;
    private final EmbeddedDnsServer dnsServer;
    private final int tickSeconds;
    private final Map<String, Map<String, long[]>> counters = new HashMap<>();
    private final Set<String> needsBaseline = new HashSet<>();
    private ScheduledExecutorService scheduler;

    @Inject
    public FlowCaptureService(FlowLogService flowLogService, SecurityGroupFirewallManager firewallManager,
                              Ec2Service ec2Service, EcsService ecsService, DockerClient dockerClient,
                              EmbeddedDnsServer dnsServer, EmulatorConfig config) {
        this.flowLogService = flowLogService;
        this.firewallManager = firewallManager;
        this.ec2Service = ec2Service;
        this.ecsService = ecsService;
        this.dockerClient = dockerClient;
        this.dnsServer = dnsServer;
        this.tickSeconds = config.services().ec2().flowLogs().captureTickSeconds();
    }

    void onStart(@Observes StartupEvent ev) {
        if (!"observed".equals(flowLogService.mode())) {
            return;
        }
        if (!firewallManager.enabled()) {
            LOG.warn("Flow logs are observed but security-group enforcement is off, so no records are delivered");
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "floci-flowlog-capture");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::tick, tickSeconds, tickSeconds, TimeUnit.SECONDS);
    }

    void onStop(@Observes ShutdownEvent ev) {
        if (scheduler != null) {
            scheduler.shutdownNow();
        }
    }

    synchronized void tick() {
        try {
            Instant now = Instant.now();
            List<SecurityGroupFirewallManager.ProtectedEndpoint> managed = firewallManager.protectedEndpoints();
            Map<String, SecurityGroupNftCompiler.Endpoint> peers = new HashMap<>();
            managed.forEach(pe -> peers.put(pe.endpoint().transportAddress(), pe.endpoint()));
            String flociAddress = dnsServer.getServerIp().orElse(null);
            List<FlowEni> enis = new ArrayList<>();
            List<FlowObservation> observations = new ArrayList<>();
            Set<String> live = new HashSet<>();
            for (SecurityGroupFirewallManager.ProtectedEndpoint pe : managed) {
                live.add(pe.helperId());
                FlowEni eni = describe(pe.endpoint());
                enis.add(eni);
                if (!flowLogService.observes(eni)) {
                    counters.remove(pe.helperId());
                    needsBaseline.add(pe.helperId());
                    continue;
                }
                ContainerExec.Result poll;
                try {
                    poll = ContainerExec.run(dockerClient, pe.helperId(), new String[]{"sh", "-c", POLL}, 10);
                } catch (RuntimeException e) {
                    LOG.debugv("Flow capture poll failed for {0}: {1}", pe.endpoint().eniId(), e.getMessage());
                    continue;
                }
                if (poll.timedOut() || poll.exitCode() != 0) {
                    LOG.debugv("Flow capture poll failed for {0}: {1}", pe.endpoint().eniId(), poll.summary());
                    continue;
                }
                Map<String, long[]> next = new HashMap<>();
                List<FlowObservation> seen = observe(pe.endpoint(), poll.stdout(),
                        counters.getOrDefault(pe.helperId(), Map.of()), next, peers, flociAddress);
                counters.put(pe.helperId(), next);
                // Counters accumulated while no flow log covered the ENI are history, not this tick.
                if (!needsBaseline.remove(pe.helperId())) {
                    observations.addAll(seen);
                }
            }
            counters.keySet().retainAll(live);
            needsBaseline.retainAll(live);
            flowLogService.ingest(now, enis, observations);
        } catch (RuntimeException e) {
            LOG.warnv(e, "Flow capture tick failed");
        }
    }

    private FlowEni describe(SecurityGroupNftCompiler.Endpoint endpoint) {
        NetworkInterface ni = null;
        try {
            ni = ec2Service.describeNetworkInterfaces(endpoint.accountId(), endpoint.region(),
                    List.of(endpoint.eniId()), Map.of()).networkInterfaces().stream().findFirst().orElse(null);
        } catch (AwsException e) {
            LOG.debugv("Flow capture could not describe {0}: {1}", endpoint.eniId(), e.getMessage());
        }
        Map<String, String> ecs = ecsService.findTaskByNetworkInterface(endpoint.eniId())
                .map(FlowCaptureService::ecsFields).orElse(Map.of());
        return new FlowEni(endpoint.eniId(), endpoint.accountId(), endpoint.region(), endpoint.vpcId(),
                ni == null ? null : ni.getSubnetId(),
                ni == null || ni.getAttachment() == null ? null : ni.getAttachment().getInstanceId(),
                ni == null ? null : ni.getAvailabilityZone(), ecs);
    }

    /**
     * Floci places awsvpc tasks Fargate-style: no container instance, and container ids in the
     * Fargate runtime form {@code <task-id>-<n>}.
     */
    static Map<String, String> ecsFields(EcsTask task) {
        String taskArn = task.getTaskArn();
        String taskId = taskArn.substring(taskArn.lastIndexOf('/') + 1);
        Map<String, String> fields = new HashMap<>();
        fields.put("ecs-cluster-arn", task.getClusterArn());
        fields.put("ecs-cluster-name", task.getClusterArn().substring(task.getClusterArn().lastIndexOf('/') + 1));
        fields.put("ecs-task-arn", taskArn);
        fields.put("ecs-task-id", taskId);
        fields.put("ecs-task-definition-arn", task.getTaskDefinitionArn());
        if (task.getGroup() != null && task.getGroup().startsWith("service:")) {
            fields.put("ecs-service-name", task.getGroup().substring("service:".length()));
        }
        List<Container> containers = task.getContainers() == null ? List.of() : task.getContainers();
        for (int i = 0; i < Math.min(2, containers.size()); i++) {
            CRC32 crc = new CRC32();
            crc.update(containers.get(i).getName().getBytes(StandardCharsets.UTF_8));
            fields.put(i == 0 ? "ecs-container-id" : "ecs-second-container-id", taskId + "-" + crc.getValue());
        }
        return fields;
    }

    /**
     * Turns one poll of a helper into observations: per conntrack entry, the originating
     * direction's and the reply direction's packets since the previous poll, and per reject-set
     * element the dropped packets since then. {@code next} receives the counters to diff against.
     */
    static List<FlowObservation> observe(SecurityGroupNftCompiler.Endpoint endpoint, String output,
                                         Map<String, long[]> previous, Map<String, long[]> next,
                                         Map<String, SecurityGroupNftCompiler.Endpoint> peers, String flociAddress) {
        String[] sections = output.split(SECTION + "\n?", -1);
        Set<String> gateways = new HashSet<>();
        if (sections.length > 2) {
            for (String line : sections[2].split("\n")) {
                String[] words = line.trim().split("\\s+");
                if (words.length >= 3 && "default".equals(words[0]) && "via".equals(words[1])) {
                    gateways.add(words[2]);
                }
            }
        }
        Capture capture = new Capture(endpoint, previous, next, peers, flociAddress, gateways);
        for (String line : sections[0].split("\n")) {
            capture.conntrack(line.trim());
        }
        if (sections.length > 1) {
            for (String document : sections[1].split("\n")) {
                capture.rejects(document.trim());
            }
        }
        return capture.observations;
    }

    private static final class Capture {
        final SecurityGroupNftCompiler.Endpoint endpoint;
        final Map<String, long[]> previous;
        final Map<String, long[]> next;
        final Map<String, SecurityGroupNftCompiler.Endpoint> peers;
        final String flociAddress;
        final Set<String> gateways;
        final List<FlowObservation> observations = new ArrayList<>();

        Capture(SecurityGroupNftCompiler.Endpoint endpoint, Map<String, long[]> previous, Map<String, long[]> next,
                Map<String, SecurityGroupNftCompiler.Endpoint> peers, String flociAddress, Set<String> gateways) {
            this.endpoint = endpoint;
            this.previous = previous;
            this.next = next;
            this.peers = peers;
            this.flociAddress = flociAddress;
            this.gateways = gateways;
        }

        void conntrack(String line) {
            String[] words = line.split("\\s+");
            if (words.length < 4 || !words[1].matches("\\d+")) {
                return;
            }
            int protocol = Integer.parseInt(words[1]);
            String state = words[3].contains("=") ? "" : words[3];
            List<Map<String, String>> tuples = new ArrayList<>();
            for (String word : words) {
                int eq = word.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String key = word.substring(0, eq);
                if ("src".equals(key)) {
                    tuples.add(new LinkedHashMap<>());
                }
                if (!tuples.isEmpty()) {
                    tuples.getLast().putIfAbsent(key, word.substring(eq + 1));
                }
            }
            if (tuples.size() < 2) {
                return;
            }
            Map<String, String> orig = tuples.get(0);
            Map<String, String> reply = tuples.get(1);
            String src = orig.get("src");
            String dst = orig.get("dst");
            int sport = port(orig.get("sport"));
            int dport = port(orig.get("dport"));
            String local = endpoint.transportAddress();
            boolean initiated = local.equals(src);
            if (!initiated && !local.equals(dst)) {
                return;
            }
            String peer = initiated ? dst : src;
            if (excluded(peer, protocol, sport, dport)) {
                return;
            }
            long[] counts = {number(orig.get("packets")), number(orig.get("bytes")),
                    number(reply.get("packets")), number(reply.get("bytes"))};
            StringBuilder key = new StringBuilder("ct ").append(protocol);
            orig.forEach((name, value) -> {
                if (!"packets".equals(name) && !"bytes".equals(name)) {
                    key.append(' ').append(name).append('=').append(value);
                }
            });
            long[] delta = delta(key.toString(), counts);
            boolean fresh = !previous.containsKey(key.toString());
            int closing = protocol == 6 && CLOSING.contains(state) ? 1 : 0;
            int originFlags = protocol == 6 ? (fresh ? 2 : 0) | closing : 0;
            int replyFlags = protocol == 6 ? (fresh ? 18 : 0) | closing : 0;
            emit(initiated ? "egress" : "ingress", src, dst, sport, dport, protocol,
                    delta[0], delta[1], originFlags, "ACCEPT", peer);
            emit(initiated ? "ingress" : "egress", dst, src, dport, sport, protocol,
                    delta[2], delta[3], replyFlags, "ACCEPT", peer);
        }

        void rejects(String document) {
            if (document.isEmpty() || document.charAt(0) != '{') {
                return;
            }
            JsonNode root;
            try {
                root = JSON.readTree(document);
            } catch (IOException e) {
                LOG.debugv("Unreadable reject counters for {0}: {1}", endpoint.eniId(), e.getMessage());
                return;
            }
            for (JsonNode item : root.path("nftables")) {
                for (JsonNode element : item.path("set").path("elem")) {
                    JsonNode elem = element.has("elem") ? element.get("elem") : element;
                    JsonNode tuple = elem.path("val").path("concat");
                    if (tuple.size() != 5) {
                        continue;
                    }
                    String src = tuple.get(0).asText();
                    String dst = tuple.get(2).asText();
                    int protocol = protocolNumber(tuple.get(4));
                    boolean ported = protocol == 6 || protocol == 17;
                    int sport = ported ? tuple.get(1).asInt() : 0;
                    int dport = ported ? tuple.get(3).asInt() : 0;
                    String local = endpoint.transportAddress();
                    boolean egress = local.equals(src);
                    if (!egress && !local.equals(dst)) {
                        continue;
                    }
                    String peer = egress ? dst : src;
                    if (excluded(peer, protocol, sport, dport)) {
                        continue;
                    }
                    String key = "rj " + protocol + " " + src + " " + tuple.get(1).asText() + " " + dst + " "
                            + tuple.get(3).asText();
                    long[] delta = delta(key, new long[]{elem.path("counter").path("packets").asLong(),
                            elem.path("counter").path("bytes").asLong()});
                    emit(egress ? "egress" : "ingress", src, dst, sport, dport, protocol,
                            delta[0], delta[1], protocol == 6 ? 2 : 0, "REJECT", peer);
                }
            }
        }

        /** Counters only grow, so any smaller one means the entry expired and came back. */
        private long[] delta(String key, long[] counts) {
            next.put(key, counts);
            long[] before = previous.get(key);
            if (before == null) {
                return counts;
            }
            long[] delta = new long[counts.length];
            for (int i = 0; i < counts.length; i++) {
                if (counts[i] < before[i]) {
                    return counts;
                }
                delta[i] = counts[i] - before[i];
            }
            return delta;
        }

        /** VPC-LIM: the Amazon DNS server, DHCP, instance metadata, time sync and the VPC router. */
        private boolean excluded(String peer, int protocol, int sport, int dport) {
            return gateways.contains(peer) || LINK_LOCAL_SERVICES.contains(peer)
                    || (peer.equals(flociAddress) && (sport == 53 || dport == 53))
                    || (protocol == 17 && (sport == 67 || sport == 68 || dport == 67 || dport == 68));
        }

        private void emit(String direction, String src, String dst, int sport, int dport, int protocol,
                          long packets, long bytes, int flags, String action, String peer) {
            if (packets <= 0) {
                return;
            }
            SecurityGroupNftCompiler.Endpoint managedPeer = peers.get(peer);
            boolean peerIsFloci = peer.equals(flociAddress);
            String trafficPath = null;
            if ("egress".equals(direction)) {
                if (peerIsFloci) {
                    trafficPath = "2";
                } else if (managedPeer != null && endpoint.vpcId().equals(managedPeer.vpcId())) {
                    trafficPath = "1";
                }
            }
            observations.add(new FlowObservation(new FlowKey(endpoint.eniId(), logical(src), logical(dst),
                    sport, dport, protocol, direction, action, peerIsFloci ? "AMAZON" : null, trafficPath),
                    packets, bytes, flags));
        }

        /** A managed ENI is reported by its private address, not the Docker one it carries traffic on. */
        private String logical(String transport) {
            SecurityGroupNftCompiler.Endpoint managed = transport.equals(endpoint.transportAddress())
                    ? endpoint : peers.get(transport);
            return managed != null && managed.logicalAddress() != null ? managed.logicalAddress() : transport;
        }

        private static int port(String value) {
            return value == null ? 0 : Integer.parseInt(value);
        }

        private static long number(String value) {
            return value == null ? 0 : Long.parseLong(value);
        }

        private static int protocolNumber(JsonNode node) {
            if (node.isNumber()) {
                return node.asInt();
            }
            return switch (node.asText()) {
                case "tcp" -> 6;
                case "udp" -> 17;
                case "icmp" -> 1;
                case "ipv6-icmp", "icmpv6" -> 58;
                default -> node.asText().matches("\\d+") ? Integer.parseInt(node.asText()) : 0;
            };
        }
    }
}
