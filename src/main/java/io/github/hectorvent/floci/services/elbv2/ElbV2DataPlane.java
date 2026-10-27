package io.github.hectorvent.floci.services.elbv2;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.config.TlsProxyServer;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.CertificateReferenceResolver;
import io.github.hectorvent.floci.core.common.CertificateReferenceResolver.CertificateMaterial;
import io.github.hectorvent.floci.core.common.Pem;
import io.github.hectorvent.floci.services.cloudtrail.record.TlsDetails;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.elbv2.model.Action;
import io.github.hectorvent.floci.services.elbv2.model.Listener;
import io.github.hectorvent.floci.services.elbv2.model.LoadBalancer;
import io.github.hectorvent.floci.services.elbv2.model.Rule;
import io.github.hectorvent.floci.services.elbv2.model.RuleCondition;
import io.github.hectorvent.floci.services.elbv2.model.TargetDescription;
import io.github.hectorvent.floci.services.elbv2.model.TargetGroup;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.lambda.model.InvocationType;
import io.github.hectorvent.floci.services.lambda.model.InvokeResult;
import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpConnection;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.net.NetSocket;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.core.net.SSLOptions;
import io.vertx.core.net.SocketAddress;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLSession;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@ApplicationScoped
public class ElbV2DataPlane {

    private static final Logger LOG = Logger.getLogger(ElbV2DataPlane.class);

    private static final List<String> HOP_BY_HOP_HEADERS = List.of(
            "connection", "keep-alive", "transfer-encoding", "upgrade", "te", "trailers", "proxy-authorization", "proxy-authenticate"
    );
    private static final String PRESERVE_HOST_HEADER_ATTRIBUTE = "routing.http.preserve_host_header.enabled";
    private static final String IDLE_TIMEOUT_ATTRIBUTE = "idle_timeout.timeout_seconds";
    private static final long DEFAULT_IDLE_TIMEOUT_SECONDS = 60;
    private static final int MAX_LAMBDA_BODY_BYTES = 1024 * 1024;

    @Inject
    Vertx vertx;

    @Inject
    ElbV2Service elbV2Service;

    @Inject
    ElbV2HealthChecker healthChecker;

    @Inject
    EmulatorConfig config;

    @Inject
    TlsProxyServer tlsProxyServer;

    @Inject
    LambdaService lambdaService;

    @Inject
    Ec2Service ec2Service;

    @Inject
    CertificateReferenceResolver certificateResolver;

    @Inject
    ObjectMapper objectMapper;

    @Inject
    ElbV2AccessLogWriter accessLogs;

    /** Left null, like {@link #accessLogs}, by the unit tests that build the data plane by hand. */
    @Inject
    Instance<ElbV2RequestInspector> inspectors;

    private final Map<Integer, HttpServer> servers = new ConcurrentHashMap<>();
    private final Map<Integer, PortState> portStates = new ConcurrentHashMap<>();
    private volatile boolean stopping;

    private static final class PortState {
        private int depth;
        private int closing;
        private long generation;
        private volatile RoutingView routing = new RoutingView(Map.of(), Map.of());
    }

    private <T> T onPort(int port, Function<PortState, T> operation) {
        while (true) {
            PortState state = portStates.computeIfAbsent(port, ignored -> new PortState());
            synchronized (state) {
                if (portStates.get(port) != state) {
                    continue;
                }
                state.depth++;
                try {
                    return operation.apply(state);
                } finally {
                    if (state.depth == 1) {
                        refreshRouting(port, state);
                    }
                    state.depth--;
                    retirePortState(port, state);
                }
            }
        }
    }

    private <T> T onPorts(List<Integer> ports, int index, Supplier<T> operation) {
        if (index == ports.size()) {
            return operation.get();
        }
        return onPort(ports.get(index), state -> onPorts(ports, index + 1, operation));
    }

    private void onCurrentPort(int port, PortState state, Runnable operation) {
        synchronized (state) {
            if (stopping || portStates.get(port) != state) {
                return;
            }
            state.depth++;
            try {
                operation.run();
            } finally {
                if (state.depth == 1) {
                    refreshRouting(port, state);
                }
                state.depth--;
                retirePortState(port, state);
            }
        }
    }

    private void retirePortState(int port, PortState state) {
        if (state.depth == 0 && state.closing == 0 && !servers.containsKey(port)
                && !listenersByHostAndPort.containsKey(port)) {
            portStates.remove(port, state);
        }
    }

    private final java.util.concurrent.atomic.AtomicBoolean releaseHandlerRegistered =
            new java.util.concurrent.atomic.AtomicBoolean();
    private final Map<Integer, Map<String, String>> listenersByHostAndPort = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, ListenerBinding> listenerBindings;
    private final Map<String, AtomicReference<List<CompiledRule>>> ruleChains = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> rrCounters = new ConcurrentHashMap<>();
    private final Map<String, String> listenerRegions = new ConcurrentHashMap<>();
    private final ElbV2StickyCookie stickyCookie = new ElbV2StickyCookie();
    private final Map<HttpConnection, String> connectionTraceIds = new ConcurrentHashMap<>();

    private HttpClient proxyClient;

    public ElbV2DataPlane() {
        this(new ConcurrentHashMap<>());
    }

    ElbV2DataPlane(ConcurrentMap<String, ListenerBinding> listenerBindings) {
        this.listenerBindings = listenerBindings;
    }

    record ListenerBinding(int port, String host, String loadBalancerArn,
                                   boolean secure, Set<String> certificateHosts, List<CertificateMaterial> certificates) {}

    @PostConstruct
    void init() {
        proxyClient = vertx.createHttpClient(new HttpClientOptions()
                .setMaxPoolSize(100)
                .setConnectTimeout(5000)
                .setKeepAlive(true));
    }

    @PreDestroy
    void shutdown() {
        stopping = true;
        for (Map.Entry<Integer, PortState> entry : portStates.entrySet()) {
            synchronized (entry.getValue()) {
                HttpServer server = servers.remove(entry.getKey());
                if (server != null) {
                    server.close();
                }
            }
        }
        portStates.clear();
        servers.clear();
        listenersByHostAndPort.clear();
        listenerBindings.clear();
        ruleChains.clear();
        rrCounters.clear();
        listenerRegions.clear();
        connectionTraceIds.clear();
    }

    boolean publishListener(Listener listener, String region, Integer previousPort,
                            BooleanSupplier publication, Supplier<List<Rule>> rules,
                            Function<Supplier<Boolean>, Boolean> admission) {
        boolean live = !config.services().elbv2().mock() && !stopping && listener.getPort() != null;
        // Certificate ownership and material resolution must precede every port gate.
        ListenerBinding prepared = live ? binding(listener, region) : null;
        String arn = listener.getListenerArn();
        ListenerBinding expected = listenerBindings.get(arn);
        Integer runtimePort = expected == null ? previousPort : Integer.valueOf(expected.port());
        List<Integer> ports = Stream.of(previousPort, runtimePort, listener.getPort())
                .filter(Objects::nonNull).distinct().sorted().toList();
        boolean applied = admission.apply(() -> {
            // Recheck snapshots under the certificate guards, before taking any port gate.
            if (prepared != null) {
                for (CertificateMaterial material : prepared.certificates()) {
                    if (!material.equals(certificateResolver.publishedMaterial(arn, region, material.arn()))) {
                        return false;
                    }
                }
            }
            return onPorts(ports, 0, () -> {
                if (listenerBindings.get(arn) != expected) {
                    return false;
                }
                if (!live) {
                    return publication.getAsBoolean();
                }
                return installBinding(arn, expected, prepared, region,
                        () -> compileRules(rules.get()), publication, true);
            });
        });
        if (applied && live && !stopping) {
            ensureReleaseHandlerRegistered();
            onPort(prepared.port(), state -> {
                if (!stopping && listenerBindings.containsKey(arn)) {
                    ensurePortServer(prepared.port());
                }
                return null;
            });
        }
        return applied;
    }

    boolean updateListener(Integer storedPort, BooleanSupplier publication) {
        return storedPort == null ? publication.getAsBoolean()
                : onPort(storedPort, state -> publication.getAsBoolean());
    }

    boolean removeListener(String arn, Integer storedPort, BooleanSupplier publication) {
        ListenerBinding expected = listenerBindings.get(arn);
        Integer runtimePort = expected == null ? storedPort : Integer.valueOf(expected.port());
        List<Integer> ports = Stream.of(storedPort, runtimePort).filter(Objects::nonNull).distinct().sorted().toList();
        return onPorts(ports, 0, () -> {
            if (listenerBindings.get(arn) != expected || !publication.getAsBoolean()) {
                return false;
            }
            if (expected != null) {
                ruleChains.remove(arn);
                listenerRegions.remove(arn);
                listenerBindings.remove(arn, expected);
                removePortBinding(arn, expected);
            }
            return true;
        });
    }

    private boolean installBinding(String arn, ListenerBinding expected, ListenerBinding prepared,
                                   String region, Supplier<List<CompiledRule>> compiled,
                                   BooleanSupplier publication, boolean preserveRules) {
        if (stopping) {
            return publication.getAsBoolean();
        }
        if (listenerBindings.get(arn) != expected) {
            return false;
        }
        requireCompatiblePort(prepared, arn);
        boolean claimed = expected == null
                ? listenerBindings.putIfAbsent(arn, prepared) == null
                : listenerBindings.replace(arn, expected, prepared);
        if (!claimed) {
            return false;
        }
        try {
            if (!publication.getAsBoolean()) {
                restoreReservation(arn, expected, prepared);
                return false;
            }
        } catch (RuntimeException failure) {
            restoreReservation(arn, expected, prepared);
            throw failure;
        }
        if (expected != null) {
            removeHostBindings(arn, expected);
            if (expected.port() != prepared.port()) {
                removePortBinding(arn, expected);
            }
        }
        publishBinding(arn, prepared);
        if (preserveRules) {
            ruleChains.computeIfAbsent(arn, ignored -> new AtomicReference<>(compiled.get()));
        } else {
            ruleChains.put(arn, new AtomicReference<>(compiled.get()));
        }
        listenerRegions.put(arn, region);
        Map<String, String> peers = listenersByHostAndPort.computeIfAbsent(
                prepared.port(), ignored -> new ConcurrentHashMap<>());
        warnOnSharedPort(prepared, peers);
        addHostBindings(arn, prepared);
        if (expected != null && expected.port() == prepared.port() && expected.secure() != prepared.secure()) {
            restartPortServer(prepared.port());
        } else {
            HttpServer server = servers.get(prepared.port());
            if (server == null) {
                ensurePortServer(prepared.port());
            } else if (prepared.secure()) {
                refreshTlsOptions(prepared.port(), server);
            }
        }
        return true;
    }

    private void restoreReservation(String arn, ListenerBinding expected, ListenerBinding prepared) {
        if (expected == null) {
            listenerBindings.remove(arn, prepared);
        } else {
            listenerBindings.replace(arn, prepared, expected);
        }
    }

    private void removePortBinding(String listenerArn, ListenerBinding binding) {
        removeHostBindings(listenerArn, binding);
        Map<String, String> listenersByHost = listenersByHostAndPort.get(binding.port());
        if (listenersByHost == null || listenersByHost.isEmpty()) {
            closePortServerIfUnused(binding.port(), listenersByHost);
        } else if (binding.secure()) {
            HttpServer server = servers.get(binding.port());
            if (server != null) {
                refreshTlsOptions(binding.port(), server);
            }
        }
    }

    public void recompileRules(String listenerArn, Supplier<List<Rule>> rules) {
        while (!stopping) {
            ListenerBinding expected = listenerBindings.get(listenerArn);
            if (expected == null) {
                return;
            }
            boolean applied = onPort(expected.port(), state -> {
                if (listenerBindings.get(listenerArn) != expected) {
                    return false;
                }
                AtomicReference<List<CompiledRule>> ref = ruleChains.get(listenerArn);
                if (ref != null) {
                    ref.set(compileRules(rules.get()));
                }
                return true;
            });
            if (applied) {
                return;
            }
        }
    }

    /**
     * Ports Floci reserves for itself, which a load balancer listener must not take.
     *
     * <p>The emulator's own port is always reserved. With TLS enabled the TLS proxy also binds
     * {@code floci.tls.aws-https-port} (443 by default), because CDK's custom-resource
     * {@code cfn-response} callback hardcodes {@code https://} and ignores the port in the
     * ResponseURL, so it always lands on 443.
     *
     * <p>Without this the two raced: whichever started first won. A stack restored from
     * persistence could hand 443 to an ALB listener, which then answered CDK's callback in plain
     * HTTP and hung every {@code Custom::} resource - and the reverse on a fresh start. Yielding
     * here makes the outcome deterministic and keeps the emulator's own control path working. To
     * give 443 to load balancers instead, set {@code floci.tls.aws-https-port=0} or disable TLS.
     */
    // Package-private for ElbV2ReservedPortTest.
    boolean isReservedByFloci(int port) {
        if (port == config.port()) {
            return true;
        }
        // Ask the proxy whether it actually holds the port rather than inferring it from config.
        // Binding the AWS-HTTPS port is privileged and its failure is non-fatal, so a port the
        // proxy never acquired must stay available to listeners instead of going unserved.
        return tlsProxyServer.reservesPort(port);
    }

    /**
     * Binds any registered listener whose port the proxy has just released. Yielding a port whose
     * bind had not resolved yet is the safe default, but if that bind then fails nothing else
     * would ever retry the listener, leaving it registered with no data plane and the port free.
     */
    private void bindListenersWaitingOn(int port) {
        PortState state = portStates.get(port);
        if (state != null) {
            onCurrentPort(port, state, () -> {
                if (listenersByHostAndPort.containsKey(port)) {
                    ensurePortServer(port);
                }
            });
        }
    }

    /**
     * Subscribes to the proxy's released ports, once, on the first listener to need it: the data
     * plane is only live once a listener exists, and this keeps the proxy out of the mock-mode
     * path entirely.
     *
     * <p>Placement is load-bearing on both sides. It runs after the listener is in
     * {@code listenersByHostAndPort}, so the replay of ports already given up finds it, and before
     * {@code servers.computeIfAbsent}, because {@code onPortReleased} replays synchronously: doing
     * this from inside the mapping function re-entered {@code computeIfAbsent} for the very key it
     * was still computing, which a {@link ConcurrentHashMap} rejects outright.
     */
    private void ensureReleaseHandlerRegistered() {
        if (releaseHandlerRegistered.compareAndSet(false, true)) {
            tlsProxyServer.onPortReleased(this::bindListenersWaitingOn);
        }
    }

    private void ensurePortServer(int port) {
        PortState state = portStates.get(port);
        if (!stopping && state != null && state.closing == 0 && !servers.containsKey(port)
                && listenersByHostAndPort.containsKey(port)) {
            startPortServer(port, state);
        }
    }

    private void startPortServer(int port, PortState state) {
        if (isReservedByFloci(port)) {
            // Returning null leaves `servers` untouched: computeIfAbsent skips a null mapping.
            // The emulator's own port cannot be handed over, so the two cases need different
            // advice: freeing floci.tls.aws-https-port is only meaningful for the TLS proxy.
            String remedy = port == config.port()
                    ? "This is the emulator's own port, so it cannot be freed; give the listener a different port."
                    : "Set floci.tls.aws-https-port=0 (or disable TLS) to free it.";
            LOG.warnv("ELBv2 listener port {0} is reserved by Floci itself; the listener is "
                    + "registered but serves no traffic. {1}", String.valueOf(port), remedy);
            return;
        }
        boolean secure = portIsSecure(port);
        HttpServerOptions options = new HttpServerOptions()
                .setHost("0.0.0.0")
                .setPort(port);
        if (secure) {
            options.setSsl(true)
                    .setSni(true)
                    .setPemKeyCertOptions(tlsKeyCertOptions(port));
        }
        HttpServer server = vertx.createHttpServer(options);
        long generation = ++state.generation;
        servers.put(port, server);
        try {
            server.connectionHandler(connection -> {
                connectionTraceIds.put(connection, ElbV2AccessLogEntry.newConnTraceId());
                connection.closeHandler(ignored -> connectionTraceIds.remove(connection));
            });
            server.requestHandler(req -> handleRequest(req, port));
            server.listen()
                    .onSuccess(s -> LOG.infov("ELBv2 {0} listener port started on {1}",
                            secure ? "HTTPS" : "HTTP", String.valueOf(port)))
                    .onFailure(err -> onCurrentPort(port, state, () -> {
                        if (state.generation == generation && servers.remove(port, server)) {
                            clearPortBindings(port);
                            closeOwnedServer(port, state, server);
                        } else {
                            server.close();
                        }
                        LOG.warnv("ELBv2 listener port failed to start on {0}: {1}",
                                String.valueOf(port), err.getMessage());
                    }));
        } catch (RuntimeException failure) {
            if (state.generation == generation && servers.remove(port, server)) {
                clearPortBindings(port);
                try {
                    closeOwnedServer(port, state, server);
                } catch (RuntimeException cleanupFailure) {
                    failure.addSuppressed(cleanupFailure);
                }
            }
            throw failure;
        }
    }

    private void closePortServerIfUnused(int port, Map<String, String> listenersByHost) {
        if (listenersByHost != null && !listenersByHost.isEmpty()) {
            return;
        }
        if (listenersByHost != null) {
            listenersByHostAndPort.remove(port, listenersByHost);
        }
        restartPortServer(port);
    }

    private void clearPortBindings(int port) {
        listenersByHostAndPort.remove(port);
        for (Map.Entry<String, ListenerBinding> entry : listenerBindings.entrySet()) {
            if (entry.getValue().port() == port) {
                // Retain the old binding claim until its metadata is gone. A publisher on
                // another port cannot install the same listener's new metadata in between.
                ruleChains.remove(entry.getKey());
                listenerRegions.remove(entry.getKey());
                listenerBindings.remove(entry.getKey(), entry.getValue());
            }
        }
    }

    /**
     * Warns when a second load balancer takes a port another one already serves. Real AWS gives
     * every load balancer its own address, so two listeners on port 80 are correct there and a
     * template that works in AWS is not wrong. Floci serves them all from one socket per port,
     * which leaves the collision invisible: nothing fails, and every request whose Host header
     * names neither load balancer answers 502 with perfectly healthy targets behind it.
     */
    private void warnOnSharedPort(ListenerBinding binding, Map<String, String> listenersOnPort) {
        for (String otherArn : listenersOnPort.values()) {
            ListenerBinding other = listenerBindings.get(otherArn);
            if (other == null || other.loadBalancerArn().equals(binding.loadBalancerArn())) {
                continue;
            }
            LOG.warnv("ELBv2 port {0} now serves two load balancers, {1} and {2}. Floci runs them "
                            + "on one socket and dispatches by Host header, so a request must send {3} "
                            + "or {4}, or a hostname one of their rules declares in a host-header "
                            + "condition. Any other Host header answers 502.",
                    String.valueOf(binding.port()), other.loadBalancerArn(), binding.loadBalancerArn(),
                    other.host(), binding.host());
            return;
        }
    }

    private void publishBinding(String listenerArn, ListenerBinding binding) {
        listenerBindings.put(listenerArn, binding);
        if (!binding.secure()) {
            return;
        }
        Map<String, CertificateMaterial> current = new LinkedHashMap<>();
        for (CertificateMaterial certificate : binding.certificates()) {
            current.put(certificate.arn(), certificate);
        }
        listenerBindings.replaceAll((peerArn, peer) -> {
            if (peer.port() != binding.port() || !peer.secure()) {
                return peer;
            }
            List<CertificateMaterial> material = new ArrayList<>();
            Set<String> hosts = new LinkedHashSet<>();
            for (CertificateMaterial certificate : peer.certificates()) {
                CertificateMaterial replacement = current.getOrDefault(certificate.arn(), certificate);
                material.add(replacement);
                addCertificateHosts(hosts, replacement);
            }
            return new ListenerBinding(peer.port(), peer.host(), peer.loadBalancerArn(), true,
                    Set.copyOf(hosts), List.copyOf(material));
        });
    }

    private ListenerBinding binding(Listener listener, String region) {
        LoadBalancer loadBalancer = elbV2Service.getLoadBalancer(region, listener.getLoadBalancerArn());
        String host = loadBalancer != null ? normalizeHost(loadBalancer.getDnsName()) : listener.getLoadBalancerArn();
        boolean secure = "HTTPS".equalsIgnoreCase(listener.getProtocol());
        Set<String> hosts = new LinkedHashSet<>();
        List<CertificateMaterial> certificates = new ArrayList<>();
        if (secure) {
            if (listener.getCertificates() == null || listener.getCertificates().isEmpty()) {
                throw new IllegalStateException("HTTPS listener has no default certificate");
            }
            for (String certificateArn : listener.getCertificates()) {
                CertificateMaterial certificate = certificateResolver.publishedMaterial(
                        listener.getListenerArn(), region, certificateArn);
                try {
                    if (!Pem.isPair(Pem.parsePrivateKey(certificate.privateKey()),
                            Pem.parseCertificate(certificate.certificateBody()).getPublicKey())) {
                        throw new IllegalArgumentException("Certificate and private key do not match");
                    }
                } catch (Exception failure) {
                    throw new IllegalStateException("Certificate " + certificateArn + " has unusable TLS material", failure);
                }
                certificates.add(certificate);
                addCertificateHosts(hosts, certificate);
            }
        }
        return new ListenerBinding(listener.getPort(), host, listener.getLoadBalancerArn(),
                secure, Set.copyOf(hosts), List.copyOf(certificates));
    }

    public void requireCompatibleListenerProtocol(String listenerArn, int port, String protocol) {
        if (config.services().elbv2().mock()) {
            return;
        }
        onPort(port, state -> {
            requireCompatiblePort(port, "HTTPS".equalsIgnoreCase(protocol), listenerArn);
            return null;
        });
    }

    private void requireCompatiblePort(ListenerBinding binding, String listenerArn) {
        requireCompatiblePort(binding.port(), binding.secure(), listenerArn);
    }

    private void requireCompatiblePort(int port, boolean secure, String listenerArn) {
        for (Map.Entry<String, ListenerBinding> entry : listenerBindings.entrySet()) {
            ListenerBinding existing = entry.getValue();
            if (!entry.getKey().equals(listenerArn)
                    && existing.port() == port
                    && existing.secure() != secure) {
                throw new IncompatibleListenerProtocolException(port);
            }
        }
    }

    static final class IncompatibleListenerProtocolException extends IllegalStateException {
        IncompatibleListenerProtocolException(int port) {
            super("ELBv2 listeners sharing port " + port + " must use the same front-end protocol");
        }
    }

    private void addHostBindings(String listenerArn, ListenerBinding binding) {
        listenersByHostAndPort.computeIfAbsent(binding.port(), ignored -> new ConcurrentHashMap<>())
                .put(binding.host(), listenerArn);
    }

    private void removeHostBindings(String listenerArn, ListenerBinding binding) {
        Map<String, String> listenersByHost = listenersByHostAndPort.get(binding.port());
        if (listenersByHost != null) {
            listenersByHost.remove(binding.host(), listenerArn);
        }
    }

    private void refreshTlsOptions(int port, HttpServer server) {
        server.updateSSLOptions(new SSLOptions().setKeyCertOptions(tlsKeyCertOptions(port)), true)
                .onFailure(err -> LOG.warnv("ELBv2 listener TLS certificates failed to refresh on {0}: {1}",
                        String.valueOf(port), err.getMessage()));
    }

    private void restartPortServer(int port) {
        PortState state = portStates.get(port);
        HttpServer server = servers.remove(port);
        if (server == null) {
            ensurePortServer(port);
            return;
        }
        closeOwnedServer(port, state, server);
    }

    private void closeOwnedServer(int port, PortState state, HttpServer server) {
        long generation = ++state.generation;
        state.closing++;
        Future<Void> closed;
        try {
            closed = server.close();
        } catch (RuntimeException failure) {
            state.closing--;
            throw failure;
        }
        closed.onComplete(ignored -> onCurrentPort(port, state, () -> {
            state.closing--;
            if (state.generation == generation) {
                ensurePortServer(port);
            }
        }));
    }

    private PemKeyCertOptions tlsKeyCertOptions(int port) {
        Map<String, CertificateMaterial> certificates = new LinkedHashMap<>();
        for (Map.Entry<String, ListenerBinding> entry : listenerBindings.entrySet()) {
            ListenerBinding binding = entry.getValue();
            if (binding.port() != port || !binding.secure()) {
                continue;
            }
            for (CertificateMaterial certificate : binding.certificates()) {
                certificates.putIfAbsent(certificate.arn(), certificate);
            }
        }
        if (certificates.isEmpty()) {
            throw new IllegalStateException("HTTPS listener port " + port + " has no certificate");
        }
        PemKeyCertOptions options = new PemKeyCertOptions();
        for (CertificateMaterial certificate : certificates.values()) {
            if (certificate.privateKey() == null || certificate.privateKey().isBlank()
                    || certificate.certificateBody() == null || certificate.certificateBody().isBlank()) {
                throw new IllegalStateException("Certificate " + certificate.arn()
                        + " does not contain TLS key material");
            }
            options.addKeyValue(Buffer.buffer(certificate.privateKey()));
            options.addCertValue(Buffer.buffer(certificatePemChain(certificate)));
        }
        return options;
    }

    private boolean portIsSecure(int port) {
        return listenerBindings.values().stream()
                .filter(binding -> binding.port() == port)
                .findFirst()
                .map(ListenerBinding::secure)
                .orElse(false);
    }

    private static String certificatePemChain(CertificateMaterial certificate) {
        String body = certificate.certificateBody().stripTrailing();
        String chain = certificate.certificateChain();
        if (chain == null || chain.isBlank()) {
            return body + "\n";
        }
        try {
            CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream(chain.getBytes(StandardCharsets.US_ASCII)));
            return body + "\n" + chain.strip() + "\n";
        } catch (CertificateException e) {
            LOG.warnv("Certificate {0} has an invalid optional chain; serving its leaf certificate only",
                    certificate.arn());
            return body + "\n";
        }
    }

    private static void addCertificateHosts(Set<String> hosts, CertificateMaterial certificate) {
        X509Certificate leaf = Pem.parseCertificate(certificate.certificateBody());
        try {
            Set<String> leafHosts = new LinkedHashSet<>();
            Collection<List<?>> names = leaf.getSubjectAlternativeNames();
            if (names != null) {
                for (List<?> name : names) {
                    if (Integer.valueOf(2).equals(name.get(0)) && name.get(1) instanceof String hostname) {
                        leafHosts.add(normalizeHost(hostname));
                    }
                }
            }
            if (leafHosts.isEmpty()) {
                for (Rdn name : new LdapName(leaf.getSubjectX500Principal().getName()).getRdns()) {
                    if ("CN".equalsIgnoreCase(name.getType())) {
                        leafHosts.add(normalizeHost(name.getValue().toString()));
                    }
                }
            }
            hosts.addAll(leafHosts);
        } catch (CertificateException | InvalidNameException failure) {
            throw new IllegalStateException("Unable to read certificate hostnames", failure);
        }
    }

    private record RoutedListener(String arn, String region, List<CompiledRule> chain, Set<String> certificateHosts) {}

    private record RoutingView(Map<String, String> hosts, Map<String, RoutedListener> listeners) {}

    /** Publishes membership, region and compiled chain together after a coordinated write. */
    private void refreshRouting(int port, PortState state) {
        Map<String, String> hosts = listenersByHostAndPort.getOrDefault(port, Map.of());
        Map<String, RoutedListener> routes = new HashMap<>();
        for (String arn : hosts.values()) {
            ListenerBinding binding = listenerBindings.get(arn);
            AtomicReference<List<CompiledRule>> chain = ruleChains.get(arn);
            String region = listenerRegions.get(arn);
            if (binding != null && binding.port() == port && chain != null && region != null) {
                routes.put(arn, new RoutedListener(arn, region, chain.get(), binding.certificateHosts()));
            }
        }
        state.routing = new RoutingView(Map.copyOf(hosts), Map.copyOf(routes));
    }

    private void handleRequest(HttpServerRequest req, int port) {
        PortState state = portStates.get(port);
        RoutingView routing = state == null ? null : state.routing;
        RoutedListener listener = routing == null ? null : resolveListener(routing, req.host());
        ListenerBinding binding = listener == null ? null : listenerBindings.get(listener.arn());
        if (binding == null) {
            req.response().setStatusCode(502).end("No listener for host");
            return;
        }
        ElbV2AccessLogEntry log = startLog(req, listener, binding, port);
        for (ElbV2RequestInspector inspector : inspectors != null ? inspectors : List.<ElbV2RequestInspector>of()) {
            ElbV2RequestInspector.Response response =
                    inspector.inspect(req, listener.region(), binding.loadBalancerArn(), log.actions);
            if (response != null) {
                req.response().setStatusCode(response.statusCode());
                response.headers().forEach(req.response()::putHeader);
                req.response().end(response.body() != null ? response.body() : "");
                return;
            }
        }
        for (CompiledRule compiled : listener.chain()) {
            if (compiled.matches(req)) {
                log.matchedRulePriority = compiled.rule.isDefault() ? "0" : compiled.rule.getPriority();
                executeAction(req, compiled.action, listener.region(), listener.arn(), log);
                return;
            }
        }
        req.response().setStatusCode(502).end("No matching rule");
    }

    /**
     * Starts the request's access-log entry and completes it when the response ends. The load
     * balancer adds or updates the request's {@code X-Amzn-Trace-Id}, as AWS does, so the target and
     * the entry see the same trace.
     */
    private ElbV2AccessLogEntry startLog(HttpServerRequest req, RoutedListener listener, ListenerBinding binding,
                                         int port) {
        Instant now = Instant.now();
        ElbV2AccessLogEntry log = new ElbV2AccessLogEntry(binding.loadBalancerArn(), listener.region(), now,
                System.nanoTime());
        boolean secure = binding.secure();
        log.type = secure ? (req.version() == HttpVersion.HTTP_2 ? "h2" : "https") : "http";
        log.client = address(req.remoteAddress());
        log.nodeIp = req.localAddress() != null ? req.localAddress().hostAddress() : null;
        String host = req.host() != null ? req.host() : log.nodeIp;
        int colon = host.lastIndexOf(':');
        if (colon > host.lastIndexOf(']')) {
            host = host.substring(0, colon);
        }
        log.requestLine = ElbV2AccessLogEntry.requestLine(req.method(), secure, host, port, req.uri(), req.version());
        log.userAgent(req.getHeader("User-Agent"));
        log.requestHeadBytes = ElbV2AccessLogEntry.headBytes(
                req.method().name() + " " + req.uri() + " HTTP/1.1", req.headers());
        log.traceId = ElbV2AccessLogEntry.traceIdHeader(req.getHeader("X-Amzn-Trace-Id"), now);
        req.headers().set("X-Amzn-Trace-Id", log.traceId);
        log.connTraceId = connectionTraceIds.get(req.connection());
        String[] classification = ElbV2AccessLogEntry.classify(req.method(), req.headers());
        if (classification != null) {
            log.classification = classification[0];
            log.classificationReason = classification[1];
        }
        if (secure && req.sslSession() != null) {
            SSLSession session = req.sslSession();
            log.sslCipher = TlsDetails.openSslName(session.getCipherSuite());
            log.sslProtocol = session.getProtocol();
            String sni = normalizeHost(req.connection().indicatedServerName());
            if (binding.certificateHosts().stream().anyMatch(h -> h.equals(sni) || wildcardMatches(h, sni))) {
                log.domainName = sni;
            }
            log.chosenCertArn = presentedCertificate(session, binding);
        }
        req.response().bodyEndHandler(ignored -> {
            if (!log.tunneled) {
                finishLog(log, req.response().getStatusCode(), log.requestHeadBytes + req.bytesRead(),
                        ElbV2AccessLogEntry.headBytes("HTTP/1.1 " + req.response().getStatusCode() + " "
                                + req.response().getStatusMessage(), req.response().headers())
                                + req.response().bytesWritten());
            }
        });
        return log;
    }

    private void finishLog(ElbV2AccessLogEntry log, int status, long receivedBytes, long sentBytes) {
        if (!log.complete(Instant.now(), status, receivedBytes, sentBytes)) {
            return;
        }
        LoadBalancer loadBalancer = elbV2Service.getLoadBalancer(log.region, log.loadBalancerArn);
        if (loadBalancer != null && accessLogs != null) {
            accessLogs.record(loadBalancer, log);
        }
    }

    private static String presentedCertificate(SSLSession session, ListenerBinding binding) {
        Certificate[] presented = session.getLocalCertificates();
        if (presented == null || presented.length == 0) {
            return null;
        }
        for (CertificateMaterial certificate : binding.certificates()) {
            if (Pem.parseCertificate(certificate.certificateBody()).equals(presented[0])) {
                return certificate.arn();
            }
        }
        return null;
    }

    private static String address(SocketAddress address) {
        return address == null ? null : address.hostAddress() + ":" + address.port();
    }

    /** Floci's shared socket first uses load-balancer DNS, then unique rule or certificate hosts. */
    private RoutedListener resolveListener(RoutingView routing, String hostHeader) {
        String host = normalizeHost(hostHeader);
        String direct = routing.hosts().get(host);
        if (direct != null) {
            return routing.listeners().get(direct);
        }
        List<RoutedListener> declaring = routing.listeners().values().stream()
                .filter(listener -> listener.chain().stream().anyMatch(rule -> rule.declaresHost(host)))
                .toList();
        if (!declaring.isEmpty()) {
            return declaring.size() == 1 ? declaring.getFirst() : null;
        }
        List<RoutedListener> certificates = routing.listeners().values().stream()
                .filter(listener -> listener.certificateHosts().stream()
                        .anyMatch(candidate -> candidate.equals(host) || wildcardMatches(candidate, host)))
                .toList();
        if (!certificates.isEmpty()) {
            return certificates.size() == 1 ? certificates.getFirst() : null;
        }
        return routing.hosts().size() == 1
                ? routing.listeners().get(routing.hosts().values().iterator().next()) : null;
    }

    private static boolean wildcardMatches(String candidate, String host) {
        return candidate.startsWith("*.")
                && host.length() > candidate.length() - 1
                && host.endsWith(candidate.substring(1))
                && host.indexOf('.') == host.length() - candidate.length() + 1;
    }

    private static String normalizeHost(String host) {
        if (host == null) {
            return "";
        }
        String normalized = host.trim().toLowerCase();
        int colon = normalized.lastIndexOf(':');
        int bracket = normalized.lastIndexOf(']');
        if (colon > -1 && colon > bracket) {
            normalized = normalized.substring(0, colon);
        }
        return normalized;
    }

    private void executeAction(io.vertx.core.http.HttpServerRequest req, Action action, String region, String listenerArn,
                               ElbV2AccessLogEntry log) {
        if (action == null) {
            req.response().setStatusCode(502).end("No action");
            return;
        }
        switch (action.getType() != null ? action.getType() : "") {
            case "forward" -> executeForward(req, action, region, listenerArn, log);
            case "redirect" -> executeRedirect(req, action, log);
            case "fixed-response" -> executeFixedResponse(req, action, log);
            default -> req.response().setStatusCode(502).end("Unsupported action type");
        }
    }

    private void executeForward(io.vertx.core.http.HttpServerRequest req, Action action, String region, String listenerArn,
                                ElbV2AccessLogEntry log) {
        log.actions.add("forward");
        String tgArn = resolveTgArn(action);
        if (tgArn == null) {
            req.response().setStatusCode(502).end("No target group");
            return;
        }
        TargetGroup tg = elbV2Service.getTargetGroup(region, tgArn);
        if (tg == null) {
            req.response().setStatusCode(502).end("Target group not found");
            return;
        }
        log.targetGroupArn = tgArn;

        if ("lambda".equals(tg.getTargetType())) {
            if (isWebSocketUpgrade(req)) {
                log.errorReason = "LambdaWebsocketNotSupported";
                req.response().setStatusCode(400).end("WebSockets are not supported for Lambda targets");
                return;
            }
            List<TargetDescription> targets = tg.getTargets();
            if (targets.isEmpty()) {
                req.response().setStatusCode(503).end("No Lambda targets registered");
                return;
            }
            String functionArn = targets.get(0).getId();
            invokeLambdaTarget(req, functionArn, region, log);
            return;
        }

        List<TargetDescription> allTargets = tg.getTargets();
        List<TargetDescription> healthy = allTargets.stream()
                .filter(t -> healthChecker.isHealthy(tgArn, t, ElbV2HealthChecker.effectivePort(t, tg)))
                .collect(Collectors.toList());
        List<TargetDescription> candidates = healthy.isEmpty() ? allTargets : healthy;
        if (candidates.isEmpty()) {
            req.response().setStatusCode(503).end("No targets available");
            return;
        }
        ListenerBinding binding = listenerBindings.get(listenerArn);
        long duration = ElbV2StickyCookie.durationSeconds(tg);
        String scope = binding != null ? binding.loadBalancerArn() + "\n" + tgArn : "";
        TargetDescription target = stickyCookie.target(req.headers().getAll("Cookie"), scope, tg, candidates, duration);
        if (target == null) {
            AtomicInteger counter = rrCounters.computeIfAbsent(tgArn, k -> new AtomicInteger(0));
            int idx = Math.abs(counter.getAndIncrement() % candidates.size());
            target = candidates.get(idx);
        }
        List<String> cookies = duration > 0 ? stickyCookie.headers(scope, tg, target) : List.of();
        int targetPort = ElbV2HealthChecker.effectivePort(target, tg);
        String host = ElbV2TargetResolver.resolveHost(ec2Service, tg, target);
        boolean preserveHostHeader = Boolean.parseBoolean(
                loadBalancerAttribute(listenerArn, region, PRESERVE_HOST_HEADER_ATTRIBUTE));
        if (isWebSocketUpgrade(req)) {
            proxyUpgrade(req, host, targetPort, preserveHostHeader, idleTimeoutMillis(listenerArn, region), cookies, log);
            return;
        }
        proxyRequest(req, host, targetPort, preserveHostHeader, cookies, log);
    }

    private String loadBalancerAttribute(String listenerArn, String region, String key) {
        ListenerBinding binding = listenerBindings.get(listenerArn);
        if (binding == null) {
            return null;
        }
        LoadBalancer loadBalancer = elbV2Service.getLoadBalancer(region, binding.loadBalancerArn());
        if (loadBalancer == null || loadBalancer.getAttributes() == null) {
            return null;
        }
        return loadBalancer.getAttributes().get(key);
    }

    private long idleTimeoutMillis(String listenerArn, String region) {
        String configured = loadBalancerAttribute(listenerArn, region, IDLE_TIMEOUT_ATTRIBUTE);
        long seconds = DEFAULT_IDLE_TIMEOUT_SECONDS;
        if (configured != null) {
            try {
                seconds = Long.parseLong(configured.trim());
            } catch (NumberFormatException e) {
                LOG.debugv("Ignoring non-numeric {0} value {1}", IDLE_TIMEOUT_ATTRIBUTE, configured);
            }
        }
        return Math.max(1, seconds) * 1000;
    }

    private void invokeLambdaTarget(io.vertx.core.http.HttpServerRequest req, String functionArn, String region,
                                    ElbV2AccessLogEntry log) {
        if (req.isEnded()) {
            invokeLambdaWithBody(req, functionArn, region, Buffer.buffer(), log);
            return;
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        AtomicBoolean rejected = new AtomicBoolean();
        req.handler(chunk -> {
            if (rejected.get()) {
                return;
            }
            if (body.size() > MAX_LAMBDA_BODY_BYTES - chunk.length()) {
                rejected.set(true);
                log.errorReason = "LambdaRequestTooLarge";
                req.response().setStatusCode(413).end();
                return;
            }
            body.writeBytes(chunk.getBytes());
        });
        req.exceptionHandler(error -> {
            if (rejected.compareAndSet(false, true)) {
                req.response().setStatusCode(502).end("Request body error");
            }
        });
        req.endHandler(ignored -> {
            if (rejected.get()) {
                return;
            }
            invokeLambdaWithBody(req, functionArn, region, Buffer.buffer(body.toByteArray()), log);
        });
    }

    private void invokeLambdaWithBody(io.vertx.core.http.HttpServerRequest req, String functionArn,
                                      String region, Buffer body, ElbV2AccessLogEntry log) {
        Map<String, Object> event = buildAlbEvent(req, body);
        log.dispatched();
        // Lambda invocation is synchronous and may take seconds while a cold container
        // boots and polls the Runtime API. The Runtime API itself runs on Vert.x event
        // loops, so blocking the listener's event loop here would deadlock the runtime
        // and the function would time out. Offload to a worker thread, same as WebSocket.
        // ordered=false so independent ALB requests run in parallel on the worker pool.
        vertx.<InvokeResult>executeBlocking(() -> {
            byte[] payload = objectMapper.writeValueAsBytes(event);
            return lambdaService.invoke(region, functionArn, payload, InvocationType.RequestResponse);
        }, false).onSuccess(result -> {
            log.responded(null);
            log.responding();
            try {
                writeLambdaResponse(req, result, log);
            } catch (Exception e) {
                LOG.errorf(e, "Error writing Lambda response for %s", functionArn);
                log.errorReason = "LambdaInvalidResponse";
                req.response().setStatusCode(502).end("Lambda invocation error");
            }
        }).onFailure(e -> {
            LOG.errorf(e, "Error invoking Lambda target %s", functionArn);
            log.errorReason = e instanceof AwsException aws && "ResourceNotFoundException".equals(aws.getErrorCode())
                    ? "LambdaResourceNotFound" : "LambdaServiceException";
            req.response().setStatusCode(502).end("Lambda invocation error");
        });
    }

    private void writeLambdaResponse(io.vertx.core.http.HttpServerRequest req, InvokeResult result,
                                     ElbV2AccessLogEntry log) throws java.io.IOException {
        if (result.getFunctionError() != null) {
            log.errorReason = "LambdaUnhandled";
            req.response().setStatusCode(502).end("Lambda function error: " + result.getFunctionError());
            return;
        }

        if (result.getPayload() == null || result.getPayload().length == 0) {
            log.targetStatusCode = "200";
            req.response().setStatusCode(200).end();
            return;
        }
        Map<String, Object> lambdaResp = objectMapper.readValue(result.getPayload(),
                new TypeReference<Map<String, Object>>() {});

        Object responseBody = lambdaResp.get("body");
        Boolean isBase64 = (Boolean) lambdaResp.get("isBase64Encoded");
        byte[] decodedBody = null;
        String textBody = null;
        if (responseBody != null) {
            if (Boolean.TRUE.equals(isBase64)) {
                decodedBody = Base64.getDecoder().decode(String.valueOf(responseBody));
                if (decodedBody.length > MAX_LAMBDA_BODY_BYTES) {
                    log.errorReason = "LambdaResponseTooLarge";
                    req.response().setStatusCode(502).end();
                    return;
                }
            } else {
                textBody = String.valueOf(responseBody);
                if (textBody.getBytes(StandardCharsets.UTF_8).length > MAX_LAMBDA_BODY_BYTES) {
                    log.errorReason = "LambdaResponseTooLarge";
                    req.response().setStatusCode(502).end();
                    return;
                }
            }
        }

        int statusCode = 200;
        Object sc = lambdaResp.get("statusCode");
        if (sc != null) {
            statusCode = ((Number) sc).intValue();
        }
        log.targetStatusCode = String.valueOf(statusCode);
        req.response().setStatusCode(statusCode);

        Object headers = lambdaResp.get("headers");
        if (headers instanceof Map<?, ?> headerMap) {
            for (Map.Entry<?, ?> entry : headerMap.entrySet()) {
                req.response().putHeader(String.valueOf(entry.getKey()), String.valueOf(entry.getValue()));
            }
        }

        Object multiValueHeaders = lambdaResp.get("multiValueHeaders");
        if (multiValueHeaders instanceof Map<?, ?> mvh) {
            for (Map.Entry<?, ?> entry : mvh.entrySet()) {
                if (entry.getValue() instanceof List<?> values) {
                    for (Object v : values) {
                        req.response().putHeader(String.valueOf(entry.getKey()), String.valueOf(v));
                    }
                }
            }
        }

        if (responseBody == null) {
            req.response().end();
        } else if (decodedBody != null) {
            req.response().end(Buffer.buffer(decodedBody));
        } else {
            req.response().end(textBody);
        }
    }

    private Map<String, Object> buildAlbEvent(io.vertx.core.http.HttpServerRequest req, Buffer body) {
        Map<String, Object> event = new HashMap<>();
        event.put("requestContext", Map.of("elb", Map.of("targetGroupArn", "")));
        event.put("httpMethod", req.method().name());
        event.put("path", req.path() != null ? req.path() : "/");

        Map<String, String> queryParams = new HashMap<>();
        Map<String, List<String>> multiValueQueryParams = new HashMap<>();
        String query = req.query();
        if (query != null && !query.isEmpty()) {
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                String key = eq >= 0 ? pair.substring(0, eq) : pair;
                String val = eq >= 0 ? pair.substring(eq + 1) : "";
                queryParams.putIfAbsent(key, val);
                multiValueQueryParams.computeIfAbsent(key, k -> new ArrayList<>()).add(val);
            }
        }
        event.put("queryStringParameters", queryParams.isEmpty() ? null : queryParams);
        event.put("multiValueQueryStringParameters", multiValueQueryParams.isEmpty() ? null : multiValueQueryParams);

        Map<String, String> headers = new HashMap<>();
        Map<String, List<String>> multiValueHeaders = new HashMap<>();
        req.headers().forEach(entry -> {
            String key = entry.getKey().toLowerCase();
            headers.putIfAbsent(key, entry.getValue());
            multiValueHeaders.computeIfAbsent(key, k -> new ArrayList<>()).add(entry.getValue());
        });
        event.put("headers", headers);
        event.put("multiValueHeaders", multiValueHeaders);

        boolean isBase64 = false;
        String bodyStr = null;
        if (body != null && body.length() > 0) {
            String contentType = req.getHeader("Content-Type");
            if (contentType != null && !contentType.startsWith("text/") && !contentType.contains("json")
                    && !contentType.contains("xml") && !contentType.contains("form")) {
                bodyStr = Base64.getEncoder().encodeToString(body.getBytes());
                isBase64 = true;
            } else {
                bodyStr = body.toString(StandardCharsets.UTF_8);
            }
        }
        event.put("body", bodyStr);
        event.put("isBase64Encoded", isBase64);

        return event;
    }

    private String resolveTgArn(Action action) {
        if (action.getTargetGroupArn() != null) {
            return action.getTargetGroupArn();
        }
        List<Action.TargetGroupTuple> tuples = action.getTargetGroups();
        if (tuples == null || tuples.isEmpty()) {
            return null;
        }
        double total = tuples.stream().mapToDouble(t -> t.getWeight() != null ? t.getWeight() : 1).sum();
        double roll = Math.random() * total;
        double cumulative = 0;
        for (Action.TargetGroupTuple tuple : tuples) {
            cumulative += (tuple.getWeight() != null ? tuple.getWeight() : 1);
            if (roll < cumulative) {
                return tuple.getTargetGroupArn();
            }
        }
        return tuples.get(tuples.size() - 1).getTargetGroupArn();
    }

    private void proxyRequest(io.vertx.core.http.HttpServerRequest req, String host, int port,
                              boolean preserveHostHeader, List<String> cookies, ElbV2AccessLogEntry log) {
        req.pause();
        if (ElbV2TargetResolver.isIpLiteral(host)) {
            try {
                proxyRequestTo(req, ElbV2TargetResolver.resolveCheckedAddress(host), host, port, preserveHostHeader,
                        cookies, log);
            } catch (IOException e) {
                rejectTarget(req, host, e);
            }
            return;
        }
        vertx.<String>executeBlocking(() -> ElbV2TargetResolver.resolveCheckedAddress(host))
                .onSuccess(address -> proxyRequestTo(req, address, host, port, preserveHostHeader, cookies, log))
                .onFailure(err -> rejectTarget(req, host, err));
    }

    private void rejectTarget(HttpServerRequest req, String host, Throwable err) {
        LOG.warnv("Refusing to proxy to target {0}: {1}", host, err.getMessage());
        req.resume();
        req.response().setStatusCode(503).end("Service unavailable");
    }

    private void proxyRequestTo(HttpServerRequest req, String address, String host, int port,
                                boolean preserveHostHeader, List<String> cookies, ElbV2AccessLogEntry log) {
        log.target = address + ":" + port;
        RequestOptions opts = new RequestOptions()
                .setHost(address)
                .setPort(port)
                .setURI(req.uri())
                .setMethod(req.method());
        proxyClient.request(opts)
                .onSuccess(clientReq -> {
                    req.headers().forEach(entry -> {
                        if (!HOP_BY_HOP_HEADERS.contains(entry.getKey().toLowerCase())) {
                            clientReq.putHeader(entry.getKey(), entry.getValue());
                        }
                    });
                    if (!preserveHostHeader) {
                        clientReq.putHeader("Host", ElbV2TargetResolver.hostHeader(host, port));
                    }
                    AtomicBoolean responseStarted = new AtomicBoolean();
                    AtomicBoolean requestFailed = new AtomicBoolean();
                    clientReq.response().onSuccess(resp -> {
                        if (requestFailed.get()) {
                            return;
                        }
                        responseStarted.set(true);
                        log.responded(String.valueOf(resp.statusCode()));
                        req.response().setStatusCode(resp.statusCode());
                        copyTargetResponseHeaders(resp.headers(), req.response());
                        cookies.forEach(cookie -> req.response().headers().add("Set-Cookie", cookie));
                        if (resp.getHeader("Content-Length") == null) {
                            req.response().setChunked(true);
                        }
                        log.responding();
                        resp.pipeTo(req.response());
                        resp.exceptionHandler(error -> {
                            if (req.response().headWritten()) {
                                req.response().close();
                            } else {
                                req.response().setStatusCode(502).end("Body error");
                            }
                        });
                    }).onFailure(error -> {
                        vertx.runOnContext(ignored -> {
                            if (requestFailed.compareAndSet(false, true)) {
                                if (responseStarted.get() || req.response().headWritten()) {
                                    req.response().close();
                                } else {
                                    req.response().setStatusCode(502).end("Bad gateway");
                                }
                            }
                        });
                    });

                    log.dispatched();
                    clientReq.send(req);
                    req.resume();
                })
                .onFailure(err -> {
                    req.resume();
                    req.response().setStatusCode(503).end("Service unavailable");
                });
    }

    private static void copyTargetResponseHeaders(MultiMap headers, HttpServerResponse response) {
        for (String name : headers.names()) {
            if (!HOP_BY_HOP_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                response.putHeader(name, headers.getAll(name));
            }
        }
    }

    /**
     * An ALB forwards a WebSocket handshake to an instance or ip target with its upgrade headers
     * intact, which an ordinary proxied request cannot do: {@code Connection} and {@code Upgrade}
     * are hop-by-hop and are stripped. AWS only tunnels WebSocket upgrades, over HTTP/1.1.
     */
    static boolean isWebSocketUpgrade(HttpServerRequest req) {
        if (req.version() != HttpVersion.HTTP_1_1 || req.method() != HttpMethod.GET) {
            return false;
        }
        if (!"websocket".equalsIgnoreCase(req.getHeader("Upgrade"))) {
            return false;
        }
        for (String connection : req.headers().getAll("Connection")) {
            for (String token : connection.split(",")) {
                if ("upgrade".equalsIgnoreCase(token.trim())) {
                    return true;
                }
            }
        }
        return false;
    }

    private void proxyUpgrade(HttpServerRequest req, String host, int port, boolean preserveHostHeader,
                              long idleTimeoutMillis, List<String> cookies, ElbV2AccessLogEntry log) {
        req.pause();
        if (ElbV2TargetResolver.isIpLiteral(host)) {
            try {
                proxyUpgradeTo(req, ElbV2TargetResolver.resolveCheckedAddress(host), host, port,
                        preserveHostHeader, idleTimeoutMillis, cookies, log);
            } catch (IOException e) {
                rejectTarget(req, host, e);
            }
            return;
        }
        vertx.<String>executeBlocking(() -> ElbV2TargetResolver.resolveCheckedAddress(host))
                .onSuccess(address -> proxyUpgradeTo(req, address, host, port, preserveHostHeader,
                        idleTimeoutMillis, cookies, log))
                .onFailure(err -> rejectTarget(req, host, err));
    }

    /**
     * Sends the handshake to the target and, once it answers {@code 101 Switching Protocols},
     * relays that answer and joins the two connections into a byte tunnel. Any other answer means
     * the target refused the upgrade and is relayed as an ordinary response.
     */
    private void proxyUpgradeTo(HttpServerRequest req, String address, String host, int port,
                                boolean preserveHostHeader, long idleTimeoutMillis, List<String> cookies,
                                ElbV2AccessLogEntry log) {
        log.target = address + ":" + port;
        RequestOptions opts = new RequestOptions()
                .setHost(address)
                .setPort(port)
                .setURI(req.uri())
                .setMethod(req.method());
        proxyClient.request(opts)
                .onSuccess(clientReq -> {
                    req.headers().forEach(entry -> {
                        if (!HOP_BY_HOP_HEADERS.contains(entry.getKey().toLowerCase())) {
                            clientReq.putHeader(entry.getKey(), entry.getValue());
                        }
                    });
                    clientReq.putHeader("Connection", "Upgrade");
                    clientReq.putHeader("Upgrade", req.getHeader("Upgrade"));
                    if (!preserveHostHeader) {
                        clientReq.putHeader("Host", ElbV2TargetResolver.hostHeader(host, port));
                    }
                    log.dispatched();
                    clientReq.connect()
                            .onSuccess(resp -> {
                                log.responded(String.valueOf(resp.statusCode()));
                                log.responding();
                                req.response().setStatusCode(resp.statusCode());
                                copyTargetResponseHeaders(resp.headers(), req.response());
                                cookies.forEach(cookie -> req.response().headers().add("Set-Cookie", cookie));
                                if (resp.statusCode() != 101) {
                                    req.resume();
                                    if (resp.getHeader("Content-Length") == null) {
                                        req.response().setChunked(true);
                                    }
                                    resp.pipeTo(req.response());
                                    return;
                                }
                                req.response().putHeader("Connection", "Upgrade");
                                req.response().putHeader("Upgrade", resp.getHeader("Upgrade"));
                                NetSocket targetSocket = resp.netSocket();
                                log.tunneled = true;
                                log.type = "http".equals(log.type) ? "ws" : "wss";
                                long handshakeOut = ElbV2AccessLogEntry.headBytes(
                                        "HTTP/1.1 101 Switching Protocols", req.response().headers());
                                req.toNetSocket()
                                        .onSuccess(clientSocket -> tunnel(clientSocket, targetSocket,
                                                idleTimeoutMillis, (in, out) -> finishLog(log, 101,
                                                        log.requestHeadBytes + in, handshakeOut + out)))
                                        .onFailure(err -> {
                                            LOG.debugv("WebSocket upgrade to {0}:{1} lost the client: {2}",
                                                    host, String.valueOf(port), err.getMessage());
                                            targetSocket.close();
                                        });
                            })
                            .onFailure(err -> {
                                LOG.debugv("WebSocket upgrade to {0}:{1} failed: {2}",
                                        host, String.valueOf(port), err.getMessage());
                                req.resume();
                                if (req.response().headWritten()) {
                                    req.response().close();
                                } else {
                                    req.response().setStatusCode(502).end("Bad gateway");
                                }
                            });
                })
                .onFailure(err -> {
                    req.resume();
                    req.response().setStatusCode(503).end("Service unavailable");
                });
    }

    /**
     * Relays bytes both ways until either side closes or no data crosses the tunnel in either
     * direction for the load balancer's {@code idle_timeout.timeout_seconds}, as an ALB does.
     */
    private void tunnel(NetSocket client, NetSocket target, long idleTimeoutMillis, BiConsumer<Long, Long> closed) {
        AtomicLong lastActivity = new AtomicLong(System.nanoTime());
        AtomicLong timerId = new AtomicLong(-1);
        AtomicLong received = new AtomicLong();
        AtomicLong sent = new AtomicLong();
        AtomicBoolean done = new AtomicBoolean();
        Runnable close = () -> {
            if (done.compareAndSet(false, true)) {
                vertx.cancelTimer(timerId.get());
                client.close();
                target.close();
                closed.accept(received.get(), sent.get());
            }
        };
        relay(client, target, lastActivity, received, close);
        relay(target, client, lastActivity, sent, close);
        scheduleIdleCheck(idleTimeoutMillis, idleTimeoutMillis, lastActivity, timerId, done, close);
    }

    private void scheduleIdleCheck(long delayMillis, long idleTimeoutMillis, AtomicLong lastActivity,
                                   AtomicLong timerId, AtomicBoolean closed, Runnable close) {
        if (closed.get()) {
            return;
        }
        timerId.set(vertx.setTimer(delayMillis, ignored -> {
            long idleMillis = (System.nanoTime() - lastActivity.get()) / 1_000_000;
            if (idleMillis >= idleTimeoutMillis) {
                close.run();
            } else {
                scheduleIdleCheck(idleTimeoutMillis - idleMillis, idleTimeoutMillis, lastActivity, timerId,
                        closed, close);
            }
        }));
    }

    private static void relay(NetSocket source, NetSocket destination, AtomicLong lastActivity, AtomicLong bytes,
                              Runnable close) {
        source.handler(buffer -> {
            lastActivity.set(System.nanoTime());
            bytes.addAndGet(buffer.length());
            destination.write(buffer);
            if (destination.writeQueueFull()) {
                source.pause();
                destination.drainHandler(ignored -> source.resume());
            }
        });
        source.endHandler(ignored -> close.run());
        source.closeHandler(ignored -> close.run());
        source.exceptionHandler(err -> close.run());
    }

    private void executeRedirect(io.vertx.core.http.HttpServerRequest req, Action action, ElbV2AccessLogEntry log) {
        String reqHost = req.host();
        String reqPort = "";
        if (reqHost != null && reqHost.contains(":")) {
            String[] parts = reqHost.split(":", 2);
            reqHost = parts[0];
            reqPort = parts[1];
        }
        String reqPath = req.path() != null ? req.path() : "/";
        String reqQuery = req.query();
        String reqProtocol = "HTTP";

        String protocol = action.getRedirectProtocol() != null ? action.getRedirectProtocol() : reqProtocol;
        String host = action.getRedirectHost() != null ? action.getRedirectHost() : reqHost;
        String portStr = action.getRedirectPort() != null ? action.getRedirectPort() : reqPort;
        String path = action.getRedirectPath() != null ? action.getRedirectPath() : reqPath;
        String query = action.getRedirectQuery() != null ? action.getRedirectQuery() : (reqQuery != null ? reqQuery : "");

        final String finalReqHost = reqHost;
        final String finalReqPort = reqPort;

        protocol = substitute(protocol, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);
        host = substitute(host, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);
        portStr = substitute(portStr, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);
        path = substitute(path, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);
        query = substitute(query, finalReqHost, finalReqPort, reqPath, reqProtocol, reqQuery);

        StringBuilder location = new StringBuilder(protocol.toLowerCase()).append("://").append(host);
        if (!portStr.isEmpty()) {
            location.append(":").append(portStr);
        }
        location.append(path);
        if (!query.isEmpty()) {
            location.append("?").append(query);
        }

        int statusCode = "HTTP_301".equals(action.getRedirectStatusCode()) ? 301 : 302;
        log.actions.add("redirect");
        log.redirectUrl = location.toString();
        req.response()
                .setStatusCode(statusCode)
                .putHeader("Location", location.toString())
                .end();
    }

    private String substitute(String template, String host, String port, String path, String protocol, String query) {
        if (template == null) {
            return "";
        }
        String result = template
                .replace("#{host}", host != null ? host : "")
                .replace("#{port}", port != null ? port : "")
                .replace("#{path}", path != null ? path : "/")
                .replace("#{protocol}", protocol != null ? protocol : "HTTP");
        if (query != null && !query.isEmpty()) {
            result = result.replace("#{query}", query);
        } else {
            result = result.replace("#{query}", "");
        }
        return result;
    }

    private void executeFixedResponse(io.vertx.core.http.HttpServerRequest req, Action action,
                                      ElbV2AccessLogEntry log) {
        log.actions.add("fixed-response");
        int statusCode = 200;
        try {
            if (action.getFixedResponseStatusCode() != null) {
                statusCode = Integer.parseInt(action.getFixedResponseStatusCode());
            }
        } catch (NumberFormatException ignored) {
        }
        req.response().setStatusCode(statusCode);
        if (action.getFixedResponseContentType() != null) {
            req.response().putHeader("Content-Type", action.getFixedResponseContentType());
        }
        String body = action.getFixedResponseMessageBody() != null ? action.getFixedResponseMessageBody() : "";
        req.response().end(body);
    }

    private List<CompiledRule> compileRules(List<Rule> rules) {
        return rules.stream()
                .map(CompiledRule::new)
                .collect(Collectors.toList());
    }

    private Action getRoutingAction(Rule rule) {
        List<Action> actions = rule.getActions();
        if (actions == null || actions.isEmpty()) {
            return null;
        }
        Action last = null;
        for (Action a : actions) {
            String type = a.getType();
            if ("forward".equals(type) || "redirect".equals(type) || "fixed-response".equals(type)) {
                last = a;
            }
        }
        return last;
    }

    private static boolean globMatches(String pattern, String text) {
        if (text == null) {
            return false;
        }
        StringBuilder regex = new StringBuilder("(?i)");
        for (char c : pattern.toCharArray()) {
            if (c == '*') {
                regex.append(".*");
            } else if (c == '?') {
                regex.append('.');
            } else {
                regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.matches(regex.toString(), text);
    }

    private class CompiledRule {
        final Rule rule;
        final Action action;
        final List<String> hostHeaderPatterns;

        CompiledRule(Rule rule) {
            this.rule = rule;
            this.action = getRoutingAction(rule);
            this.hostHeaderPatterns = hostHeaderPatterns(rule);
        }

        /**
         * The hostnames this rule declares through its {@code host-header} conditions. Collected
         * at compile time because listener selection consults them on every request, before any
         * rule is evaluated. The default rule declares nothing: it matches every Host header, so
         * counting it would make every listener claim every hostname.
         */
        private static List<String> hostHeaderPatterns(Rule rule) {
            if (rule.isDefault() || rule.getConditions() == null) {
                return List.of();
            }
            List<String> patterns = new ArrayList<>();
            for (RuleCondition condition : rule.getConditions()) {
                if (!"host-header".equals(condition.getField())) {
                    continue;
                }
                patterns.addAll(condition.getHostHeaderValues().isEmpty()
                        ? condition.getValues()
                        : condition.getHostHeaderValues());
            }
            return patterns;
        }

        boolean declaresHost(String host) {
            return hostHeaderPatterns.stream().anyMatch(p -> globMatches(p, host));
        }

        boolean matches(io.vertx.core.http.HttpServerRequest req) {
            if (rule.isDefault()) {
                return true;
            }
            for (RuleCondition condition : rule.getConditions()) {
                if (!matchesCondition(condition, req)) {
                    return false;
                }
            }
            return true;
        }

        private boolean matchesCondition(RuleCondition condition, io.vertx.core.http.HttpServerRequest req) {
            String field = condition.getField();
            if (field == null) {
                return true;
            }
            return switch (field) {
                case "host-header" -> {
                    List<String> patterns = condition.getHostHeaderValues().isEmpty()
                            ? condition.getValues()
                            : condition.getHostHeaderValues();
                    String host = req.host();
                    if (host != null && host.contains(":")) {
                        host = host.substring(0, host.indexOf(':'));
                    }
                    String effectiveHost = host;
                    yield patterns.stream().anyMatch(p -> globMatches(p, effectiveHost));
                }
                case "path-pattern" -> {
                    List<String> patterns = condition.getPathPatternValues().isEmpty()
                            ? condition.getValues()
                            : condition.getPathPatternValues();
                    String path = req.path();
                    yield patterns.stream().anyMatch(p -> globMatches(p, path));
                }
                case "http-header" -> {
                    String headerName = condition.getHttpHeaderName();
                    if (headerName == null) {
                        yield true;
                    }
                    String headerValue = req.getHeader(headerName);
                    yield condition.getHttpHeaderValues().stream().anyMatch(p -> globMatches(p, headerValue));
                }
                case "http-request-method" -> {
                    String method = req.method().name();
                    yield condition.getHttpMethodValues().stream()
                            .anyMatch(m -> m.equalsIgnoreCase(method));
                }
                case "query-string" -> {
                    String queryString = req.query();
                    Map<String, String> queryParams = parseQueryString(queryString);
                    yield condition.getQueryStringValues().stream().allMatch(pair -> {
                        String key = pair.getKey();
                        String valuePattern = pair.getValue();
                        if (key == null) {
                            return queryParams.values().stream().anyMatch(v -> globMatches(valuePattern, v));
                        }
                        String paramValue = queryParams.get(key);
                        return paramValue != null && globMatches(valuePattern, paramValue);
                    });
                }
                case "source-ip" -> true;
                default -> true;
            };
        }

        private Map<String, String> parseQueryString(String query) {
            Map<String, String> params = new java.util.LinkedHashMap<>();
            if (query == null || query.isEmpty()) {
                return params;
            }
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                if (eq >= 0) {
                    params.put(pair.substring(0, eq), pair.substring(eq + 1));
                } else {
                    params.put(pair, "");
                }
            }
            return params;
        }
    }
}
