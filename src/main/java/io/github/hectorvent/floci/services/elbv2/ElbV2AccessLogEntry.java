package io.github.hectorvent.floci.services.elbv2;

import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpVersion;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * One Application Load Balancer access-log entry, filled in while the data plane handles a request
 * and rendered with the fields of AWS's "Access log entries" table, in its order and quoting. A
 * field the request never reached is {@code -}, and a processing time is {@code -1} when the request
 * never reached the step it times.
 */
final class ElbV2AccessLogEntry {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'")
            .withZone(ZoneOffset.UTC);
    private static final int MAX_USER_AGENT_BYTES = 8 * 1024;
    private static final List<String> SEVERITY = List.of("Acceptable", "Ambiguous", "Severe");

    final String loadBalancerArn;
    final String region;
    final Instant received;
    final List<String> actions = new ArrayList<>();
    private final long receivedNanos;
    String type;
    String client;
    String nodeIp;
    String requestLine;
    String userAgent;
    String sslCipher;
    String sslProtocol;
    String traceId;
    String domainName;
    String chosenCertArn;
    String connTraceId;
    String classification;
    String classificationReason;
    String target;
    String targetGroupArn;
    String matchedRulePriority;
    String redirectUrl;
    String errorReason;
    String targetStatusCode;
    boolean tunneled;
    long requestHeadBytes;
    private long dispatchedNanos = -1;
    private long respondedNanos = -1;
    private long respondingNanos = -1;
    private Instant time;
    private int elbStatusCode;
    private long receivedBytes;
    private long sentBytes;

    ElbV2AccessLogEntry(String loadBalancerArn, String region, Instant received, long receivedNanos) {
        this.loadBalancerArn = loadBalancerArn;
        this.region = region;
        this.received = received;
        this.receivedNanos = receivedNanos;
    }

    void dispatched() {
        dispatchedNanos = System.nanoTime();
    }

    void responded(String targetStatus) {
        respondedNanos = System.nanoTime();
        targetStatusCode = targetStatus;
    }

    void responding() {
        respondingNanos = System.nanoTime();
    }

    /** Sets the response fields; false when the entry was already completed. */
    synchronized boolean complete(Instant time, int elbStatusCode, long receivedBytes, long sentBytes) {
        if (this.time != null) {
            return false;
        }
        this.time = time;
        this.elbStatusCode = elbStatusCode;
        this.receivedBytes = receivedBytes;
        this.sentBytes = sentBytes;
        return true;
    }

    Instant time() {
        return time;
    }

    String render() {
        return String.join(" ",
                type,
                TIME.format(time),
                loadBalancerArn.substring(loadBalancerArn.indexOf(":loadbalancer/") + ":loadbalancer/".length()),
                client,
                dash(target),
                seconds(receivedNanos, dispatchedNanos),
                seconds(dispatchedNanos, respondedNanos),
                seconds(respondedNanos, respondingNanos),
                String.valueOf(elbStatusCode),
                dash(targetStatusCode),
                String.valueOf(receivedBytes),
                String.valueOf(sentBytes),
                quote(requestLine),
                quote(userAgent),
                dash(sslCipher),
                dash(sslProtocol),
                dash(targetGroupArn),
                quote(traceId),
                quote(domainName),
                quote(chosenCertArn),
                dash(matchedRulePriority),
                TIME.format(received),
                quote(actions.isEmpty() ? null : String.join(",", actions)),
                quote(redirectUrl),
                quote(errorReason),
                quote(target),
                quote(targetStatusCode),
                quote(classification),
                quote(classificationReason),
                dash(connTraceId),
                quote(null),
                quote(null),
                quote(null),
                dash(nodeIp),
                "-",
                "-");
    }

    void userAgent(String header) {
        if (header == null) {
            return;
        }
        byte[] bytes = header.getBytes(StandardCharsets.UTF_8);
        userAgent = bytes.length <= MAX_USER_AGENT_BYTES ? header
                : new String(bytes, 0, MAX_USER_AGENT_BYTES, StandardCharsets.UTF_8);
    }

    static String requestLine(HttpMethod method, boolean secure, String host, int port, String uri,
                              HttpVersion version) {
        String httpVersion = switch (version) {
            case HTTP_1_0 -> "HTTP/1.0";
            case HTTP_2 -> "HTTP/2.0";
            default -> "HTTP/1.1";
        };
        return method.name() + " " + (secure ? "https" : "http") + "://" + host + ":" + port + uri + " " + httpVersion;
    }

    /** A new {@code X-Amzn-Trace-Id} value, {@code Root=1-<epoch seconds in hex>-<96 random bits>}. */
    static String newTraceId(Instant now) {
        byte[] random = new byte[12];
        ThreadLocalRandom.current().nextBytes(random);
        return "Root=1-" + HexFormat.of().toHexDigits((int) now.getEpochSecond()) + "-" + HexFormat.of().formatHex(random);
    }

    static String newConnTraceId() {
        return "TID_" + HexFormat.of().toHexDigits(ThreadLocalRandom.current().nextLong());
    }

    /**
     * The desync-mitigation classification of a request that reached Floci, as {@code {classification,
     * reason}}, or null when it complies with RFC 7230. Only the reasons Vert.x lets through are
     * detectable here: it rejects the malformed requests AWS classifies as Severe before any handler runs.
     */
    static String[] classify(HttpMethod method, MultiMap headers) {
        String[] worst = null;
        boolean getOrHead = method == HttpMethod.GET || method == HttpMethod.HEAD;
        if (getOrHead) {
            String contentLength = headers.get("Content-Length");
            if (contentLength != null) {
                worst = worse(worst, "0".equals(contentLength.trim())
                        ? new String[] {"Acceptable", "GetHeadZeroContentLength"}
                        : new String[] {"Ambiguous", "UndefinedContentLengthSemantics"});
            }
            if (headers.contains("Transfer-Encoding")) {
                worst = worse(worst, new String[] {"Ambiguous", "UndefinedTransferEncodingSemantics"});
            }
        }
        for (Map.Entry<String, String> header : headers) {
            if (!isCompliant(header.getKey()) || !isCompliant(header.getValue())) {
                worst = worse(worst, new String[] {"Acceptable", "NonCompliantHeader"});
            }
        }
        return worst;
    }

    private static boolean isCompliant(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c > 0x7e || (c < 0x20 && c != '\t')) {
                return false;
            }
        }
        return true;
    }

    private static String[] worse(String[] current, String[] candidate) {
        return current == null || SEVERITY.indexOf(candidate[0]) > SEVERITY.indexOf(current[0]) ? candidate : current;
    }

    /** Bytes of an HTTP/1.1 head: the start line, each header line and the blank line after them. */
    static long headBytes(String startLine, MultiMap headers) {
        long bytes = startLine.length() + 2L + 2L;
        for (Map.Entry<String, String> header : headers) {
            bytes += header.getKey().length() + 2L + header.getValue().length() + 2L;
        }
        return bytes;
    }

    private static String seconds(long from, long to) {
        return from < 0 || to < 0 ? "-1" : String.format(Locale.ROOT, "%.3f", (to - from) / 1_000_000_000.0);
    }

    private static String dash(String value) {
        return value == null || value.isEmpty() ? "-" : value;
    }

    private static String quote(String value) {
        return "\"" + dash(value) + "\"";
    }
}
