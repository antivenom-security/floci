package io.github.hectorvent.floci.services.cloudtrail.record;

import io.github.hectorvent.floci.core.common.RequestHost;
import io.quarkus.runtime.annotations.RegisterForReflection;
import io.vertx.core.http.HttpServerRequest;

import javax.net.ssl.SSLSession;

/**
 * A CloudTrail record's {@code tlsDetails}: the TLS version and cipher suite the client
 * negotiated, the cipher in OpenSSL's naming as CloudTrail records it, and the host the client
 * addressed, from {@code Host} or HTTP/2's {@code :authority}. A plain-HTTP request has none.
 */
@RegisterForReflection
public record TlsDetails(String tlsVersion, String cipherSuite, String clientProvidedHostHeader) {

    /** The TLS details of {@code request}'s connection, or null when it is not TLS. */
    public static TlsDetails of(HttpServerRequest request) {
        if (request == null || !request.isSSL()) {
            return null;
        }
        SSLSession session = request.sslSession();
        if (session == null) {
            return null;
        }
        return new TlsDetails(session.getProtocol(), openSslName(session.getCipherSuite()), RequestHost.of(request));
    }

    /**
     * The OpenSSL name of a JSSE (IANA) cipher suite. TLS 1.3 suites are named alike in both; a
     * TLS 1.2 suite such as {@code TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256} is
     * {@code ECDHE-RSA-AES128-GCM-SHA256}, a CBC suite drops its mode, and plain RSA key exchange is
     * unnamed: {@code TLS_RSA_WITH_AES_128_CBC_SHA} is {@code AES128-SHA}.
     */
    static String openSslName(String iana) {
        if (iana == null || !iana.contains("_WITH_")) {
            return iana;
        }
        String name = iana.startsWith("TLS_") ? iana.substring(4) : iana;
        if (name.startsWith("RSA_WITH_")) {
            name = name.substring("RSA_WITH_".length());
        }
        name = name.replace("_WITH_", "_")
                .replace("_CBC", "")
                .replace("AES_128", "AES128")
                .replace("AES_256", "AES256")
                .replace("CHACHA20_POLY1305_SHA256", "CHACHA20_POLY1305");
        return name.replace('_', '-');
    }
}
