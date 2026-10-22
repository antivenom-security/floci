package io.github.hectorvent.floci.services.cloudtrail.record;

import io.quarkus.runtime.annotations.RegisterForReflection;
import io.vertx.core.http.HttpServerRequest;

import javax.net.ssl.SSLSession;

/**
 * A CloudTrail record's {@code tlsDetails}: the TLS version and cipher suite the client
 * negotiated, the cipher in OpenSSL's naming as CloudTrail records it, and the {@code Host} header
 * the client sent. A plain-HTTP request has none.
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
        return new TlsDetails(session.getProtocol(), openSslName(session.getCipherSuite()), request.getHeader("Host"));
    }

    /**
     * The OpenSSL name of a JSSE (IANA) cipher suite. TLS 1.3 suites are named alike in both; a
     * TLS 1.2 suite such as {@code TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256} is
     * {@code ECDHE-RSA-AES128-GCM-SHA256}.
     */
    static String openSslName(String iana) {
        if (iana == null || !iana.contains("_WITH_")) {
            return iana;
        }
        String name = iana.startsWith("TLS_") ? iana.substring(4) : iana;
        name = name.replace("_WITH_", "_")
                .replace("AES_128", "AES128")
                .replace("AES_256", "AES256")
                .replace("CHACHA20_POLY1305_SHA256", "CHACHA20_POLY1305");
        return name.replace('_', '-');
    }
}
