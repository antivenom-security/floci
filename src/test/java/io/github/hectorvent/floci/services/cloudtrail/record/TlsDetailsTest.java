package io.github.hectorvent.floci.services.cloudtrail.record;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.HostAndPort;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSession;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TlsDetailsTest {

    @Test
    void plainHttpHasNoTlsDetails() {
        HttpServerRequest request = mock(HttpServerRequest.class);
        when(request.isSSL()).thenReturn(false);

        assertNull(TlsDetails.of(request));
        assertNull(TlsDetails.of(null));
    }

    @Test
    void tlsReportsTheNegotiatedProtocolCipherAndHost() {
        assertEquals(new TlsDetails("TLSv1.3", "TLS_AES_128_GCM_SHA256", "s3.us-east-1.amazonaws.com"),
                TlsDetails.of(tls("TLSv1.3", "TLS_AES_128_GCM_SHA256", "s3.us-east-1.amazonaws.com")));
        assertEquals(new TlsDetails("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", "sqs.us-east-1.amazonaws.com"),
                TlsDetails.of(tls("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "sqs.us-east-1.amazonaws.com")));
    }

    @Test
    void ianaCipherSuitesTakeTheirOpenSslNames() {
        assertEquals("ECDHE-ECDSA-AES256-GCM-SHA384",
                TlsDetails.openSslName("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"));
        assertEquals("ECDHE-RSA-CHACHA20-POLY1305",
                TlsDetails.openSslName("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));
        assertEquals("TLS_AES_256_GCM_SHA384", TlsDetails.openSslName("TLS_AES_256_GCM_SHA384"));
        assertEquals("ECDHE-RSA-AES128-SHA", TlsDetails.openSslName("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"));
        assertEquals("ECDHE-RSA-AES256-SHA384", TlsDetails.openSslName("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"));
        assertEquals("AES128-GCM-SHA256", TlsDetails.openSslName("TLS_RSA_WITH_AES_128_GCM_SHA256"));
        assertEquals("AES256-SHA", TlsDetails.openSslName("TLS_RSA_WITH_AES_256_CBC_SHA"));
    }

    @Test
    void http2TakesTheHostFromItsAuthority() {
        HttpServerRequest request = tls("TLSv1.3", "TLS_AES_128_GCM_SHA256", null);
        when(request.authority()).thenReturn(HostAndPort.create("sqs.us-east-1.amazonaws.com", 4566));

        assertEquals("sqs.us-east-1.amazonaws.com:4566", TlsDetails.of(request).clientProvidedHostHeader());
    }

    private static HttpServerRequest tls(String protocol, String cipher, String host) {
        SSLSession session = mock(SSLSession.class);
        when(session.getProtocol()).thenReturn(protocol);
        when(session.getCipherSuite()).thenReturn(cipher);
        HttpServerRequest request = mock(HttpServerRequest.class);
        when(request.isSSL()).thenReturn(true);
        when(request.sslSession()).thenReturn(session);
        when(request.getHeader("Host")).thenReturn(host);
        return request;
    }
}
