package io.github.hectorvent.floci.services.elbv2;

import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpVersion;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class ElbV2AccessLogEntryTest {

    private static final String LB_ARN =
            "arn:aws:elasticloadbalancing:us-east-2:123456789012:loadbalancer/app/my-loadbalancer/50dc6c495c0c9188";

    @Test
    void rendersTheDocumentedFieldsInOrder() {
        ElbV2AccessLogEntry entry = new ElbV2AccessLogEntry(LB_ARN, "us-east-2",
                Instant.parse("2018-07-02T22:22:48.364Z"), 0);
        entry.type = "http";
        entry.client = "192.168.131.39:2817";
        entry.nodeIp = "10.0.0.5";
        entry.requestLine = ElbV2AccessLogEntry.requestLine(HttpMethod.GET, false, "www.example.com", 80, "/",
                HttpVersion.HTTP_1_1);
        entry.userAgent("curl/7.46.0");
        entry.traceId = "Root=1-58337262-36d228ad5d99923122bbe354";
        entry.connTraceId = "TID_1234abcd5678ef90";
        entry.matchedRulePriority = "0";
        entry.actions.add("redirect");
        entry.redirectUrl = "https://www.example.com:443/";
        entry.complete(Instant.parse("2018-07-02T22:23:00.186641Z"), 301, 34, 366);
        assertFalse(entry.complete(Instant.now(), 500, 0, 0));

        assertEquals("http 2018-07-02T22:23:00.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 - "
                + "-1 -1 -1 301 - 34 366 \"GET http://www.example.com:80/ HTTP/1.1\" \"curl/7.46.0\" - - - "
                + "\"Root=1-58337262-36d228ad5d99923122bbe354\" \"-\" \"-\" 0 2018-07-02T22:22:48.364000Z "
                + "\"redirect\" \"https://www.example.com:443/\" \"-\" \"-\" \"-\" \"-\" \"-\" TID_1234abcd5678ef90 "
                + "\"-\" \"-\" \"-\" 10.0.0.5 - -", entry.render());
    }

    @Test
    void classifiesWhatReachesTheDataPlane() {
        assertNull(ElbV2AccessLogEntry.classify(HttpMethod.GET, MultiMap.caseInsensitiveMultiMap().add("Host", "a")));
        assertArrayEquals(new String[] {"Acceptable", "GetHeadZeroContentLength"}, ElbV2AccessLogEntry.classify(
                HttpMethod.GET, MultiMap.caseInsensitiveMultiMap().add("Content-Length", "0")));
        assertArrayEquals(new String[] {"Ambiguous", "UndefinedContentLengthSemantics"},
                ElbV2AccessLogEntry.classify(HttpMethod.HEAD, MultiMap.caseInsensitiveMultiMap()
                        .add("X-Name", "café").add("Content-Length", "5")));
        assertArrayEquals(new String[] {"Acceptable", "NonCompliantHeader"}, ElbV2AccessLogEntry.classify(
                HttpMethod.POST, MultiMap.caseInsensitiveMultiMap().add("X-Name", "café")));
    }

    @Test
    void namesFilesAsTheAccessLogDocumentationDoes() {
        ElbV2AccessLogWriter.LogFile file = new ElbV2AccessLogWriter.LogFile("amzn-s3-demo-logging-bucket",
                "logging-prefix", "arn:aws:elasticloadbalancing:us-east-2:123456789012:loadbalancer/app/"
                + "my-loadbalancer/1234567890abcdef", "us-east-2", "172.160.001.192",
                Instant.parse("2022-02-15T23:40:00Z"));
        assertEquals("logging-prefix/AWSLogs/123456789012/elasticloadbalancing/us-east-2/2022/05/01/"
                        + "123456789012_elasticloadbalancing_us-east-2_app.my-loadbalancer.1234567890abcdef_"
                        + "20220215T2340Z_172.160.001.192_20sg8hgm.log.gz",
                ElbV2AccessLogWriter.s3Key(file, Instant.parse("2022-05-01T00:00:00Z"), "20sg8hgm"));
    }
}
