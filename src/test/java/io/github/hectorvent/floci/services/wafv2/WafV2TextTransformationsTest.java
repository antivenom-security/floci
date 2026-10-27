package io.github.hectorvent.floci.services.wafv2;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WafV2TextTransformationsTest {

    @Test
    void transformsAsAwsDocumentsThem() {
        assertEquals("select * from", WafV2TextTransformations.apply("LOWERCASE", "SELECT * FROM"));
        assertEquals("' or 1=1 ", WafV2TextTransformations.apply("URL_DECODE", "%27+or+1%3D1%20"));
        assertEquals("100%zz", WafV2TextTransformations.apply("URL_DECODE", "100%zz"));
        assertEquals("<script>'\"", WafV2TextTransformations.apply("HTML_ENTITY_DECODE", "&LT;script&#x3e;&apos;&#34;"));
        assertEquals("a b c", WafV2TextTransformations.apply("COMPRESS_WHITE_SPACE", "a \t\n b\u00A0c"));
        assertEquals("abc", WafV2TextTransformations.apply("REMOVE_WHITESPACE", " a\tb\nc "));
        assertEquals("x", WafV2TextTransformations.apply("TRIM", " \tx\r\n"));
        assertEquals("/b/c/", WafV2TextTransformations.apply("NORMALIZE_PATH", "/a/..//./b/c/"));
        assertEquals("/a/c", WafV2TextTransformations.apply("NORMALIZE_PATH_WIN", "\\a\\b\\..\\c"));
        assertEquals("cmd/c dir", WafV2TextTransformations.apply("CMD_LINE", "C^M\"D  /c;   DIR"));
        assertEquals("hello", WafV2TextTransformations.apply("BASE64_DECODE", "aGVsbG8="));
        assertEquals("AB", WafV2TextTransformations.apply("HEX_DECODE", "4142"));
        assertEquals("5d41402abc4b2a76b9719d911017c592", HexFormat.of().formatHex(
                WafV2TextTransformations.apply("MD5", "hello").getBytes(StandardCharsets.ISO_8859_1)));
        assertEquals("a  b", WafV2TextTransformations.apply("REPLACE_COMMENTS", "a/* x */ b"));
        assertNull(WafV2TextTransformations.apply("JS_DECODE", "x"));
    }

    @Test
    void containsWordNeedsWordBoundaries() {
        assertTrue(WafV2AlbInspector.byteMatch("/my-admin/x", "admin", "CONTAINS_WORD"));
        assertTrue(WafV2AlbInspector.byteMatch("admin", "admin", "CONTAINS_WORD"));
        assertFalse(WafV2AlbInspector.byteMatch("/administrator", "admin", "CONTAINS_WORD"));
        assertFalse(WafV2AlbInspector.byteMatch("/x", "", "CONTAINS_WORD"));
    }

    @Test
    void s3KeyFollowsTheDocumentedLayout() {
        WafV2LogWriter.S3File file = new WafV2LogWriter.S3File("aws-waf-logs-x", "edge", "11111111111", "us-east-1",
                "TEST-WEBACL", Instant.parse("2021-10-28T19:50:00Z"));
        assertEquals("edge/AWSLogs/11111111111/WAFLogs/us-east-1/TEST-WEBACL/2021/10/28/19/50/"
                + "11111111111_waflogs_us-east-1_TEST-WEBACL_20211028T1950Z_e0ca43b5.log.gz",
                WafV2LogWriter.s3Key(file, "e0ca43b5"));
    }
}
