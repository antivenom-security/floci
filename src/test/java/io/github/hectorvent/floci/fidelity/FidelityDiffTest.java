package io.github.hectorvent.floci.fidelity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailLogWriter;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@QuarkusTest
@EnabledIfEnvironmentVariable(named = "FLOCI_FIDELITY_SAMPLES", matches = ".+")
class FidelityDiffTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern KEY = Pattern.compile("<Key>([^<]+)</Key>");

    @Inject
    CloudTrailLogWriter writer;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void writesFidelityReportAgainstProductionShapeCatalog() throws Exception {
        JsonNode production = MAPPER.readTree(
                Path.of(System.getenv("FLOCI_FIDELITY_SAMPLES"), "shape-catalog.json").toFile());
        assertEquals(1, production.path("schemaVersion").asInt(), "unsupported shape-catalog schemaVersion");

        List<JsonNode> records = produceS3DataEvents();
        assertFalse(records.isEmpty(), "Floci delivered no CloudTrail records");

        Path report = Path.of("target", "fidelity-report.md");
        Files.createDirectories(report.getParent());
        Files.writeString(report, ShapeCatalog.report(production, ShapeCatalog.cloudtrail(records)));
    }

    private List<JsonNode> produceS3DataEvents() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String source = "fidelity-source-" + suffix;
        String logs = "fidelity-logs-" + suffix;
        String trail = "fidelity-" + suffix;
        given().put("/" + source).then().statusCode(200);
        given().put("/" + logs).then().statusCode(200);
        invokeCloudTrail("CreateTrail", "{\"Name\":\"" + trail + "\",\"S3BucketName\":\"" + logs + "\"}");
        invokeCloudTrail("PutEventSelectors", "{\"TrailName\":\"" + trail + "\",\"EventSelectors\":[{"
                + "\"ReadWriteType\":\"All\",\"IncludeManagementEvents\":false,"
                + "\"DataResources\":[{\"Type\":\"AWS::S3::Object\",\"Values\":[\"arn:aws:s3:::" + source + "/\"]}]}]}");
        invokeCloudTrail("StartLogging", "{\"Name\":\"" + trail + "\"}");

        given().body("hello").put("/" + source + "/k.txt").then().statusCode(200);
        given().get("/" + source + "/k.txt").then().statusCode(200);
        given().head("/" + source + "/k.txt").then().statusCode(200);
        given().get("/" + source + "/missing.txt").then().statusCode(404);
        given().delete("/" + source + "/k.txt").then().statusCode(204);
        writer.flushNow();

        List<JsonNode> records = new ArrayList<>();
        Matcher keys = KEY.matcher(given().get("/" + logs + "?list-type=2").then().statusCode(200).extract().asString());
        while (keys.find()) {
            byte[] gz = given().get("/" + logs + "/" + keys.group(1)).then().statusCode(200).extract().asByteArray();
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(gz))) {
                MAPPER.readTree(in).path("Records").forEach(records::add);
            }
        }
        return records;
    }

    private static void invokeCloudTrail(String action, String body) {
        given().header("X-Amz-Target", "CloudTrail_20131101." + action)
                .contentType("application/x-amz-json-1.1")
                .body(body)
                .post("/")
                .then().statusCode(200);
    }
}
