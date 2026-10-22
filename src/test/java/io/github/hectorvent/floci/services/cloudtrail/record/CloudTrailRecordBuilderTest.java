package io.github.hectorvent.floci.services.cloudtrail.record;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.OperationResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CloudTrailRecordBuilderTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final CloudTrailRecordBuilder builder = new CloudTrailRecordBuilder(mapper);

    /**
     * Each fixture under {@code cloudtrail/fidelity/} is a record in the shape of AWS's documented
     * examples, with the operation's input and output as the service model names them. The built
     * record must match it field for field and in AWS's key order.
     */
    @ParameterizedTest
    @ValueSource(strings = {"ec2-start-instances", "iam-create-user", "sns-publish", "kms-decrypt"})
    void buildsTheDocumentedRecord(String fixture) throws IOException {
        JsonNode doc = load("/cloudtrail/fidelity/" + fixture + ".json");
        JsonNode event = doc.path("event");
        String source = event.path("eventSource").asText();
        String name = event.path("eventName").asText();
        OperationResolver.Operation operation = new OperationResolver.Operation(
                source.substring(0, source.indexOf('.')), source, name);

        ObjectNode record = builder.build(CloudTrailEvent.builder()
                .eventSource(source)
                .eventName(name)
                .awsRegion(event.path("awsRegion").asText())
                .eventTime(Instant.parse(event.path("eventTime").asText()))
                .userIdentity((ObjectNode) event.path("userIdentity"))
                .sourceIPAddress(event.path("sourceIPAddress").asText())
                .userAgent(event.path("userAgent").asText())
                .requestParameters(builder.parameters(operation, false, doc.path("input")))
                .responseElements(builder.parameters(operation, true, doc.path("output")))
                .requestId(event.path("requestID").asText())
                .tlsDetails(event.has("tlsDetails") ? mapper.treeToValue(event.path("tlsDetails"), TlsDetails.class)
                        : null)
                .recipientAccountId(event.path("recipientAccountId").asText())
                .build());

        assertTrue(record.path("eventID").asText().matches("[0-9a-f-]{36}"), record.toString());
        record.put("eventID", "<eventID>");
        assertEquals(mapper.writeValueAsString(doc.path("record")), mapper.writeValueAsString(record));
    }

    @Test
    void anErrorHasNoResponseElements() {
        ObjectNode record = builder.build(minimal("iam.amazonaws.com", "CreateUser")
                .errorCode("AccessDenied")
                .errorMessage("User is not authorized")
                .responseElements(mapper.createObjectNode().put("user", "x"))
                .build());

        assertEquals("AccessDenied", record.path("errorCode").asText());
        assertTrue(record.path("responseElements").isNull());
        assertTrue(record.has("responseElements"));
    }

    @Test
    void oversizedParametersAreOmittedAndLongFieldsTruncated() {
        String big = "x".repeat(CloudTrailRecordBuilder.MAX_PARAMETERS_BYTES + 1);
        ObjectNode record = builder.build(minimal("ssm.amazonaws.com", "PutParameter")
                .requestParameters(mapper.createObjectNode().put("value", big))
                .userAgent("\u00e9".repeat(2000))
                .errorCode("E".repeat(2000))
                .errorMessage("m".repeat(2000))
                .requestId("r".repeat(2000))
                .build());

        assertFalse(record.has("requestParameters"));
        assertEquals("\u00e9".repeat(512), record.path("userAgent").asText());
        assertEquals(1024, record.path("errorCode").asText().length());
        assertEquals(1024, record.path("errorMessage").asText().length());
        assertEquals(1024, record.path("requestID").asText().length());
    }

    @Test
    void plainHttpHasNoTlsDetailsAndLogsCarriesItsApiVersion() {
        ObjectNode record = builder.build(minimal("logs.amazonaws.com", "CreateLogGroup").build());

        assertFalse(record.has("tlsDetails"));
        assertEquals("20140328", record.path("apiVersion").asText());
    }

    @Test
    void readOnlyAndDataEventClassification() {
        assertTrue(CloudTrailRecordBuilder.isReadOnly("iam.amazonaws.com", "GetUser"));
        assertTrue(CloudTrailRecordBuilder.isReadOnly("cloudtrail.amazonaws.com", "LookupEvents"));
        assertFalse(CloudTrailRecordBuilder.isReadOnly("iam.amazonaws.com", "CreateUser"));
        assertFalse(CloudTrailRecordBuilder.isReadOnly("iam.amazonaws.com", "Getaway"));
        assertTrue(CloudTrailRecordBuilder.isReadOnly("kms.amazonaws.com", "Decrypt"));
        assertTrue(CloudTrailRecordBuilder.isReadOnly("secretsmanager.amazonaws.com", "GetSecretValue"));
        assertTrue(CloudTrailRecordBuilder.isDataEvent("sqs.amazonaws.com", "ReceiveMessage"));
        assertFalse(CloudTrailRecordBuilder.isDataEvent("sqs.amazonaws.com", "CreateQueue"));
        assertTrue(CloudTrailRecordBuilder.isNotLogged("logs.amazonaws.com", "PutLogEvents"));
    }

    @Test
    void ec2ListsTakeTheirSetNames() {
        assertEquals("instancesSet", CloudTrailRecordBuilder.ec2SetName("InstanceId"));
        assertEquals("filterSet", CloudTrailRecordBuilder.ec2SetName("Filter"));
        assertEquals("tagSet", CloudTrailRecordBuilder.ec2SetName("tagSet"));
    }

    @Test
    void ec2NestedListsRenderAsItems() {
        JsonNode input = mapper.createObjectNode().set("Filters", mapper.createArrayNode().add(
                mapper.createObjectNode().put("Name", "instance-state-name")
                        .set("Values", mapper.createArrayNode().add("running"))));

        JsonNode rendered = builder.parameters(
                new OperationResolver.Operation("ec2", "ec2.amazonaws.com", "DescribeInstances"), false, input);

        assertEquals("{\"filterSet\":{\"items\":[{\"name\":\"instance-state-name\","
                + "\"valueSet\":{\"items\":[{\"value\":\"running\"}]}}]}}", rendered.toString());
    }

    private CloudTrailEvent.Builder minimal(String source, String name) {
        return CloudTrailEvent.builder()
                .eventSource(source)
                .eventName(name)
                .awsRegion("us-east-1")
                .userIdentity(mapper.createObjectNode().put("type", "Root"))
                .sourceIPAddress("127.0.0.1")
                .recipientAccountId("111122223333");
    }

    private JsonNode load(String resource) throws IOException {
        try (InputStream in = getClass().getResourceAsStream(resource)) {
            return mapper.readTree(in);
        }
    }
}
