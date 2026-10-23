package io.github.hectorvent.floci.services.cloudtrail.record;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsOperationModels;
import io.github.hectorvent.floci.core.common.XmlParser;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WireParametersTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private WireParameters wire(String model) {
        return new WireParameters(mapper, AwsOperationModels.model(model).path("shapes"));
    }

    @Test
    void ec2FormListsAreReadByLocationName() {
        JsonNode input = wire("ec2").fromForm("StartInstancesRequest",
                Map.of("Action", "StartInstances", "InstanceId.1", "i-1", "InstanceId.2", "i-2"), true);
        assertEquals("{\"InstanceIds\":[\"i-1\",\"i-2\"]}", input.toString());
    }

    @Test
    void queryFormStructureListsAreReadFromMemberEntries() {
        JsonNode input = wire("iam").fromForm("CreateUserRequest", Map.of("UserName", "bob",
                "Tags.member.1.Key", "team", "Tags.member.1.Value", "red"), false);
        assertEquals("bob", input.path("UserName").asText());
        assertEquals("red", input.path("Tags").path(0).path("Value").asText());
    }

    @Test
    void restLabelsAndQueryParametersMapToMembers() {
        JsonNode input = wire("lambda").fromRest("GetFunctionRequest", "/2015-03-31/functions/{FunctionName}",
                "/2015-03-31/functions/my%3Afn", Map.of("Qualifier", List.of("1")), null);
        assertEquals("{\"FunctionName\":\"my:fn\",\"Qualifier\":\"1\"}", input.toString());
    }

    @Test
    void ec2XmlResponseIsReadIntoMembers() {
        String xml = "<StartInstancesResponse><requestId>r</requestId><instancesSet><item>"
                + "<instanceId>i-1</instanceId><currentState><code>0</code><name>pending</name></currentState>"
                + "</item></instancesSet></StartInstancesResponse>";
        JsonNode output = wire("ec2").fromXml("StartInstancesResult", XmlParser.parseDocumentElementTree(xml));
        assertEquals("i-1", output.path("StartingInstances").path(0).path("InstanceId").asText());
        assertEquals("pending", output.path("StartingInstances").path(0).path("CurrentState").path("Name").asText());
    }
}
