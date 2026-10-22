package io.github.hectorvent.floci.fidelity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ShapeCatalogTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void entryRecordsEveryNodeWithPresenceTypesAndClasses() throws Exception {
        JsonNode first = MAPPER.readTree("""
                {"eventSource":"sts.amazonaws.com","eventName":"AssumeRole",
                 "eventTime":"2026-10-22T10:00:00Z","sourceIPAddress":"10.1.2.3",
                 "resources":[{"ARN":"arn:aws:iam::111122223333:role/r","accountId":"111122223333"}]}
                """);
        JsonNode second = MAPPER.readTree("""
                {"eventSource":"sts.amazonaws.com","eventName":"AssumeRole",
                 "eventTime":"2026-10-22T10:00:01.123Z","sourceIPAddress":"2001:db8::1",
                 "errorCode":null}
                """);

        ObjectNode catalog = ShapeCatalog.cloudtrail(List.of(first, second));

        JsonNode expected = MAPPER.readTree("""
                {"sts.amazonaws.com AssumeRole":{
                  "samples":2,
                  "keyOrder":["eventSource","eventName","eventTime","sourceIPAddress","resources"],
                  "fields":{
                    "errorCode":{"presence":0.5,"types":["null"],"valueClasses":["null"]},
                    "eventName":{"presence":1.0,"types":["string"],"valueClasses":["string"]},
                    "eventSource":{"presence":1.0,"types":["string"],"valueClasses":["string"]},
                    "eventTime":{"presence":1.0,"types":["string"],"valueClasses":["iso8601"]},
                    "resources":{"presence":0.5,"types":["array"],"valueClasses":["array"]},
                    "resources[]":{"presence":0.5,"types":["object"],"valueClasses":["object"]},
                    "resources[].ARN":{"presence":0.5,"types":["string"],"valueClasses":["arn"]},
                    "resources[].accountId":{"presence":0.5,"types":["string"],"valueClasses":["account-id"]},
                    "sourceIPAddress":{"presence":1.0,"types":["string"],"valueClasses":["ipv4","ipv6"]}
                  }}}
                """);
        assertEquals(expected, catalog);
    }

    @Test
    void valueClassRecognisesAccessKeysAndRejectsLookalikes() {
        assertEquals("access-key", ShapeCatalog.valueClass(MAPPER.getNodeFactory().textNode("ASIAEXAMPLEEXAMPLE12")));
        assertEquals("string", ShapeCatalog.valueClass(MAPPER.getNodeFactory().textNode("01.2.3.4")));
        assertEquals("string", ShapeCatalog.valueClass(MAPPER.getNodeFactory().textNode("a:b")));
        assertEquals("string", ShapeCatalog.valueClass(MAPPER.getNodeFactory().textNode("1.2.3.4\n")));
        assertEquals("number", ShapeCatalog.valueClass(MAPPER.getNodeFactory().numberNode(5)));
    }

    @Test
    void reportListsDeviationsAndUnproducedEvents() throws Exception {
        JsonNode production = MAPPER.readTree("""
                {"schemaVersion":1,"cloudtrail":{
                  "s3.amazonaws.com GetObject":{"samples":1,"keyOrder":["a","b"],"fields":{
                    "a":{"presence":1.0,"types":["string"],"valueClasses":["string"]},
                    "b":{"presence":1.0,"types":["string"],"valueClasses":["arn"]}}},
                  "iam.amazonaws.com CreateUser":{"samples":1,"keyOrder":["a"],"fields":{}}}}
                """);
        ObjectNode floci = ShapeCatalog.cloudtrail(List.of(MAPPER.readTree("""
                {"eventSource":"s3.amazonaws.com","eventName":"GetObject"}
                """)));

        String report = ShapeCatalog.report(production, floci);

        assertThat(report, containsString("## s3.amazonaws.com GetObject"));
        assertThat(report, containsString("`a`: missing in Floci"));
        assertThat(report, containsString("`eventSource`: only in Floci"));
        assertThat(report, containsString("key order: production"));
        assertThat(report, containsString("- iam.amazonaws.com CreateUser"));
        assertThat(List.of(report.split("\n")), hasItem("Compared 1 event types, 5 deviations, 1 not produced."));
    }
}
