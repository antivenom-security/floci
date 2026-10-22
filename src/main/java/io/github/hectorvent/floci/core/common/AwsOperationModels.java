package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The AWS service models CloudTrail records are built from, vendored as
 * {@code aws/cloudtrail-operations.json} by {@code tools/aws/regen_cloudtrail_operations.py}.
 *
 * <p>The file holds every operation and input/output shape of each model Floci serves, a few
 * megabytes in all, so only the models' headers are read up front. A model's operations and shapes
 * are read the first time a request names it, and kept.
 */
public final class AwsOperationModels {

    static final String RESOURCE_NAME = "aws/cloudtrail-operations.json";

    /** A model's header: the credential scope it signs for, its event source, protocol and target prefix. */
    public record ModelInfo(String name, String signingName, String eventSource, String protocol,
                            String targetPrefix) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final List<ModelInfo> INDEX = VendoredResources.read(RESOURCE_NAME,
            "CloudTrail operation models", AwsOperationModels::index);

    private static final Map<String, JsonNode> MODELS = new ConcurrentHashMap<>();

    private AwsOperationModels() {
    }

    public static List<ModelInfo> models() {
        return INDEX;
    }

    /** The model {@code name}: its {@code operations} and {@code shapes}. */
    public static JsonNode model(String name) {
        return MODELS.computeIfAbsent(name, key -> VendoredResources.read(RESOURCE_NAME,
                "CloudTrail operation models", in -> load(in, key)));
    }

    /** The first model with {@code eventSource} that defines the operation {@code name}, or null. */
    public static String modelOf(String eventSource, String name) {
        for (ModelInfo info : INDEX) {
            if (info.eventSource().equals(eventSource) && model(info.name()).path("operations").has(name)) {
                return info.name();
            }
        }
        return null;
    }

    static List<ModelInfo> index(InputStream in) throws IOException {
        List<ModelInfo> index = new ArrayList<>();
        try (JsonParser parser = MAPPER.createParser(in)) {
            toModels(parser);
            while (parser.nextToken() == JsonToken.FIELD_NAME) {
                String name = parser.currentName();
                parser.nextToken();
                String signingName = null;
                String eventSource = null;
                String protocol = null;
                String targetPrefix = null;
                while (parser.nextToken() == JsonToken.FIELD_NAME) {
                    String field = parser.currentName();
                    parser.nextToken();
                    switch (field) {
                        case "signingName" -> signingName = parser.getText();
                        case "eventSource" -> eventSource = parser.getText();
                        case "protocol" -> protocol = parser.getText();
                        case "targetPrefix" -> targetPrefix = parser.getText();
                        default -> parser.skipChildren();
                    }
                }
                index.add(new ModelInfo(name, signingName, eventSource, protocol, targetPrefix));
            }
        }
        if (index.isEmpty()) {
            throw new IllegalStateException(RESOURCE_NAME + " carries no models");
        }
        return List.copyOf(index);
    }

    private static JsonNode load(InputStream in, String name) throws IOException {
        try (JsonParser parser = MAPPER.createParser(in)) {
            toModels(parser);
            while (parser.nextToken() == JsonToken.FIELD_NAME) {
                String current = parser.currentName();
                parser.nextToken();
                if (current.equals(name)) {
                    return MAPPER.readTree(parser);
                }
                parser.skipChildren();
            }
        }
        throw new IllegalStateException(RESOURCE_NAME + " has no model " + name);
    }

    private static void toModels(JsonParser parser) throws IOException {
        parser.nextToken();
        while (parser.nextToken() == JsonToken.FIELD_NAME) {
            String field = parser.currentName();
            parser.nextToken();
            if ("models".equals(field)) {
                return;
            }
            parser.skipChildren();
        }
        throw new IllegalStateException(RESOURCE_NAME + " has no models");
    }
}
