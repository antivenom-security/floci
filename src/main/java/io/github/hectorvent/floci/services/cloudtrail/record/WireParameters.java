package io.github.hectorvent.floci.services.cloudtrail.record;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.XmlParser.XmlElement;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads an operation's input or output off the wire into the shape
 * {@link CloudTrailRecordBuilder#parameters} takes: keyed by model member names, walked along the
 * vendored model shapes so only modelled members are kept.
 *
 * <p>shortcut: scalars read from forms, paths and XML stay strings, since the vendored shapes carry
 * no scalar types; REST headers and rest-xml bodies are not read, since the vendored shapes carry no
 * member locations. Upgrade when samples show a field that needs them.
 */
public final class WireParameters {

    private static final Pattern LABEL = Pattern.compile("\\{([^}]+?)\\+?}");

    private final ObjectMapper mapper;
    private final JsonNode shapes;

    public WireParameters(ObjectMapper mapper, JsonNode shapes) {
        this.mapper = mapper;
        this.shapes = shapes;
    }

    /** A Query ({@code ec2} false) or EC2 protocol form, such as {@code Tags.member.1.Key=k}. */
    public JsonNode fromForm(String shapeName, Map<String, String> form, boolean ec2) {
        return form(shapeName, form, "", ec2);
    }

    /** A REST request: the URI template's labels, the query string, and a JSON body when there is one. */
    public ObjectNode fromRest(String shapeName, String uriTemplate, String path,
                               Map<String, List<String>> query, JsonNode body) {
        ObjectNode out = body != null && body.isObject() ? body.deepCopy() : mapper.createObjectNode();
        JsonNode members = shapes.path(shapeName).path("members");
        List<String> labels = new ArrayList<>();
        Matcher label = LABEL.matcher(uriTemplate);
        StringBuilder regex = new StringBuilder("^");
        int last = 0;
        while (label.find()) {
            regex.append(Pattern.quote(uriTemplate.substring(last, label.start())))
                    .append(label.group().endsWith("+}") ? "(.+)" : "([^/]+)");
            labels.add(label.group(1));
            last = label.end();
        }
        regex.append(Pattern.quote(uriTemplate.substring(last))).append("/?$");
        Matcher values = Pattern.compile(regex.toString()).matcher(path);
        if (values.matches()) {
            for (int i = 0; i < labels.size(); i++) {
                String member = member(members, labels.get(i));
                if (member != null) {
                    out.put(member, URLDecoder.decode(values.group(i + 1), StandardCharsets.UTF_8));
                }
            }
        }
        query.forEach((name, list) -> {
            String member = member(members, name);
            if (member == null || list.isEmpty()) {
                return;
            }
            JsonNode target = shapes.get(members.path(member).asText(""));
            if (target != null && target.has("list")) {
                ArrayNode array = out.putArray(member);
                list.forEach(array::add);
            } else {
                out.put(member, list.getFirst());
            }
        });
        return out;
    }

    /** A Query or EC2 protocol XML response element, the {@code <OperationResult>} or the document element. */
    public JsonNode fromXml(String shapeName, XmlElement element) {
        JsonNode shape = shapeName.isEmpty() ? null : shapes.get(shapeName);
        if (shape == null) {
            return mapper.getNodeFactory().textNode(element.text());
        }
        if (shape.has("list")) {
            ArrayNode list = mapper.createArrayNode();
            element.children().forEach(child -> list.add(fromXml(shape.path("list").asText(), child)));
            return list;
        }
        if (shape.has("map")) {
            ObjectNode map = mapper.createObjectNode();
            for (XmlElement entry : element.children()) {
                XmlElement key = entry.child("key");
                XmlElement value = entry.child("value");
                if (key != null) {
                    map.put(key.text(), value == null ? null : value.text());
                }
            }
            return map;
        }
        ObjectNode out = mapper.createObjectNode();
        for (Map.Entry<String, JsonNode> member : shape.path("members").properties()) {
            String wire = shape.path("locationNames").path(member.getKey()).asText(member.getKey());
            XmlElement child = element.child(wire);
            if (child == null) {
                child = element.child(CloudTrailRecordBuilder.lowerFirst(wire));
            }
            if (child != null) {
                out.set(member.getKey(), fromXml(member.getValue().asText(), child));
            }
        }
        return out;
    }

    private JsonNode form(String shapeName, Map<String, String> form, String prefix, boolean ec2) {
        JsonNode shape = shapeName.isEmpty() ? null : shapes.get(shapeName);
        if (shape == null) {
            String value = form.get(prefix);
            return value == null ? null : mapper.getNodeFactory().textNode(value);
        }
        if (shape.has("list")) {
            String itemPrefix = ec2 ? prefix : prefix + "." + shape.path("locationName").asText("member");
            ArrayNode list = mapper.createArrayNode();
            for (int i = 1; present(form, itemPrefix + "." + i); i++) {
                JsonNode item = form(shape.path("list").asText(), form, itemPrefix + "." + i, ec2);
                if (item != null) {
                    list.add(item);
                }
            }
            return list.isEmpty() ? null : list;
        }
        if (shape.has("map")) {
            ObjectNode map = mapper.createObjectNode();
            for (int i = 1; form.containsKey(prefix + ".entry." + i + ".key"); i++) {
                map.put(form.get(prefix + ".entry." + i + ".key"), form.get(prefix + ".entry." + i + ".value"));
            }
            return map.isEmpty() ? null : map;
        }
        ObjectNode out = mapper.createObjectNode();
        for (Map.Entry<String, JsonNode> member : shape.path("members").properties()) {
            String wire = shape.path("locationNames").path(member.getKey()).asText(member.getKey());
            if (ec2) {
                wire = Character.toUpperCase(wire.charAt(0)) + wire.substring(1);
            }
            String childPrefix = prefix.isEmpty() ? wire : prefix + "." + wire;
            if (present(form, childPrefix)) {
                JsonNode value = form(member.getValue().asText(), form, childPrefix, ec2);
                if (value != null) {
                    out.set(member.getKey(), value);
                }
            }
        }
        return out.isEmpty() && !prefix.isEmpty() ? null : out;
    }

    private static boolean present(Map<String, String> form, String prefix) {
        if (form.containsKey(prefix)) {
            return true;
        }
        String nested = prefix + ".";
        for (String key : form.keySet()) {
            if (key.startsWith(nested)) {
                return true;
            }
        }
        return false;
    }

    private static String member(JsonNode members, String name) {
        for (Map.Entry<String, JsonNode> member : members.properties()) {
            if (member.getKey().equalsIgnoreCase(name)) {
                return member.getKey();
            }
        }
        return null;
    }
}
