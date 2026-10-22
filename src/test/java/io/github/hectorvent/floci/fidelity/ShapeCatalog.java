package io.github.hectorvent.floci.fidelity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.Inet6Address;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

final class ShapeCatalog {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern ISO8601 = Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z");
    private static final Pattern ARN = Pattern.compile("^arn:[^:]+:");
    private static final String OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
    private static final Pattern IPV4 = Pattern.compile("(" + OCTET + "\\.){3}" + OCTET);
    private static final Pattern ACCOUNT_ID = Pattern.compile("\\d{12}");
    private static final Pattern ACCESS_KEY = Pattern.compile("(AKIA|ASIA)[A-Z0-9]{16}");

    private ShapeCatalog() {
    }

    static ObjectNode cloudtrail(List<JsonNode> records) {
        Map<String, List<JsonNode>> byKey = new TreeMap<>();
        for (JsonNode record : records) {
            String key = record.path("eventSource").asText() + " " + record.path("eventName").asText();
            byKey.computeIfAbsent(key, k -> new ArrayList<>()).add(record);
        }
        ObjectNode out = MAPPER.createObjectNode();
        byKey.forEach((key, samples) -> out.set(key, entry(samples)));
        return out;
    }

    static ObjectNode entry(List<JsonNode> samples) {
        Map<String, Integer> presence = new TreeMap<>();
        Map<String, Set<String>> types = new TreeMap<>();
        Map<String, Set<String>> classes = new TreeMap<>();
        Map<List<String>, Integer> orders = new LinkedHashMap<>();
        for (JsonNode sample : samples) {
            Set<String> seen = new TreeSet<>();
            List<String> order = new ArrayList<>();
            Iterator<Map.Entry<String, JsonNode>> fields = sample.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                order.add(field.getKey());
                visit(field.getValue(), field.getKey(), seen, types, classes);
            }
            seen.forEach(path -> presence.merge(path, 1, Integer::sum));
            orders.merge(order, 1, Integer::sum);
        }
        List<String> keyOrder = List.of();
        int best = 0;
        for (Map.Entry<List<String>, Integer> order : orders.entrySet()) {
            if (order.getValue() > best) {
                best = order.getValue();
                keyOrder = order.getKey();
            }
        }
        ObjectNode entry = MAPPER.createObjectNode();
        entry.put("samples", samples.size());
        keyOrder.forEach(entry.putArray("keyOrder")::add);
        ObjectNode fieldsNode = entry.putObject("fields");
        presence.forEach((path, count) -> {
            ObjectNode field = fieldsNode.putObject(path);
            field.put("presence", Math.round(count * 1000.0 / samples.size()) / 1000.0);
            types.get(path).forEach(field.putArray("types")::add);
            classes.get(path).forEach(field.putArray("valueClasses")::add);
        });
        return entry;
    }

    private static void visit(JsonNode node, String path, Set<String> seen,
                              Map<String, Set<String>> types, Map<String, Set<String>> classes) {
        seen.add(path);
        types.computeIfAbsent(path, p -> new TreeSet<>()).add(type(node));
        classes.computeIfAbsent(path, p -> new TreeSet<>()).add(valueClass(node));
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                visit(field.getValue(), path + "." + field.getKey(), seen, types, classes);
            }
        } else if (node.isArray()) {
            for (JsonNode element : node) {
                visit(element, path + "[]", seen, types, classes);
            }
        }
    }

    static String type(JsonNode node) {
        if (node.isObject()) {
            return "object";
        }
        if (node.isArray()) {
            return "array";
        }
        if (node.isTextual()) {
            return "string";
        }
        if (node.isNumber()) {
            return "number";
        }
        if (node.isBoolean()) {
            return "boolean";
        }
        return "null";
    }

    static String valueClass(JsonNode node) {
        if (!node.isTextual()) {
            return type(node);
        }
        String value = node.asText();
        if (ISO8601.matcher(value).matches()) {
            return "iso8601";
        }
        if (ARN.matcher(value).find()) {
            return "arn";
        }
        if (IPV4.matcher(value).matches()) {
            return "ipv4";
        }
        if (isIpv6(value)) {
            return "ipv6";
        }
        if (ACCOUNT_ID.matcher(value).matches()) {
            return "account-id";
        }
        if (ACCESS_KEY.matcher(value).matches()) {
            return "access-key";
        }
        return "string";
    }

    private static boolean isIpv6(String value) {
        if (!value.contains(":")) {
            return false;
        }
        try {
            Inet6Address.ofLiteral(value);
            return true;
        } catch (IllegalArgumentException expected) {
            return false;
        }
    }

    static List<String> diff(JsonNode production, JsonNode floci) {
        List<String> lines = new ArrayList<>();
        if (!production.path("keyOrder").equals(floci.path("keyOrder"))) {
            lines.add("key order: production `" + production.path("keyOrder") + "`, Floci `" + floci.path("keyOrder") + "`");
        }
        Set<String> paths = new TreeSet<>();
        production.path("fields").fieldNames().forEachRemaining(paths::add);
        floci.path("fields").fieldNames().forEachRemaining(paths::add);
        for (String path : paths) {
            JsonNode expected = production.path("fields").path(path);
            JsonNode actual = floci.path("fields").path(path);
            if (actual.isMissingNode()) {
                lines.add("`" + path + "`: missing in Floci (production presence " + expected.path("presence") + ")");
            } else if (expected.isMissingNode()) {
                lines.add("`" + path + "`: only in Floci");
            } else {
                compare(lines, path, "types", expected, actual);
                compare(lines, path, "valueClasses", expected, actual);
                boolean expectedAlways = expected.path("presence").asDouble() == 1.0;
                if (expectedAlways != (actual.path("presence").asDouble() == 1.0)) {
                    lines.add("`" + path + "`: presence production " + expected.path("presence")
                            + ", Floci " + actual.path("presence"));
                }
            }
        }
        return lines;
    }

    private static void compare(List<String> lines, String path, String attribute, JsonNode expected, JsonNode actual) {
        if (!expected.path(attribute).equals(actual.path(attribute))) {
            lines.add("`" + path + "`: " + attribute + " production " + expected.path(attribute)
                    + ", Floci " + actual.path(attribute));
        }
    }

    static String report(JsonNode productionCatalog, ObjectNode flociCloudtrail) {
        StringBuilder out = new StringBuilder("# Fidelity report\n\n");
        List<String> notProduced = new ArrayList<>();
        int deviations = 0;
        Iterator<Map.Entry<String, JsonNode>> entries = productionCatalog.path("cloudtrail").fields();
        while (entries.hasNext()) {
            Map.Entry<String, JsonNode> entry = entries.next();
            JsonNode floci = flociCloudtrail.get(entry.getKey());
            if (floci == null) {
                notProduced.add(entry.getKey());
                continue;
            }
            List<String> lines = diff(entry.getValue(), floci);
            deviations += lines.size();
            out.append("## ").append(entry.getKey()).append("\n\n");
            if (lines.isEmpty()) {
                out.append("No deviations.\n\n");
            } else {
                lines.forEach(line -> out.append("- ").append(line).append('\n'));
                out.append('\n');
            }
        }
        out.append("## Not produced by Floci yet\n\n");
        notProduced.forEach(key -> out.append("- ").append(key).append('\n'));
        out.append("\nCompared ").append(productionCatalog.path("cloudtrail").size() - notProduced.size())
                .append(" event types, ").append(deviations).append(" deviations, ")
                .append(notProduced.size()).append(" not produced.\n");
        return out.toString();
    }
}
