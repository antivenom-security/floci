package io.github.hectorvent.floci.services.cloudtrail.record;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsOperationModels;
import io.github.hectorvent.floci.core.common.OperationResolver;
import io.github.hectorvent.floci.core.common.VendoredResources;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Builds CloudTrail records ({@code eventVersion} 1.11) in the key order of AWS's examples, applying
 * CloudTrail's rules: read-only classification, management or data event, {@code responseElements}
 * null for read-only calls and errors, {@code resources} and {@code apiVersion} from the vendored
 * tables, and the size limits of the CloudTrail record contents reference.
 *
 * <p>{@link #parameters} turns an operation's input or output, keyed by model member names, into
 * CloudTrail's form: first letter lowercased ({@code locationName} for Query and EC2), sensitive
 * members hidden, blobs left out, EC2 lists as {@code {"items": [...]}} under a {@code ...Set} name,
 * and output timestamps in the service's format.
 */
@ApplicationScoped
public class CloudTrailRecordBuilder {

    public static final String EVENT_VERSION = "1.11";
    public static final String CONSOLE_SIGN_IN = "AwsConsoleSignIn";
    public static final String HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS";
    static final int MAX_PARAMETERS_BYTES = 100 * 1024;
    static final int MAX_FIELD_BYTES = 1024;

    private static final Pattern READ_ONLY_PREFIX =
            Pattern.compile("^(Get|List|Describe|Head|BatchGet|Lookup|Search|Check)[A-Z0-9].*");

    private static final ObjectMapper TABLE_MAPPER = new ObjectMapper();
    private static final JsonNode DATA_EVENTS = table("aws/cloudtrail-data-events.json");
    private static final JsonNode READ_ONLY_TABLE = table("aws/cloudtrail-readonly-overrides.json");
    private static final JsonNode READ_ONLY_OVERRIDES = READ_ONLY_TABLE.path("overrides");
    private static final JsonNode RESOURCES = table("aws/cloudtrail-resources.json");
    private static final JsonNode TIME_FORMATS = table("aws/cloudtrail-response-time-formats.json").path("formats");
    private static final JsonNode SENSITIVE_OVERRIDES = table("aws/cloudtrail-sensitive-overrides.json")
            .path("members");
    private static final Map<String, DateTimeFormatter> FORMATTERS = new ConcurrentHashMap<>();

    private final ObjectMapper mapper;

    @Inject
    public CloudTrailRecordBuilder(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public ObjectNode build(CloudTrailEvent event) {
        boolean readOnly = isReadOnly(event.eventSource(), event.eventName());
        boolean data = isDataEvent(event.eventSource(), event.eventName());
        ObjectNode record = mapper.createObjectNode();
        record.put("eventVersion", EVENT_VERSION);
        record.set("userIdentity", event.userIdentity());
        Instant time = event.eventTime() == null ? Instant.now() : event.eventTime();
        record.put("eventTime", DateTimeFormatter.ISO_INSTANT.format(time.truncatedTo(ChronoUnit.SECONDS)));
        record.put("eventSource", event.eventSource());
        record.put("eventName", event.eventName());
        record.put("awsRegion", event.awsRegion());
        record.put("sourceIPAddress", event.sourceIPAddress());
        record.put("userAgent", truncate(event.userAgent() == null ? "" : event.userAgent()));
        if (event.errorCode() != null) {
            record.put("errorCode", truncate(event.errorCode()));
        }
        if (event.errorMessage() != null) {
            record.put("errorMessage", truncate(event.errorMessage()));
        }
        putParameters(record, "requestParameters", event.requestParameters());
        putParameters(record, "responseElements",
                (readOnly && !keepsResponse(event.eventSource(), event.eventName())) || event.errorCode() != null
                        ? null : event.responseElements());
        if (event.additionalEventData() != null) {
            record.set("additionalEventData", event.additionalEventData());
        }
        String eventType = event.eventType() == null ? "AwsApiCall" : event.eventType();
        // AWS's console sign-in records carry no requestID.
        if (!CONSOLE_SIGN_IN.equals(eventType)) {
            record.put("requestID", truncate(event.requestId() == null ? UUID.randomUUID().toString()
                    : event.requestId()));
        }
        record.put("eventID", UUID.randomUUID().toString());
        record.put("readOnly", readOnly);
        ArrayNode resources = event.resources() != null ? event.resources() : resources(event);
        if (resources != null && !resources.isEmpty()) {
            record.set("resources", resources);
        }
        record.put("eventType", eventType);
        JsonNode apiVersion = RESOURCES.path("apiVersions").get(event.eventSource());
        if (apiVersion != null) {
            record.put("apiVersion", apiVersion.asText());
        }
        record.put("managementEvent", !data);
        record.put("recipientAccountId", event.recipientAccountId());
        record.put("eventCategory", data ? "Data" : "Management");
        if (event.tlsDetails() != null) {
            ObjectNode tls = record.putObject("tlsDetails");
            tls.put("tlsVersion", event.tlsDetails().tlsVersion());
            tls.put("cipherSuite", event.tlsDetails().cipherSuite());
            if (event.tlsDetails().clientProvidedHostHeader() != null) {
                tls.put("clientProvidedHostHeader", event.tlsDetails().clientProvidedHostHeader());
            }
        }
        return record;
    }

    /**
     * {@code value}, the input ({@code output} false) or output of the resolved {@code operation} keyed by
     * model member names, in CloudTrail's form, or null when the operation is not modelled.
     */
    public JsonNode parameters(OperationResolver.Operation operation, boolean output, JsonNode value) {
        JsonNode modelNode = AwsOperationModels.model(operation.model());
        JsonNode op = modelNode.path("operations").get(operation.name());
        if (op == null || value == null || value.isNull()) {
            return null;
        }
        String shape = op.path(output ? "output" : "input").asText(null);
        String protocol = AwsOperationModels.info(operation.model()).protocol();
        Rendering rendering = new Rendering(modelNode.path("shapes"), operation.eventSource(),
                "query".equals(protocol) || "ec2".equals(protocol), "ec2".equals(protocol), output);
        return render(rendering, shape, value);
    }

    /** Whether a read-only operation's record still carries responseElements, as STS AssumeRole's does. */
    public static boolean keepsResponse(String eventSource, String eventName) {
        return contains(READ_ONLY_TABLE.path("responseKept").path(eventSource), eventName);
    }

    public static boolean isReadOnly(String eventSource, String eventName) {
        JsonNode override = READ_ONLY_OVERRIDES.path(eventSource).get(eventName);
        if (override != null) {
            return override.asBoolean();
        }
        return eventName != null && READ_ONLY_PREFIX.matcher(eventName).matches();
    }

    public static boolean isDataEvent(String eventSource, String eventName) {
        return contains(DATA_EVENTS.path("dataEvents").path(eventSource), eventName);
    }

    /** Operations CloudTrail does not record at all, such as CloudWatch Logs PutLogEvents. */
    public static boolean isNotLogged(String eventSource, String eventName) {
        return contains(DATA_EVENTS.path("notLogged").path(eventSource), eventName);
    }

    private record Rendering(JsonNode shapes, String eventSource, boolean locationNames, boolean ec2Lists,
                             boolean output) {
    }

    private JsonNode render(Rendering rendering, String shapeName, JsonNode value) {
        JsonNode shape = shapeName == null || shapeName.isEmpty() ? null : rendering.shapes().get(shapeName);
        if (shape == null) {
            return value;
        }
        if (shape.has("list") && value.isArray()) {
            ArrayNode list = mapper.createArrayNode();
            value.forEach(element -> list.add(render(rendering, shape.path("list").asText(), element)));
            return list;
        }
        if (!shape.has("members") || !value.isObject()) {
            return value;
        }
        JsonNode members = shape.path("members");
        Set<String> sensitive = names(shape.path("sensitive"));
        sensitive.addAll(names(SENSITIVE_OVERRIDES.path(rendering.eventSource()).path(shapeName)));
        Set<String> blobs = names(shape.path("blobs"));
        Set<String> timestamps = names(shape.path("timestamps"));
        ObjectNode out = mapper.createObjectNode();
        value.properties().forEach(field -> {
            String member = field.getKey();
            if (blobs.contains(member)) {
                return;
            }
            String wireName = rendering.locationNames()
                    ? shape.path("locationNames").path(member).asText(member) : member;
            String target = members.path(member).asText("");
            JsonNode child = target.isEmpty() ? null : rendering.shapes().get(target);
            if (sensitive.contains(member) || (child != null && child.path("sensitive").asBoolean())) {
                out.put(lowerFirst(wireName), HIDDEN);
            } else if (rendering.ec2Lists() && child != null && child.has("list") && field.getValue().isArray()) {
                out.set(ec2SetName(wireName), ec2Items(rendering, child, wireName, field.getValue()));
            } else if (rendering.output() && timestamps.contains(member)) {
                out.set(lowerFirst(wireName), timestamp(rendering.eventSource(), field.getValue()));
            } else {
                out.set(lowerFirst(wireName), render(rendering, target, field.getValue()));
            }
        });
        return out;
    }

    private ObjectNode ec2Items(Rendering rendering, JsonNode listShape, String wireName, JsonNode values) {
        ObjectNode set = mapper.createObjectNode();
        if (values.isEmpty()) {
            return set;
        }
        ArrayNode items = set.putArray("items");
        String element = listShape.path("list").asText("");
        String itemName = lowerFirst(wireName);
        for (JsonNode value : values) {
            if (element.isEmpty()) {
                items.addObject().set(itemName, value);
            } else {
                items.add(render(rendering, element, value));
            }
        }
        return set;
    }

    /**
     * The {@code ...Set} name the EC2 API gives a list in CloudTrail: {@code InstanceId} is
     * {@code instancesSet}, {@code Filter} is {@code filterSet}.
     * shortcut: a naming rule, not a table; irregular names (RunInstances' groupSet) need samples to correct.
     */
    static String ec2SetName(String locationName) {
        String name = lowerFirst(locationName);
        if (name.endsWith("Set")) {
            return name;
        }
        if (name.endsWith("Id") && name.length() > 2) {
            return name.substring(0, name.length() - 2) + "sSet";
        }
        return name + "Set";
    }

    private JsonNode timestamp(String eventSource, JsonNode value) {
        Instant instant;
        try {
            if (value.isNumber()) {
                BigDecimal seconds = value.decimalValue();
                instant = Instant.ofEpochSecond(seconds.longValue(),
                        seconds.remainder(BigDecimal.ONE).movePointRight(9).longValue());
            } else if (value.isTextual()) {
                instant = Instant.parse(value.asText());
            } else {
                return value;
            }
        } catch (DateTimeParseException e) {
            return value;
        }
        JsonNode pattern = TIME_FORMATS.get(eventSource);
        if (pattern == null) {
            return mapper.getNodeFactory().textNode(
                    DateTimeFormatter.ISO_INSTANT.format(instant.truncatedTo(ChronoUnit.SECONDS)));
        }
        DateTimeFormatter formatter = FORMATTERS.computeIfAbsent(pattern.asText(),
                p -> DateTimeFormatter.ofPattern(p, Locale.US).withZone(ZoneOffset.UTC));
        return mapper.getNodeFactory().textNode(formatter.format(instant));
    }

    private ArrayNode resources(CloudTrailEvent event) {
        JsonNode entry = RESOURCES.path("resources").path(event.eventSource()).get(event.eventName());
        if (entry == null) {
            return null;
        }
        String member = entry.path("arnMember").asText();
        String arn = textAt(event.requestParameters(), member);
        if (arn == null) {
            arn = textAt(event.responseElements(), member);
        }
        if (arn == null || !AwsArnUtils.isArn(arn)) {
            return null;
        }
        ArrayNode resources = mapper.createArrayNode();
        ObjectNode resource = resources.addObject();
        resource.put("accountId", AwsArnUtils.parse(arn).accountId());
        resource.put("type", entry.path("type").asText());
        resource.put("ARN", arn);
        return resources;
    }

    private void putParameters(ObjectNode record, String field, JsonNode value) {
        if (value == null || value.isNull()) {
            record.putNull(field);
            return;
        }
        if (serializedBytes(value) > MAX_PARAMETERS_BYTES) {
            return;
        }
        record.set(field, value);
    }

    private long serializedBytes(JsonNode value) {
        try {
            return mapper.writeValueAsBytes(value).length;
        } catch (Exception e) {
            return value.toString().getBytes(StandardCharsets.UTF_8).length;
        }
    }

    private static String textAt(JsonNode node, String member) {
        if (node == null) {
            return null;
        }
        JsonNode value = node.get(member);
        return value == null || !value.isTextual() ? null : value.asText();
    }

    private static String truncate(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= MAX_FIELD_BYTES) {
            return value;
        }
        int end = MAX_FIELD_BYTES;
        while ((bytes[end] & 0xC0) == 0x80) {
            end--;
        }
        return new String(bytes, 0, end, StandardCharsets.UTF_8);
    }

    static String lowerFirst(String name) {
        return name.isEmpty() ? name : Character.toLowerCase(name.charAt(0)) + name.substring(1);
    }

    private static Set<String> names(JsonNode array) {
        Set<String> names = new HashSet<>();
        array.forEach(name -> names.add(name.asText()));
        return names;
    }

    private static boolean contains(JsonNode array, String value) {
        for (JsonNode element : array) {
            if (element.asText().equals(value)) {
                return true;
            }
        }
        return false;
    }

    private static JsonNode table(String resource) {
        return VendoredResources.read(resource, "CloudTrail table", TABLE_MAPPER::readTree);
    }
}
