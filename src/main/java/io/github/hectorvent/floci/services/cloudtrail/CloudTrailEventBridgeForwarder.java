package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RequestScopes;
import io.github.hectorvent.floci.services.eventbridge.EventBridgeService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Sends a record that a logging trail covers to the default bus of its account and region, as
 * CloudTrail does: {@code source} {@code aws.<service>}, a detail-type by {@code eventType}, no
 * resources and the record as {@code detail}. Read-only management events match only rules in state
 * {@code ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS}; records over 256 KB are not sent.
 */
@ApplicationScoped
public class CloudTrailEventBridgeForwarder {

    private static final Logger LOG = Logger.getLogger(CloudTrailEventBridgeForwarder.class);
    static final int MAX_EVENT_BYTES = 256 * 1024;

    private final EventBridgeService eventBridge;
    private final ObjectMapper mapper;
    private final int delaySeconds;

    @Inject
    public CloudTrailEventBridgeForwarder(EventBridgeService eventBridge, ObjectMapper mapper, EmulatorConfig config) {
        this.eventBridge = eventBridge;
        this.mapper = mapper;
        this.delaySeconds = config.services().cloudtrail().eventbridgeDelaySeconds();
    }

    public void forward(ObjectNode record) {
        String detailType = switch (record.path("eventType").asText()) {
            case "AwsApiCall" -> "AWS API Call via CloudTrail";
            case "AwsServiceEvent" -> "AWS Service Event via CloudTrail";
            default -> null;
        };
        if (detailType == null) {
            return;
        }
        try {
            String detail = mapper.writeValueAsString(record);
            if (detail.getBytes(StandardCharsets.UTF_8).length > MAX_EVENT_BYTES) {
                LOG.debugv("Not sending CloudTrail event {0} to EventBridge: over 256 KB",
                        record.path("eventID").asText());
                return;
            }
            String eventSource = record.path("eventSource").asText();
            Map<String, Object> entry = EventBridgeService.serviceEventEntry(
                    "aws." + eventSource.substring(0, eventSource.indexOf('.')), detailType, detail, null);
            if (record.path("managementEvent").asBoolean() && record.path("readOnly").asBoolean()) {
                entry.put(EventBridgeService.CLOUDTRAIL_READ_ONLY_MANAGEMENT_EVENT, true);
            }
            String region = record.path("awsRegion").asText();
            String account = record.path("recipientAccountId").asText();
            if (delaySeconds <= 0) {
                send(entry, region, account);
                return;
            }
            CompletableFuture.delayedExecutor(delaySeconds, TimeUnit.SECONDS).execute(() -> send(entry, region, account));
        } catch (Exception e) {
            LOG.warnv(e, "Failed to send CloudTrail event {0} to EventBridge", record.path("eventName").asText());
        }
    }

    private void send(Map<String, Object> entry, String region, String account) {
        try {
            RequestScopes.runAs(account, region, () -> eventBridge.putEvents(List.of(entry), region));
        } catch (Exception e) {
            LOG.warnv(e, "Failed to send CloudTrail event to EventBridge");
        }
    }
}
