package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Where every management event record goes: event history, which keeps it whether or not a trail
 * covers it, each trail whose selectors log it and, when one does, EventBridge.
 */
@ApplicationScoped
public class CloudTrailRecorder {

    private final EventHistoryStore history;
    private final CloudTrailService trails;
    private final CloudTrailEventBridgeForwarder eventBridge;
    private final boolean enabled;

    @Inject
    public CloudTrailRecorder(EventHistoryStore history, CloudTrailService trails,
                              CloudTrailEventBridgeForwarder eventBridge, EmulatorConfig config) {
        this.history = history;
        this.trails = trails;
        this.eventBridge = eventBridge;
        this.enabled = config.services().cloudtrail().enabled()
                && config.services().cloudtrail().managementEvents().enabled();
    }

    public boolean enabled() {
        return enabled;
    }

    public void record(ObjectNode record) {
        if (!enabled) {
            return;
        }
        history.append(record);
        if (trails.routeManagementEvent(record)) {
            eventBridge.forward(record);
        }
    }
}
