package io.github.hectorvent.floci.services.eventbridge.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public enum RuleState {
    ENABLED,
    DISABLED,
    ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS;

    /** PutRule's and CloudFormation's {@code State}, ENABLED when absent or unknown. */
    public static RuleState fromValue(String state) {
        if (state == null || state.isBlank()) {
            return ENABLED;
        }
        return switch (state.toUpperCase()) {
            case "DISABLED" -> DISABLED;
            case "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" -> ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS;
            default -> ENABLED;
        };
    }
}
