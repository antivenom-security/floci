package io.github.hectorvent.floci.services.eventbridge.model;

import io.github.hectorvent.floci.core.common.AwsException;
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public enum RuleState {
    ENABLED,
    DISABLED,
    ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS;

    /** PutRule's and CloudFormation's {@code State}: ENABLED when absent, otherwise an exact value. */
    public static RuleState fromValue(String state) {
        if (state == null || state.isBlank()) {
            return ENABLED;
        }
        for (RuleState value : values()) {
            if (value.name().equals(state)) {
                return value;
            }
        }
        throw new AwsException("ValidationException", "1 validation error detected: Value '" + state
                + "' at 'state' failed to satisfy constraint: Member must satisfy enum value set: "
                + "[ENABLED, DISABLED, ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS]", 400);
    }
}
