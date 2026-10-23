package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.services.cloudtrail.model.AdvancedEventSelector;
import io.github.hectorvent.floci.services.cloudtrail.model.AdvancedFieldSelector;
import io.github.hectorvent.floci.services.cloudtrail.model.EventSelector;

import java.util.List;

/**
 * Whether a trail's selectors log a management event. A trail with no selectors logs every
 * management event, as CreateTrail's default selector does. Basic selectors honour
 * {@code IncludeManagementEvents}, {@code ReadWriteType} and {@code ExcludeManagementEventSources};
 * advanced selectors {@code eventCategory}, {@code readOnly} and {@code eventSource}.
 */
final class TrailRouter {

    private TrailRouter() {
    }

    static boolean logsManagementEvent(List<EventSelector> selectors, List<AdvancedEventSelector> advanced,
                                       String eventSource, boolean readOnly) {
        if (advanced != null && !advanced.isEmpty()) {
            return advanced.stream().anyMatch(selector -> matches(selector, eventSource, readOnly));
        }
        if (selectors == null || selectors.isEmpty()) {
            return true;
        }
        return selectors.stream().anyMatch(selector -> matches(selector, eventSource, readOnly));
    }

    private static boolean matches(EventSelector selector, String eventSource, boolean readOnly) {
        String readWriteType = selector.readWriteType() == null ? "All" : selector.readWriteType();
        return !Boolean.FALSE.equals(selector.includeManagementEvents())
                && !("ReadOnly".equalsIgnoreCase(readWriteType) && !readOnly)
                && !("WriteOnly".equalsIgnoreCase(readWriteType) && readOnly)
                && (selector.excludeManagementEventSources() == null
                || !selector.excludeManagementEventSources().contains(eventSource));
    }

    private static boolean matches(AdvancedEventSelector selector, String eventSource, boolean readOnly) {
        List<AdvancedFieldSelector> fields = selector.fieldSelectors();
        if (fields == null || fields.isEmpty()) {
            return false;
        }
        for (AdvancedFieldSelector field : fields) {
            String value = switch (field.field()) {
                case "eventCategory" -> "Management";
                case "readOnly" -> String.valueOf(readOnly);
                case "eventSource" -> eventSource;
                default -> null;
            };
            if (value == null || !CloudTrailService.matchesFieldValue(field, value)) {
                return false;
            }
        }
        return true;
    }
}
