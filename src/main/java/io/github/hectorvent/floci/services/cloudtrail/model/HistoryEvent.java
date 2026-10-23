package io.github.hectorvent.floci.services.cloudtrail.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.List;

/** A management event in event history: the LookupEvents attributes and the record itself. */
@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public record HistoryEvent(
        String eventId,
        String eventName,
        String eventSource,
        String region,
        long eventTimeMillis,
        boolean readOnly,
        String accessKeyId,
        String username,
        List<Resource> resources,
        String cloudTrailEvent) {

    @RegisterForReflection
    public record Resource(String resourceType, String resourceName) {
    }
}
