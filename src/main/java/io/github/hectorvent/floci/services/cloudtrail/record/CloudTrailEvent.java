package io.github.hectorvent.floci.services.cloudtrail.record;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;

/**
 * What {@link CloudTrailRecordBuilder} builds one record from. {@code requestParameters} and
 * {@code responseElements} are already in CloudTrail's form (see
 * {@link CloudTrailRecordBuilder#parameters}). {@code resources} left null are taken from the
 * vendored resources table.
 */
public record CloudTrailEvent(
        String eventSource,
        String eventName,
        String awsRegion,
        Instant eventTime,
        ObjectNode userIdentity,
        String sourceIPAddress,
        String userAgent,
        String errorCode,
        String errorMessage,
        JsonNode requestParameters,
        JsonNode responseElements,
        ObjectNode additionalEventData,
        String requestId,
        ArrayNode resources,
        TlsDetails tlsDetails,
        String recipientAccountId) {

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String eventSource;
        private String eventName;
        private String awsRegion;
        private Instant eventTime;
        private ObjectNode userIdentity;
        private String sourceIPAddress;
        private String userAgent;
        private String errorCode;
        private String errorMessage;
        private JsonNode requestParameters;
        private JsonNode responseElements;
        private ObjectNode additionalEventData;
        private String requestId;
        private ArrayNode resources;
        private TlsDetails tlsDetails;
        private String recipientAccountId;

        public Builder eventSource(String v) { this.eventSource = v; return this; }
        public Builder eventName(String v) { this.eventName = v; return this; }
        public Builder awsRegion(String v) { this.awsRegion = v; return this; }
        public Builder eventTime(Instant v) { this.eventTime = v; return this; }
        public Builder userIdentity(ObjectNode v) { this.userIdentity = v; return this; }
        public Builder sourceIPAddress(String v) { this.sourceIPAddress = v; return this; }
        public Builder userAgent(String v) { this.userAgent = v; return this; }
        public Builder errorCode(String v) { this.errorCode = v; return this; }
        public Builder errorMessage(String v) { this.errorMessage = v; return this; }
        public Builder requestParameters(JsonNode v) { this.requestParameters = v; return this; }
        public Builder responseElements(JsonNode v) { this.responseElements = v; return this; }
        public Builder additionalEventData(ObjectNode v) { this.additionalEventData = v; return this; }
        public Builder requestId(String v) { this.requestId = v; return this; }
        public Builder resources(ArrayNode v) { this.resources = v; return this; }
        public Builder tlsDetails(TlsDetails v) { this.tlsDetails = v; return this; }
        public Builder recipientAccountId(String v) { this.recipientAccountId = v; return this; }

        public CloudTrailEvent build() {
            return new CloudTrailEvent(eventSource, eventName, awsRegion, eventTime, userIdentity,
                    sourceIPAddress, userAgent, errorCode, errorMessage, requestParameters, responseElements,
                    additionalEventData, requestId, resources, tlsDetails, recipientAccountId);
        }
    }
}
