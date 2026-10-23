package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.eventbridge.EventBridgeService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The forwarder hands sends to its own thread and leaves out entries over 256 KB. */
@Timeout(30)
class CloudTrailEventBridgeForwarderTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final EventBridgeService eventBridge = mock(EventBridgeService.class);

    private CloudTrailEventBridgeForwarder forwarder() {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().cloudtrail().eventbridgeDelaySeconds()).thenReturn(0);
        return new CloudTrailEventBridgeForwarder(eventBridge, mapper, config);
    }

    private ObjectNode record(String parameter) {
        ObjectNode record = mapper.createObjectNode();
        record.put("eventSource", "iam.amazonaws.com").put("eventName", "CreateUser").put("eventType", "AwsApiCall")
                .put("awsRegion", "us-east-1").put("recipientAccountId", "123456789012");
        record.putObject("requestParameters").put("userName", parameter);
        return record;
    }

    @Test
    void aSlowTargetDoesNotHoldUpTheCaller() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch sent = new CountDownLatch(1);
        when(eventBridge.putEvents(anyList(), anyString())).thenAnswer(invocation -> {
            sent.countDown();
            release.await();
            return null;
        });
        CloudTrailEventBridgeForwarder forwarder = forwarder();

        long start = System.nanoTime();
        forwarder.forward(record("one"));
        forwarder.forward(record("two"));
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        assertTrue(sent.await(10, TimeUnit.SECONDS));
        assertTrue(elapsedMillis < 1000, "forward took " + elapsedMillis + " ms");
        release.countDown();
    }

    @Test
    void anEntryOver256KbIsNotSent() {
        forwarder().forward(record("x".repeat(CloudTrailEventBridgeForwarder.MAX_EVENT_BYTES)));

        verify(eventBridge, after(500).never()).putEvents(anyList(), any());
    }
}
