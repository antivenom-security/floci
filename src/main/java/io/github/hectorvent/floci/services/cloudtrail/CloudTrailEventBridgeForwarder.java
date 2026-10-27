package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RequestScopes;
import io.github.hectorvent.floci.core.common.Resettable;
import io.github.hectorvent.floci.services.eventbridge.EventBridgeService;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Sends a record that a logging trail covers to the default bus of its account and region, as
 * CloudTrail does: {@code source} {@code aws.<service>}, a detail-type by {@code eventType}, no
 * resources and the record as {@code detail}. Entries over 256 KB are not sent. Sends run on one
 * background thread, after {@code eventbridge-delay-seconds}, so a slow target never holds up the
 * call that produced the record; past {@value #QUEUE_SIZE} pending sends, new ones are dropped.
 */
@ApplicationScoped
public class CloudTrailEventBridgeForwarder implements Resettable {

    private static final Logger LOG = Logger.getLogger(CloudTrailEventBridgeForwarder.class);
    static final int MAX_EVENT_BYTES = 256 * 1024;
    static final int QUEUE_SIZE = 10_000;

    private final EventBridgeService eventBridge;
    private final ObjectMapper mapper;
    private final long delayMillis;
    private final AtomicLong generation = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final ThreadPoolExecutor sender = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(QUEUE_SIZE), runnable -> {
                Thread thread = new Thread(runnable, "floci-cloudtrail-eventbridge");
                thread.setDaemon(true);
                return thread;
            }, (runnable, pool) -> {
                if (dropped.incrementAndGet() % QUEUE_SIZE == 1) {
                    LOG.warnv("CloudTrail to EventBridge is behind; dropped {0} events so far", dropped.get());
                }
            });

    @Inject
    public CloudTrailEventBridgeForwarder(EventBridgeService eventBridge, ObjectMapper mapper, EmulatorConfig config) {
        this.eventBridge = eventBridge;
        this.mapper = mapper;
        this.delayMillis = TimeUnit.SECONDS.toMillis(config.services().cloudtrail().eventbridgeDelaySeconds());
    }

    public void forward(ObjectNode record) {
        String detailType = switch (record.path("eventType").asText()) {
            case "AwsApiCall" -> "AWS API Call via CloudTrail";
            case "AwsServiceEvent" -> "AWS Service Event via CloudTrail";
            case "AwsConsoleSignIn" -> "AWS Console Sign In via CloudTrail";
            default -> null;
        };
        if (detailType == null) {
            return;
        }
        try {
            String eventSource = record.path("eventSource").asText();
            String source = "aws." + eventSource.substring(0, eventSource.indexOf('.'));
            String detail = mapper.writeValueAsString(record);
            if (utf8Length(source) + utf8Length(detailType) + utf8Length(detail) > MAX_EVENT_BYTES) {
                LOG.debugv("Not sending CloudTrail event {0} to EventBridge: over 256 KB",
                        record.path("eventID").asText());
                return;
            }
            Map<String, Object> entry = EventBridgeService.serviceEventEntry(source, detailType, detail, null);
            String region = record.path("awsRegion").asText();
            String account = record.path("recipientAccountId").asText();
            long due = System.currentTimeMillis() + delayMillis;
            long queuedIn = generation.get();
            sender.execute(() -> send(entry, region, account, due, queuedIn));
        } catch (Exception e) {
            LOG.warnv(e, "Failed to send CloudTrail event {0} to EventBridge", record.path("eventName").asText());
        }
    }

    private void send(Map<String, Object> entry, String region, String account, long due, long queuedIn) {
        try {
            long wait = due - System.currentTimeMillis();
            if (wait > 0) {
                Thread.sleep(wait);
            }
            if (queuedIn == generation.get()) {
                RequestScopes.runAs(account, region, () -> eventBridge.putEvents(List.of(entry), region));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            LOG.warnv(e, "Failed to send CloudTrail event to EventBridge");
        }
    }

    private static int utf8Length(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    @Override
    public void beforeReset() {
        clear();
    }

    @Override
    public void clear() {
        generation.incrementAndGet();
        sender.getQueue().clear();
    }

    @PreDestroy
    void shutdown() {
        sender.shutdownNow();
    }
}
