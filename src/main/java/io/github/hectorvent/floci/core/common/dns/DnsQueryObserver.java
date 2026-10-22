package io.github.hectorvent.floci.core.common.dns;

import java.time.Instant;
import java.util.List;

/**
 * Told about every query {@link EmbeddedDnsServer} answers, with the answer the client received,
 * which is how Route 53 Resolver query logging sees DNS traffic. Discovered through CDI so the DNS
 * server never imports the service that logs. Runs on a worker thread, after the response is sent.
 */
public interface DnsQueryObserver {

    /** One answered query. {@code name} has no trailing dot; {@code answers} is empty unless answered. */
    record Query(Instant timestamp, String sourceAddress, int sourcePort, String name, int type,
                 int queryClass, int responseCode, List<Answer> answers) {
    }

    /** One answer record, its data in presentation form ({@code 10.0.0.1}, {@code host.example.}). */
    record Answer(String data, int type, int answerClass) {
    }

    void observe(Query query);
}
