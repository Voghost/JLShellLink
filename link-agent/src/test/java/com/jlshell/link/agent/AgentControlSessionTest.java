package com.jlshell.link.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AgentControlSessionTest {
    @Test
    void failedRelayOpenIsRetriedWhileWebsiteKeepsAuthorizationLeaseActive() {
        UUID agentId = UUID.randomUUID();
        NodeKeyFingerprint fingerprint = new NodeKeyFingerprint("a".repeat(64));
        Instant now = Instant.now();
        var request = new AgentControlPlaneClient.RelayOpenRequest(
                UUID.randomUUID(), UUID.randomUUID(), agentId, "b".repeat(64), fingerprint.value(),
                "192.0.2.20", 22, 3, now.plusSeconds(30), now.plusSeconds(120));
        var snapshot = new AgentLeaseSnapshot(agentId, fingerprint, 3, now.plusSeconds(180), false);
        AtomicInteger attempts = new AtomicInteger();
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        AgentControlSession session = new AgentControlSession(
                new AgentControlPlaneClient(URI.create("https://website.example"),
                        Duration.ofSeconds(1), Duration.ofSeconds(1)),
                "credential", agentId, fingerprint, "test", Set.of("tcp-connect"), scheduler,
                Duration.ofSeconds(10), ignored -> { }, () -> { }, ignored -> {
                    attempts.incrementAndGet();
                    return CompletableFuture.failedFuture(new IllegalStateException("temporary relay failure"));
                }, ignored -> { }, () -> { }, ignored -> { });
        try {
            session.handleRelayRequests(List.of(request), snapshot);
            session.handleRelayRequests(List.of(request), snapshot);

            assertEquals(2, attempts.get(), "failed relay creation must be retried on the next control poll");
        } finally {
            session.close();
            scheduler.shutdownNow();
        }
    }
}
