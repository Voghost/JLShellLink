package com.jlshell.link.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jlshell.link.core.model.ConnectPolicy;
import com.jlshell.link.core.model.LinkFailure;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;

class ReauthorizingConnectionFlowTest {
    @Test
    void obtainsFreshTicketAndTunnelForEveryReconnectWhileReusingSession() throws Exception {
        Instant now = Instant.parse("2026-09-25T07:30:00Z");
        UUID agent = UUID.randomUUID();
        LinkSessionId session = LinkSessionId.random();
        TargetEndpoint target = new TargetEndpoint("192.168.31.20", 22);
        List<Optional<LinkSessionId>> reusedSessions = new ArrayList<>();
        List<ReauthorizingConnectionFlow.AuthorizedTunnel> grants = new ArrayList<>();
        var scheduler = Executors.newSingleThreadScheduledExecutor();
        try (ConnectionCoordinator coordinator = new ConnectionCoordinator(scheduler);
             var ignored = new AutoCloseable() { @Override public void close() { scheduler.shutdownNow(); } }) {
            ReauthorizingConnectionFlow flow = new ReauthorizingConnectionFlow(coordinator,
                    Clock.fixed(now, ZoneOffset.UTC));
            ReauthorizingConnectionFlow.AccessRequestProvider access = (reuse, requestedAgent, requestedTarget, policy) -> {
                reusedSessions.add(reuse);
                TunnelId tunnel = TunnelId.random();
                ReauthorizingConnectionFlow.AuthorizedTunnel grant = new ReauthorizingConnectionFlow.AuthorizedTunnel(
                        session, tunnel, requestedAgent, requestedTarget, "opaque-ticket-" + grants.size(),
                        now.plusSeconds(60), now.plusSeconds(300), 1);
                grants.add(grant);
                return CompletableFuture.completedFuture(grant);
            };
            var plans = (ReauthorizingConnectionFlow.CarrierPlanFactory) grant ->
                    new ReauthorizingConnectionFlow.PathPlan(
                            context -> CompletableFuture.failedFuture(new LinkFailure("auth.rejected",
                                    LinkFailure.Category.AUTHORIZATION, "ticket rejected")),
                            null,
                            (carrier, request, context) -> CompletableFuture.failedFuture(
                                    new AssertionError("target opener must not run after carrier rejection")));
            var config = new ConnectionCoordinator.Config(Duration.ofSeconds(1), Duration.ofSeconds(1), 1);

            assertThrows(ExecutionException.class, () -> flow.connect(config, ConnectPolicy.DIRECT_ONLY,
                    0, agent, target, access, plans, null).toCompletableFuture().get());
            assertThrows(ExecutionException.class, () -> flow.connect(config, ConnectPolicy.DIRECT_ONLY,
                    0, agent, target, access, plans, null).toCompletableFuture().get());

            assertEquals(Optional.empty(), reusedSessions.getFirst());
            assertEquals(Optional.of(session), reusedSessions.get(1));
            assertNotEquals(grants.get(0).tunnelId(), grants.get(1).tunnelId());
            assertNotEquals(grants.get(0).accessTicket(), grants.get(1).accessTicket());
            assertEquals(Optional.of(session), flow.sessionId());
        }
    }
}
