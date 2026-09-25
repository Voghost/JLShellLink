package com.jlshell.link.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.model.ConnectPolicy;
import com.jlshell.link.core.model.LinkFailure;
import com.jlshell.link.core.model.LinkPath;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.ReliableDuplexChannel;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ConnectionCoordinatorTest {
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final ConnectionCoordinator coordinator = new ConnectionCoordinator(scheduler, 4);

    @AfterEach
    void close() {
        coordinator.close();
        scheduler.shutdownNow();
    }

    @Test
    void autoUsesDirectAndCountsOnlyTunnelBytes() throws Exception {
        AtomicInteger relayCalls = new AtomicInteger();
        AtomicInteger targetCalls = new AtomicInteger();
        DummyCarrier direct = new DummyCarrier(LinkPath.DIRECT);
        ConnectionCoordinator.Connection connection = connect(ConnectPolicy.AUTO,
                context -> CompletableFuture.completedFuture(direct),
                context -> { relayCalls.incrementAndGet(); return CompletableFuture.completedFuture(new DummyCarrier(LinkPath.RELAY)); },
                (carrier, request, context) -> {
                    targetCalls.incrementAndGet();
                    assertEquals(direct, carrier);
                    assertEquals("TargetRequest[<redacted>]", request.toString());
                    return CompletableFuture.completedFuture(new DummyTunnel());
                }).result().toCompletableFuture().get(2, TimeUnit.SECONDS);

        assertEquals(LinkPath.DIRECT, connection.path());
        assertEquals(0, relayCalls.get());
        assertEquals(1, targetCalls.get());
        connection.channel().write(ByteBuffer.wrap(new byte[17])).toCompletableFuture().get(1, TimeUnit.SECONDS);
        connection.channel().read(9).toCompletableFuture().get(1, TimeUnit.SECONDS);
        assertEquals(17, connection.bytesSent());
        assertEquals(4, connection.bytesReceived());
        connection.channel().close();
        assertTrue(direct.closed);
        connection.close();
    }

    @Test
    void autoFallsBackOnlyForRetryableDirectNetworkFailure() throws Exception {
        AtomicInteger targetCalls = new AtomicInteger();
        List<ConnectionCoordinator.PathAttemptEvent> events = new ArrayList<>();
        DummyCarrier relay = new DummyCarrier(LinkPath.RELAY);
        ConnectionCoordinator.Connection connection = connect(ConnectPolicy.AUTO,
                context -> CompletableFuture.failedFuture(new LinkFailure("direct.unreachable",
                        LinkFailure.Category.TRANSIENT_NETWORK, "network unavailable")),
                context -> {
                    assertEquals(16, context.maxCandidates());
                    return CompletableFuture.completedFuture(relay);
                },
                (carrier, request, context) -> {
                    targetCalls.incrementAndGet();
                    return CompletableFuture.completedFuture(new DummyTunnel());
                }, events::add).result().toCompletableFuture().get(2, TimeUnit.SECONDS);

        assertEquals(LinkPath.RELAY, connection.path());
        assertEquals(1, targetCalls.get());
        assertEquals(List.of(LinkPath.DIRECT, LinkPath.RELAY, LinkPath.RELAY), events.stream()
                .map(ConnectionCoordinator.PathAttemptEvent::path).toList());
        assertEquals(ConnectionCoordinator.PathOutcome.FAILED, events.get(0).outcome());
        assertEquals(ConnectionCoordinator.PathOutcome.READY, events.get(1).outcome());
        assertEquals(ConnectionCoordinator.PathOutcome.TARGET_OPENED, events.get(2).outcome());
        assertEquals(LinkFailure.Category.TRANSIENT_NETWORK,
                events.getFirst().failureCategory().orElseThrow());
        connection.close();
    }

    @Test
    void authorizationFailureNeverFallsBackToRelay() throws Exception {
        AtomicInteger relayCalls = new AtomicInteger();
        var attempt = connect(ConnectPolicy.AUTO,
                context -> CompletableFuture.failedFuture(new LinkFailure("ticket.denied",
                        LinkFailure.Category.AUTHORIZATION, "denied")),
                context -> { relayCalls.incrementAndGet(); return CompletableFuture.completedFuture(new DummyCarrier(LinkPath.RELAY)); },
                (carrier, request, context) -> CompletableFuture.completedFuture(new DummyTunnel()));

        LinkFailure failure = failure(attempt);
        assertEquals(LinkFailure.Category.AUTHORIZATION, failure.category());
        assertEquals(0, relayCalls.get());
    }

    @Test
    void unclassifiedCarrierFailureDoesNotFallBack() throws Exception {
        AtomicInteger relayCalls = new AtomicInteger();
        LinkFailure failure = failure(connect(ConnectPolicy.AUTO,
                context -> CompletableFuture.failedFuture(new IOException("unclassified")),
                context -> { relayCalls.incrementAndGet(); return CompletableFuture.completedFuture(new DummyCarrier(LinkPath.RELAY)); },
                (carrier, request, context) -> CompletableFuture.completedFuture(new DummyTunnel())));
        assertEquals(LinkFailure.Category.PROTOCOL, failure.category());
        assertEquals(0, relayCalls.get());
    }

    @Test
    void connectorCannotMislabelCarrierPath() throws Exception {
        AtomicInteger relayCalls = new AtomicInteger();
        DummyCarrier mislabeled = new DummyCarrier(LinkPath.RELAY);
        LinkFailure failure = failure(connect(ConnectPolicy.AUTO,
                context -> CompletableFuture.completedFuture(mislabeled),
                context -> { relayCalls.incrementAndGet(); return CompletableFuture.completedFuture(new DummyCarrier(LinkPath.RELAY)); },
                (carrier, request, context) -> CompletableFuture.completedFuture(new DummyTunnel())));
        assertEquals(LinkFailure.Category.PROTOCOL, failure.category());
        assertTrue(mislabeled.closed);
        assertEquals(0, relayCalls.get());
    }

    @Test
    void directOnlyNeverCallsRelayAndRelayOnlyNeverCallsDirect() throws Exception {
        AtomicInteger directCalls = new AtomicInteger();
        AtomicInteger relayCalls = new AtomicInteger();
        LinkFailure directFailure = failure(connect(ConnectPolicy.DIRECT_ONLY,
                context -> { directCalls.incrementAndGet(); return CompletableFuture.failedFuture(
                        new LinkFailure("direct.timeout", LinkFailure.Category.DIRECT_TIMEOUT, "timed out")); },
                context -> { relayCalls.incrementAndGet(); return CompletableFuture.completedFuture(new DummyCarrier(LinkPath.RELAY)); },
                (carrier, request, context) -> CompletableFuture.completedFuture(new DummyTunnel())));
        assertEquals(LinkFailure.Category.DIRECT_TIMEOUT, directFailure.category());
        assertEquals(1, directCalls.get());
        assertEquals(0, relayCalls.get());

        ConnectionCoordinator.Connection relayConnection = connect(ConnectPolicy.RELAY_ONLY,
                context -> { directCalls.incrementAndGet(); return CompletableFuture.completedFuture(new DummyCarrier(LinkPath.DIRECT)); },
                context -> { relayCalls.incrementAndGet(); return CompletableFuture.completedFuture(new DummyCarrier(LinkPath.RELAY)); },
                (carrier, request, context) -> CompletableFuture.completedFuture(new DummyTunnel()))
                .result().toCompletableFuture().get(2, TimeUnit.SECONDS);
        assertEquals(LinkPath.RELAY, relayConnection.path());
        assertEquals(1, directCalls.get());
        assertEquals(1, relayCalls.get());
        relayConnection.close();
    }

    @Test
    void targetOpenFailureDoesNotRetryOrConsumeTicketTwice() throws Exception {
        AtomicInteger relayCalls = new AtomicInteger();
        AtomicInteger targetCalls = new AtomicInteger();
        DummyCarrier selected = new DummyCarrier(LinkPath.DIRECT);
        var attempt = connect(ConnectPolicy.AUTO,
                context -> CompletableFuture.completedFuture(selected),
                context -> { relayCalls.incrementAndGet(); return CompletableFuture.completedFuture(new DummyCarrier(LinkPath.RELAY)); },
                (carrier, request, context) -> {
                    targetCalls.incrementAndGet();
                    return CompletableFuture.failedFuture(new LinkFailure("ticket.expired",
                            LinkFailure.Category.AUTHORIZATION, "expired"));
                });

        assertEquals(LinkFailure.Category.AUTHORIZATION, failure(attempt).category());
        assertEquals(1, targetCalls.get());
        assertEquals(0, relayCalls.get());
        assertTrue(selected.closed);
    }

    @Test
    void directTimeoutFallsBackAndClosesLateCarrier() throws Exception {
        CompletableFuture<ConnectionCoordinator.SecureCarrier> directPending = new CompletableFuture<>();
        AtomicInteger targetCalls = new AtomicInteger();
        DummyCarrier lateDirect = new DummyCarrier(LinkPath.DIRECT);
        DummyCarrier relay = new DummyCarrier(LinkPath.RELAY);
        ConnectionCoordinator.Config shortTimeout = new ConnectionCoordinator.Config(
                Duration.ofMillis(25), Duration.ofSeconds(1), 16);
        ConnectionCoordinator.Connection connection = connect(shortTimeout, ConnectPolicy.AUTO,
                context -> directPending,
                context -> CompletableFuture.completedFuture(relay),
                (carrier, request, context) -> {
                    targetCalls.incrementAndGet();
                    return CompletableFuture.completedFuture(new DummyTunnel());
                }, ConnectionCoordinator.Observer.NOOP).result().toCompletableFuture().get(2, TimeUnit.SECONDS);

        directPending.complete(lateDirect);
        assertEquals(LinkPath.RELAY, connection.path());
        assertTrue(lateDirect.closed);
        assertEquals(1, targetCalls.get());
        connection.close();
    }

    @Test
    void networkGenerationChangeCancelsPendingPathAndRejectsLateCandidate() throws Exception {
        CompletableFuture<ConnectionCoordinator.SecureCarrier> directPending = new CompletableFuture<>();
        AtomicInteger relayCalls = new AtomicInteger();
        AtomicInteger targetCalls = new AtomicInteger();
        AtomicReferenceHolder<ConnectionCoordinator.AttemptContext> context = new AtomicReferenceHolder<>();
        ConnectionCoordinator.ConnectionAttempt attempt = connect(ConnectPolicy.AUTO,
                current -> { context.value = current; return directPending; },
                current -> { relayCalls.incrementAndGet(); return CompletableFuture.completedFuture(new DummyCarrier(LinkPath.RELAY)); },
                (carrier, request, current) -> {
                    targetCalls.incrementAndGet();
                    return CompletableFuture.completedFuture(new DummyTunnel());
                });

        coordinator.updateNetworkGeneration(5);
        assertEquals(4, attempt.networkGeneration());
        assertTrue(context.value.cancellation().isCancelled());
        assertEquals(LinkFailure.Category.CANCELLED, failure(attempt).category());
        DummyCarrier late = new DummyCarrier(LinkPath.DIRECT);
        directPending.complete(late);
        assertTrue(late.closed);
        assertEquals(0, relayCalls.get());
        assertEquals(0, targetCalls.get());
    }

    private ConnectionCoordinator.ConnectionAttempt connect(ConnectPolicy policy,
            ConnectionCoordinator.CarrierConnector direct, ConnectionCoordinator.CarrierConnector relay,
            ConnectionCoordinator.TargetOpener opener) {
        return connect(policy, direct, relay, opener, ConnectionCoordinator.Observer.NOOP);
    }

    private ConnectionCoordinator.ConnectionAttempt connect(ConnectPolicy policy,
            ConnectionCoordinator.CarrierConnector direct, ConnectionCoordinator.CarrierConnector relay,
            ConnectionCoordinator.TargetOpener opener, ConnectionCoordinator.Observer observer) {
        return connect(new ConnectionCoordinator.Config(Duration.ofSeconds(1), Duration.ofSeconds(1), 16),
                policy, direct, relay, opener, observer);
    }

    private ConnectionCoordinator.ConnectionAttempt connect(ConnectionCoordinator.Config config, ConnectPolicy policy,
            ConnectionCoordinator.CarrierConnector direct, ConnectionCoordinator.CarrierConnector relay,
            ConnectionCoordinator.TargetOpener opener, ConnectionCoordinator.Observer observer) {
        return coordinator.connect(config, policy, coordinatorGeneration(),
                new ConnectionCoordinator.TargetRequest(new TargetEndpoint("192.0.2.9", 22),
                        TunnelId.random(), "test-ticket-not-a-real-credential"),
                direct, relay, opener, observer);
    }

    private long coordinatorGeneration() { return 4; }

    private static LinkFailure failure(ConnectionCoordinator.ConnectionAttempt attempt) throws Exception {
        try {
            attempt.result().toCompletableFuture().get(2, TimeUnit.SECONDS);
            throw new AssertionError("expected attempt to fail");
        } catch (ExecutionException error) {
            return assertInstanceOf(LinkFailure.class, error.getCause());
        }
    }

    private static final class DummyCarrier implements ConnectionCoordinator.SecureCarrier {
        private final LinkPath path;
        private volatile boolean closed;
        private DummyCarrier(LinkPath path) { this.path = path; }
        @Override public LinkPath path() { return path; }
        @Override public void close() { closed = true; }
    }

    private static final class DummyTunnel implements ReliableDuplexChannel {
        private volatile boolean closed;
        private final CompletableFuture<Void> closedStage = new CompletableFuture<>();
        @Override public CompletionStage<ByteBuffer> read(int maxBytes) {
            return CompletableFuture.completedFuture(ByteBuffer.wrap(new byte[4]));
        }
        @Override public CompletionStage<Void> write(ByteBuffer data) {
            return CompletableFuture.completedFuture(null);
        }
        @Override public CompletionStage<Void> whenWritable() { return CompletableFuture.completedFuture(null); }
        @Override public CompletionStage<Void> shutdownOutput() { return CompletableFuture.completedFuture(null); }
        @Override public CompletionStage<Void> closed() { return closedStage; }
        @Override public void abort(Throwable cause) { close(); }
        @Override public void close() { closed = true; closedStage.complete(null); }
    }

    private static final class AtomicReferenceHolder<T> { private volatile T value; }
}
