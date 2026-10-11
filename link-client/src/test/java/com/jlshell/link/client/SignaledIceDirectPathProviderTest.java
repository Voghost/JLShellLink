package com.jlshell.link.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.model.LinkFailure;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.signal.ControlSignal;
import com.jlshell.link.transport.Ice4jDirectSession;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class SignaledIceDirectPathProviderTest {
    private static final Ice4jDirectSession.Config CONFIG = new Ice4jDirectSession.Config(
            List.of(), 4, Duration.ofSeconds(2), 1_200, 50);
    private static final NodeKeyFingerprint CLIENT_KEY = new NodeKeyFingerprint("1".repeat(64));
    private static final NodeKeyFingerprint AGENT_KEY = new NodeKeyFingerprint("2".repeat(64));

    @Test
    void rejectsInvitationForAnotherClientBeforeCreatingIceSession() {
        LinkSessionId session = LinkSessionId.random();
        UUID device = UUID.randomUUID();
        UUID agent = UUID.randomUUID();
        var request = new IceKcpCarrierPlanFactory.DirectSessionRequest(session, device, CLIENT_KEY,
                agent, AGENT_KEY, 7, Instant.now().plusSeconds(60));
        ControlSignal.SessionInvite invite = new ControlSignal.SessionInvite(UUID.randomUUID(), session, 1,
                agent, UUID.randomUUID(), AGENT_KEY, CLIENT_KEY, 7,
                Instant.now().plusSeconds(30), true);
        TestSignaling signaling = new TestSignaling(invite);
        var provider = new SignaledIceDirectPathProvider(signaling, directExecutor(), CONFIG);
        var context = new TestAttemptContext();

        CompletionException rejected = assertThrows(CompletionException.class,
                () -> provider.establish(request, context).toCompletableFuture().join());

        assertInstanceOf(SecurityException.class, rejected.getCause());
        assertFalse(signaling.listenCalled.get());
        assertFalse(context.cancelled().toCompletableFuture().isDone());
    }

    @Test
    void reportsUnnegotiatedIceAsRetryableDirectPathFailure() {
        LinkSessionId session = LinkSessionId.random();
        UUID device = UUID.randomUUID();
        UUID agent = UUID.randomUUID();
        var request = new IceKcpCarrierPlanFactory.DirectSessionRequest(session, device, CLIENT_KEY,
                agent, AGENT_KEY, 7, Instant.now().plusSeconds(60));
        ControlSignal.SessionInvite invite = new ControlSignal.SessionInvite(UUID.randomUUID(), session, 1,
                agent, device, AGENT_KEY, CLIENT_KEY, 7, Instant.now().plusSeconds(30), false);
        TestSignaling signaling = new TestSignaling(invite);
        var provider = new SignaledIceDirectPathProvider(signaling, directExecutor(), CONFIG);

        CompletionException rejected = assertThrows(CompletionException.class,
                () -> provider.establish(request, new TestAttemptContext()).toCompletableFuture().join());

        LinkFailure failure = assertInstanceOf(LinkFailure.class, rejected.getCause());
        assertTrue(failure.retryableAcrossPath());
        assertFalse(signaling.listenCalled.get());
    }

    @Test
    void establishedLeaseRetainsItsSubscriptionUntilCurrentGenerationRevocation() throws Exception {
        try (var fixture = new EstablishedFixture()) {
            fixture.receive(new ControlSignal.SessionRevoked(UUID.randomUUID(), fixture.session, 2));
            fixture.receive(new ControlSignal.SessionRevoked(UUID.randomUUID(), LinkSessionId.random(), 1));
            assertTrue(fixture.lease.datagrams().isOpen());
            org.junit.jupiter.api.Assertions.assertEquals(0, fixture.unsubscribed.get());
            fixture.receive(new ControlSignal.SessionRevoked(UUID.randomUUID(), fixture.session, 1));
            assertFalse(fixture.lease.datagrams().isOpen());
            org.junit.jupiter.api.Assertions.assertEquals(1, fixture.failed.get());
            org.junit.jupiter.api.Assertions.assertEquals(1, fixture.unsubscribed.get());
            fixture.lease.close();
            org.junit.jupiter.api.Assertions.assertEquals(1, fixture.failed.get());
        }
    }

    @Test
    void successfulSetupContextCleanupDoesNotCancelTheTransferredLease() throws Exception {
        try (var fixture = new EstablishedFixture()) {
            var cancel = fixture.negotiation.getClass().getDeclaredMethod("cancelSetup");
            cancel.setAccessible(true);cancel.invoke(fixture.negotiation);
            assertTrue(fixture.lease.datagrams().isOpen());
            org.junit.jupiter.api.Assertions.assertEquals(0, fixture.unsubscribed.get());
            org.junit.jupiter.api.Assertions.assertEquals(0, fixture.failed.get());
        }
    }

    @Test
    void controlFailureAfterEstablishmentClosesTheDataPath() throws Exception {
        try (var fixture = new EstablishedFixture()) {
            var fail = fixture.negotiation.getClass().getDeclaredMethod("fail", Throwable.class);
            fail.setAccessible(true);fail.invoke(fixture.negotiation, new java.io.IOException("control lost"));
            assertFalse(fixture.lease.datagrams().isOpen());
            org.junit.jupiter.api.Assertions.assertEquals(1, fixture.failed.get());
            org.junit.jupiter.api.Assertions.assertEquals(1, fixture.unsubscribed.get());
        }
    }

    /** Simulated nomination fixture for ownership only; real ICE/business acceptance is separate. */
    private static final class EstablishedFixture implements AutoCloseable {
        final LinkSessionId session = LinkSessionId.random();
        final java.net.DatagramSocket socket = new java.net.DatagramSocket();
        final Ice4jDirectSession ice;
        final Object negotiation;
        final IceKcpCarrierPlanFactory.DirectPathLease lease;
        final java.util.concurrent.atomic.AtomicInteger unsubscribed = new java.util.concurrent.atomic.AtomicInteger();
        final java.util.concurrent.atomic.AtomicInteger failed = new java.util.concurrent.atomic.AtomicInteger();
        EstablishedFixture() throws Exception {
            ice = new Ice4jDirectSession(session, 1, true, CONFIG);
            var invite = new ControlSignal.SessionInvite(UUID.randomUUID(), session, 1, UUID.randomUUID(),
                    UUID.randomUUID(), AGENT_KEY, CLIENT_KEY, 7, Instant.now().plusSeconds(30), true);
            var provider = new SignaledIceDirectPathProvider(new TestSignaling(invite), directExecutor(), CONFIG);
            var result = new CompletableFuture<IceKcpCarrierPlanFactory.DirectPathLease>();
            Class<?> type = Class.forName(SignaledIceDirectPathProvider.class.getName() + "$Negotiation");
            var ctor = type.getDeclaredConstructor(SignaledIceDirectPathProvider.class, Ice4jDirectSession.class,
                    ConnectionCoordinator.AttemptContext.class, CompletableFuture.class);
            ctor.setAccessible(true);negotiation=ctor.newInstance(provider, ice, new TestAttemptContext(), result);
            var datagrams = new com.jlshell.link.transport.IceSelectedDatagramPath(socket,
                    new java.net.InetSocketAddress("192.0.2.1", 23000), 1200, 50);
            var selectedCtor = Ice4jDirectSession.SelectedPath.class.getDeclaredConstructor(Ice4jDirectSession.class,
                    com.jlshell.link.transport.IceSelectedDatagramPath.class, UUID.class, UUID.class);
            selectedCtor.setAccessible(true);var local=UUID.randomUUID();var remote=UUID.randomUUID();
            var selected=(Ice4jDirectSession.SelectedPath)selectedCtor.newInstance(ice, datagrams, local, remote);
            var iceSelected=Ice4jDirectSession.class.getDeclaredField("selected");iceSelected.setAccessible(true);
            iceSelected.set(ice, selected);
            setValue("selected", selected);
            var ready=type.getDeclaredField("peerReady");ready.setAccessible(true);
            @SuppressWarnings("unchecked") var future=(CompletableFuture<ControlSignal.PathReady>)ready.get(negotiation);
            future.complete(new ControlSignal.PathReady(UUID.randomUUID(),session,1,ControlSignal.Path.DIRECT,remote,local));
            var subscription=type.getDeclaredField("subscription");subscription.setAccessible(true);
            subscription.set(negotiation,(SignaledIceDirectPathProvider.Subscription)unsubscribed::incrementAndGet);
            var complete=type.getDeclaredMethod("maybeComplete");complete.setAccessible(true);complete.invoke(negotiation);
            lease=result.join();lease.datagrams().setReceiver(packet -> { }, error -> failed.incrementAndGet());
        }
        @SuppressWarnings("unchecked") void setValue(String name, Object value) throws Exception {
            var field=negotiation.getClass().getDeclaredField(name);field.setAccessible(true);
            ((java.util.concurrent.atomic.AtomicReference<Object>)field.get(negotiation)).set(value);
        }
        void receive(ControlSignal signal) throws Exception {
            var method=negotiation.getClass().getDeclaredMethod("receive",ControlSignal.class);
            method.setAccessible(true);method.invoke(negotiation,signal);
        }
        public void close() { lease.close();ice.close();socket.close(); }
    }

    private static Executor directExecutor() { return Runnable::run; }

    private static final class TestSignaling implements SignaledIceDirectPathProvider.Signaling {
        private final ControlSignal.SessionInvite invite;
        private final AtomicBoolean listenCalled = new AtomicBoolean();

        private TestSignaling(ControlSignal.SessionInvite invite) { this.invite = invite; }

        @Override public CompletableFuture<ControlSignal.SessionInvite> awaitInvite(LinkSessionId sessionId) {
            return CompletableFuture.completedFuture(invite);
        }
        @Override public SignaledIceDirectPathProvider.Subscription listen(LinkSessionId sessionId,
                long generation, java.util.function.Consumer<ControlSignal> signals,
                java.util.function.Consumer<Throwable> failure) {
            listenCalled.set(true);
            return () -> { };
        }
        @Override public CompletableFuture<Void> send(ControlSignal signal) {
            return CompletableFuture.completedFuture(null);
        }
    }

    private static final class TestAttemptContext implements ConnectionCoordinator.AttemptContext {
        private final CompletableFuture<Void> cancelled = new CompletableFuture<>();
        @Override public long networkGeneration() { return 1; }
        @Override public int maxCandidates() { return 4; }
        @Override public boolean isCancelled() { return cancelled.isDone(); }
        @Override public CompletableFuture<Void> cancelled() { return cancelled; }
    }
}
