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
