package com.jlshell.link.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.signal.ControlSignal;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ClientIceSignalBrokerTest {
    private static final NodeKeyFingerprint CLIENT = new NodeKeyFingerprint("1".repeat(64));
    private static final NodeKeyFingerprint AGENT = new NodeKeyFingerprint("2".repeat(64));

    @Test
    void deliversInvitationAndOnlyCurrentGenerationSignals() {
        LinkSessionId sessionId = LinkSessionId.random();
        UUID agentId = UUID.randomUUID();
        UUID deviceId = UUID.randomUUID();
        ControlSignal.SessionInvite invite = new ControlSignal.SessionInvite(UUID.randomUUID(), sessionId, 4,
                agentId, deviceId, AGENT, CLIENT, 2, Instant.now().plusSeconds(30), true);
        ClientIceSignalBroker broker = new ClientIceSignalBroker();
        var inviteFuture = broker.awaitInvite(sessionId).toCompletableFuture();
        broker.accept(invite);
        assertSame(invite, inviteFuture.join());

        AtomicInteger received = new AtomicInteger();
        var subscription = broker.listen(sessionId, 4, ignored -> received.incrementAndGet(), ignored -> { });
        broker.accept(new ControlSignal.IceEnd(UUID.randomUUID(), sessionId, 3));
        broker.accept(new ControlSignal.IceEnd(UUID.randomUUID(), sessionId, 4));
        assertEquals(1, received.get());
        subscription.close();
        broker.close();
    }

    @Test
    void routesAWebsiteInviteThatArrivesBeforeTheAccessRequestWaitsForIt() {
        LinkSessionId sessionId = LinkSessionId.random();
        ControlSignal.SessionInvite invite = new ControlSignal.SessionInvite(UUID.randomUUID(), sessionId, 1,
                UUID.randomUUID(), UUID.randomUUID(), AGENT, CLIENT, 1,
                Instant.now().plusSeconds(30), true);
        ClientIceSignalBroker broker = new ClientIceSignalBroker();
        broker.accept(invite);
        assertSame(invite, broker.awaitInvite(sessionId).toCompletableFuture().join());
        broker.close();
    }
    @Test
    void buffersAuthenticatedOfferUntilSubscriberFinishesGathering() {
        var session = LinkSessionId.random();
        var broker = new ClientIceSignalBroker();
        broker.accept(invite(session, 1));
        broker.awaitInvite(session).toCompletableFuture().join();
        var credentials = new ControlSignal.IceCredentials(UUID.randomUUID(), session, 1,
                "testfragment", "testpasswordwithsufficientlength");
        var end = new ControlSignal.IceEnd(UUID.randomUUID(), session, 1);
        broker.accept(credentials);
        broker.accept(end);
        var received = new java.util.ArrayList<ControlSignal>();
        var subscription = broker.listen(session, 1, received::add, ignored -> { });
        assertEquals(java.util.List.of(credentials, end), received);
        subscription.close();
        broker.close();
    }

    @Test
    void neverBuffersUnknownOrSupersededGenerations() {
        var session = LinkSessionId.random();
        var broker = new ClientIceSignalBroker();
        broker.accept(new ControlSignal.IceEnd(UUID.randomUUID(), session, 1));
        broker.accept(invite(session, 1));
        broker.accept(new ControlSignal.IceEnd(UUID.randomUUID(), session, 1));
        broker.accept(invite(session, 2));
        broker.accept(invite(session, 1));
        var received = new java.util.ArrayList<ControlSignal>();
        broker.listen(session, 1, received::add, ignored -> { });
        assertEquals(0, received.size());
        broker.close();
    }

    @Test
    void limitsEarlyMessagesAndClearsThemOnDisconnect() {
        var session = LinkSessionId.random();
        var broker = new ClientIceSignalBroker();
        broker.accept(invite(session, 1));
        for (int i = 0; i < 36; i++) broker.accept(new ControlSignal.IceEnd(UUID.randomUUID(), session, 1));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> broker.accept(new ControlSignal.IceEnd(UUID.randomUUID(), session, 1)));
        broker.accept(invite(session, 2));
        broker.accept(new ControlSignal.IceEnd(UUID.randomUUID(), session, 2));
        broker.connectionLost(new java.io.IOException("disconnected"));
        var received = new java.util.ArrayList<ControlSignal>();
        broker.listen(session, 2, received::add, ignored -> { });
        assertEquals(0, received.size());
        broker.close();
    }

    private static ControlSignal.SessionInvite invite(LinkSessionId session, long generation) {
        return new ControlSignal.SessionInvite(UUID.randomUUID(), session, generation,
                UUID.randomUUID(), UUID.randomUUID(), AGENT, CLIENT, 1,
                Instant.now().plusSeconds(30), true);
    }

}
