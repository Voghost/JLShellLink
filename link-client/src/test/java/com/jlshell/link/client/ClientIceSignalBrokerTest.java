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
}
