package com.jlshell.link.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.signal.ControlSignal;
import java.net.InetAddress;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class SignalRouterTest {
    private static final Instant NOW = Instant.parse("2026-09-25T00:00:00Z");
    private final UUID accountId = UUID.randomUUID();
    private final UUID clientId = UUID.randomUUID();
    private final UUID agentId = UUID.randomUUID();
    private final LinkSessionId sessionId = LinkSessionId.random();
    private final NodeKeyFingerprint clientKey = new NodeKeyFingerprint("11".repeat(32));
    private final NodeKeyFingerprint agentKey = new NodeKeyFingerprint("22".repeat(32));

    @Test
    void authorizesExactPeersAndRoutesSignalsInBothDirections() throws Exception {
        SignalRouter router = router();
        List<ControlSignal> fromAgent = new ArrayList<>();
        List<ControlSignal> fromClient = new ArrayList<>();
        var client = router.register(clientPeer(), fromClient::add);
        var agent = router.register(agentPeer(), fromAgent::add);
        router.authorize(grant());

        assertInstanceOf(ControlSignal.SessionInvite.class, fromAgent.getFirst());
        assertInstanceOf(ControlSignal.SessionInvite.class, fromClient.getFirst());
        long generation = fromAgent.getFirst().generation();
        var clientCandidate = candidate(generation, "192.0.2.10");
        var agentCandidate = candidate(generation, "198.51.100.20");
        router.route(client, clientCandidate);
        router.route(agent, agentCandidate);

        assertEquals(clientCandidate, fromAgent.get(1));
        assertEquals(agentCandidate, fromClient.get(1));
    }

    @Test
    void rejectsCrossAccountPeerAndStaleOrReplayedSignals() throws Exception {
        SignalRouter router = router();
        List<ControlSignal> fromAgent = new ArrayList<>();
        var client = router.register(clientPeer(), ignored -> { });
        router.register(agentPeer(), fromAgent::add);
        var foreignGrant = new SignalRouter.AuthorizedSession(UUID.randomUUID(), sessionId,
                clientId, agentId, clientKey, agentKey, 4, NOW.plusSeconds(90));
        assertThrows(SecurityException.class, () -> router.authorize(foreignGrant));

        router.authorize(grant());
        long generation = fromAgent.getFirst().generation();
        var candidate = candidate(generation, "192.0.2.10");
        assertThrows(SecurityException.class, () -> router.route(client,
                new ControlSignal.IceEnd(UUID.randomUUID(), sessionId, generation + 1)));
        router.route(client, candidate);
        assertThrows(SecurityException.class, () -> router.route(client, candidate));
    }

    @Test
    void reconnectInvalidatesOldSocketAndAdvancesSessionGeneration() {
        SignalRouter router = router();
        List<ControlSignal> firstAgentMessages = new ArrayList<>();
        var oldClient = router.register(clientPeer(), ignored -> { });
        router.register(agentPeer(), firstAgentMessages::add);
        router.authorize(grant());
        long oldGeneration = firstAgentMessages.getFirst().generation();

        router.register(clientPeer(), ignored -> { });
        List<ControlSignal> nextAgentMessages = new ArrayList<>();
        router.register(agentPeer(), nextAgentMessages::add);
        router.authorize(grant());
        assertEquals(oldGeneration + 1, nextAgentMessages.getFirst().generation());
        assertThrows(SecurityException.class, () -> router.route(oldClient,
                new ControlSignal.IceEnd(UUID.randomUUID(), sessionId, oldGeneration)));
    }

    @Test
    void candidateAfterIceEndIsRejected() throws Exception {
        SignalRouter router = router();
        List<ControlSignal> fromAgent = new ArrayList<>();
        var client = router.register(clientPeer(), ignored -> { });
        router.register(agentPeer(), fromAgent::add);
        router.authorize(grant());
        long generation = fromAgent.getFirst().generation();
        router.route(client, new ControlSignal.IceEnd(UUID.randomUUID(), sessionId, generation));
        assertThrows(SecurityException.class, () -> router.route(client, candidate(generation, "192.0.2.10")));
    }

    @Test
    void committedWebsiteGrantWaitsForBothOnlineControlPeers() {
        SignalRouter router = router();
        List<ControlSignal> fromAgent = new ArrayList<>();
        router.authorize(grant());
        assertEquals(0, router.activeSessionCount());

        router.register(clientPeer(), ignored -> { });
        assertEquals(0, router.activeSessionCount());
        router.register(agentPeer(), fromAgent::add);

        assertEquals(1, router.activeSessionCount());
        assertInstanceOf(ControlSignal.SessionInvite.class, fromAgent.getFirst());
    }

    @Test
    void websiteRevocationPushesToBothPeersAndStopsFurtherSignals() {
        SignalRouter router = router();
        List<ControlSignal> fromAgent = new ArrayList<>();
        List<ControlSignal> fromClient = new ArrayList<>();
        var client = router.register(clientPeer(), fromClient::add);
        router.register(agentPeer(), fromAgent::add);
        router.authorize(grant());
        long generation = fromAgent.getFirst().generation();

        router.revoke(sessionId);

        assertInstanceOf(ControlSignal.SessionRevoked.class, fromClient.getLast());
        assertInstanceOf(ControlSignal.SessionRevoked.class, fromAgent.getLast());
        assertThrows(SecurityException.class, () -> router.route(client,
                new ControlSignal.IceEnd(UUID.randomUUID(), sessionId, generation)));
    }

    private SignalRouter router() {
        return new SignalRouter(Clock.fixed(NOW, ZoneOffset.UTC), 16, 16, 32, 256);
    }

    private SignalRouter.ControlPeer clientPeer() {
        return new SignalRouter.ControlPeer(NodeRole.CLIENT, accountId, clientId, null, clientKey);
    }

    private SignalRouter.ControlPeer agentPeer() {
        return new SignalRouter.ControlPeer(NodeRole.AGENT, accountId, agentId, agentId, agentKey);
    }

    private SignalRouter.AuthorizedSession grant() {
        return new SignalRouter.AuthorizedSession(accountId, sessionId, clientId, agentId,
                clientKey, agentKey, 4, NOW.plusSeconds(90));
    }

    private ControlSignal.IceCandidate candidate(long generation, String address) throws Exception {
        return new ControlSignal.IceCandidate(UUID.randomUUID(), sessionId, generation,
                UUID.randomUUID(), ControlSignal.CandidateType.SERVER_REFLEXIVE,
                ControlSignal.Transport.UDP, InetAddress.getByName(address), 19_000, 100,
                "foundation1");
    }
}
