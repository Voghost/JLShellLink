package com.jlshell.link.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeIdentity;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.model.TunnelId;
import io.netty.channel.embedded.EmbeddedChannel;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class RelayPairingServiceTest {
    @Test
    void pairsOnlyOneClientAndOnlineExpectedAgentForSameAccountAndTunnel() throws Exception {
        var clock = Clock.systemUTC();
        UUID account = UUID.randomUUID();
        UUID agentId = UUID.randomUUID();
        LinkSessionId session = LinkSessionId.random();
        TunnelId tunnel = TunnelId.random();
        var clientKey = Ed25519NodeKey.generate();
        var agentKey = Ed25519NodeKey.generate();
        var nodes = new NodeConnectionRegistry(clock);
        var scheduler = Executors.newSingleThreadScheduledExecutor();
        var service = new RelayPairingService(nodes, scheduler, clock, 8, 1024);
        EmbeddedChannel clientChannel = new EmbeddedChannel();
        EmbeddedChannel agentChannel = new EmbeddedChannel();
        try {
            var client = new RelayPairingService.AuthorizedPeer(NodeRole.CLIENT, account, agentId,
                    session, tunnel, clientKey.fingerprint(), clientKey.fingerprint(), agentKey.fingerprint(),
                    Instant.now().plusSeconds(30));
            var agent = new RelayPairingService.AuthorizedPeer(NodeRole.AGENT, account, agentId,
                    session, tunnel, agentKey.fingerprint(), clientKey.fingerprint(), agentKey.fingerprint(),
                    client.ticketExpiresAt());
            var first = service.join(client, clientChannel);
            var second = service.join(agent, agentChannel);
            var pair = first.toCompletableFuture().get(1, TimeUnit.SECONDS);
            assertEquals(pair, second.toCompletableFuture().get(1, TimeUnit.SECONDS));
            assertEquals(clientChannel, pair.aChannel());
            assertEquals(agentChannel, pair.cChannel());
            assertTrue(nodes.findOnline(agentId).isPresent(),
                    "pairing must register the authenticated, live Agent channel");

            EmbeddedChannel duplicate = new EmbeddedChannel();
            try {
                assertThrows(RejectedExecutionException.class, () -> service.join(client, duplicate));
            } finally {
                duplicate.finishAndReleaseAll();
            }
        } finally {
            service.close();
            clientChannel.finishAndReleaseAll();
            agentChannel.finishAndReleaseAll();
            scheduler.shutdownNow();
        }
        assertTrue(nodes.findOnline(agentId).isEmpty(),
                "closing the authenticated Agent channel must clear its online lease");
    }

    @Test
    void staleConnectionCannotRemoveNewOnlineGeneration() throws Exception {
        NodeConnectionRegistry registry = new NodeConnectionRegistry(Clock.systemUTC());
        UUID id = UUID.randomUUID();
        UUID account = UUID.randomUUID();
        var key = Ed25519NodeKey.generate();
        var identity = new NodeIdentity(id, NodeRole.AGENT, key.fingerprint());
        var old = registry.register(identity, account, UUID.randomUUID(), Instant.now().plusSeconds(60));
        var current = registry.register(identity, account, UUID.randomUUID(), Instant.now().plusSeconds(90));

        registry.unregister(old);
        assertTrue(registry.findOnline(id).isPresent());
        assertTrue(registry.heartbeat(current, Instant.now().plusSeconds(120)));
    }
}
