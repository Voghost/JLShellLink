package com.jlshell.link.server;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.model.TunnelId;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class RelayChallengeStoreTest {
    @Test
    void proofIsBoundToHandshakeAndConsumedOnce() throws Exception {
        var key = Ed25519NodeKey.generate();
        UUID agentId = UUID.randomUUID();
        var session = LinkSessionId.random();
        var handshake = new RelayHandshake(NodeRole.AGENT, agentId, agentId, session,
                TunnelId.random(), key.fingerprint());
        var principal = new RelayControlAuthenticator.AuthenticatedPeer(NodeRole.AGENT,
                UUID.randomUUID(), agentId, agentId, key.fingerprint(), key.publicKey(),
                new NodeKeyFingerprint("1".repeat(64)), key.fingerprint(),
                java.time.Instant.now().plusSeconds(60));
        var store = new RelayChallengeStore(new java.security.SecureRandom(), new NodeProofService(),
                Clock.systemUTC(), Duration.ofSeconds(30), 4);
        var challenge = store.issue(handshake, principal);
        byte[] nonce = Base64.getUrlDecoder().decode(challenge.challenge());
        byte[] signature = new NodeProofService().sign(key, new NodeProofContext("relay-control", agentId,
                Optional.of(session)), nonce);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);

        assertTrue(store.consume(challenge.challengeId(), handshake, principal, encoded));
        assertFalse(store.consume(challenge.challengeId(), handshake, principal, encoded));

        var next = store.issue(handshake, principal);
        var altered = new RelayHandshake(NodeRole.AGENT, agentId, agentId, session,
                TunnelId.random(), key.fingerprint());
        byte[] secondNonce = Base64.getUrlDecoder().decode(next.challenge());
        byte[] wrongContextSignature = new NodeProofService().sign(key,
                new NodeProofContext("relay-control", agentId, Optional.of(session)), secondNonce);
        assertFalse(store.consume(next.challengeId(), altered, principal,
                Base64.getUrlEncoder().withoutPadding().encodeToString(wrongContextSignature)));
    }
}
