package com.jlshell.link.server;

import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletionStage;

/** Website adapter boundary. Implementations must re-check current tunnel, account, ticket and online Agent state. */
@FunctionalInterface
public interface RelayControlAuthenticator {
    CompletionStage<AuthenticatedPeer> authenticate(RelayHandshake handshake, String bearerCredential);

    record AuthenticatedPeer(NodeRole role, UUID accountId, UUID nodeId, UUID agentId,
                             NodeKeyFingerprint keyFingerprint, PublicKey nodePublicKey,
                             NodeKeyFingerprint clientKeyFingerprint,
                             NodeKeyFingerprint agentKeyFingerprint,
                             Instant ticketExpiresAt) {
        public AuthenticatedPeer {
            if (role != NodeRole.CLIENT && role != NodeRole.AGENT) {
                throw new IllegalArgumentException("relay role must be CLIENT or AGENT");
            }
            Objects.requireNonNull(accountId, "accountId");
            Objects.requireNonNull(nodeId, "nodeId");
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(keyFingerprint, "keyFingerprint");
            Objects.requireNonNull(nodePublicKey, "nodePublicKey");
            Objects.requireNonNull(clientKeyFingerprint, "clientKeyFingerprint");
            Objects.requireNonNull(agentKeyFingerprint, "agentKeyFingerprint");
            Objects.requireNonNull(ticketExpiresAt, "ticketExpiresAt");
            if (!NodeKeyFingerprint.from(nodePublicKey).equals(keyFingerprint)) {
                throw new IllegalArgumentException("public key does not match authenticated fingerprint");
            }
            if (role == NodeRole.CLIENT && !keyFingerprint.equals(clientKeyFingerprint)) {
                throw new IllegalArgumentException("client key does not match current access request");
            }
            if (role == NodeRole.AGENT && !keyFingerprint.equals(agentKeyFingerprint)) {
                throw new IllegalArgumentException("Agent key does not match current access request");
            }
        }

        boolean matches(RelayHandshake handshake) {
            return role == handshake.role() && nodeId.equals(handshake.nodeId())
                    && agentId.equals(handshake.agentId()) && keyFingerprint.equals(handshake.keyFingerprint());
        }
    }
}
