package com.jlshell.link.server;

import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import java.security.PublicKey;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletionStage;

/** Website boundary for node credentials; implementations must re-check ownership, revocation and expiry. */
@FunctionalInterface
public interface ControlPeerAuthenticator {
    CompletionStage<AuthenticatedPeer> authenticate(ControlHandshake handshake, String bearerCredential);

    record AuthenticatedPeer(NodeRole role, UUID accountId, UUID nodeId, UUID agentId,
                             NodeKeyFingerprint keyFingerprint, PublicKey nodePublicKey) {
        public AuthenticatedPeer {
            if (role != NodeRole.CLIENT && role != NodeRole.AGENT) {
                throw new IllegalArgumentException("control role must be CLIENT or AGENT");
            }
            Objects.requireNonNull(accountId, "accountId");
            Objects.requireNonNull(nodeId, "nodeId");
            Objects.requireNonNull(keyFingerprint, "keyFingerprint");
            Objects.requireNonNull(nodePublicKey, "nodePublicKey");
            if (!NodeKeyFingerprint.from(nodePublicKey).equals(keyFingerprint)) {
                throw new IllegalArgumentException("public key does not match authenticated fingerprint");
            }
            if (role == NodeRole.AGENT && (agentId == null || !agentId.equals(nodeId))) {
                throw new IllegalArgumentException("Agent control identity is invalid");
            }
            if (role == NodeRole.CLIENT && agentId != null) {
                throw new IllegalArgumentException("client control identity cannot bind to one Agent");
            }
        }
        boolean matches(ControlHandshake handshake) {
            return role == handshake.role() && nodeId.equals(handshake.nodeId())
                    && keyFingerprint.equals(handshake.keyFingerprint());
        }
    }
}
