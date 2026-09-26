package com.jlshell.link.server;

import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import java.util.Objects;
import java.util.UUID;

/** Node-level WSS control handshake; it is intentionally not bound to one access tunnel. */
public record ControlHandshake(NodeRole role, UUID nodeId, NodeKeyFingerprint keyFingerprint) {
    public ControlHandshake {
        if (role != NodeRole.CLIENT && role != NodeRole.AGENT) {
            throw new IllegalArgumentException("control role must be CLIENT or AGENT");
        }
        Objects.requireNonNull(nodeId, "nodeId");
        Objects.requireNonNull(keyFingerprint, "keyFingerprint");
    }
}
