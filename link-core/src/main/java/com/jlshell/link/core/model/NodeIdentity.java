package com.jlshell.link.core.model;

import java.util.Objects;
import java.util.UUID;

/** Public node identity. Private key material is intentionally absent. */
public record NodeIdentity(UUID nodeId, NodeRole role, NodeKeyFingerprint keyFingerprint) {
    public NodeIdentity {
        Objects.requireNonNull(nodeId, "nodeId");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(keyFingerprint, "keyFingerprint");
    }
}
