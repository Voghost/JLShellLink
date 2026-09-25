package com.jlshell.link.core.model;

import java.time.Instant;
import java.util.Objects;

public record AuthorizationLease(
        LinkSessionId sessionId,
        TunnelId tunnelId,
        NodeKeyFingerprint clientKeyFingerprint,
        NodeKeyFingerprint agentKeyFingerprint,
        long policyVersion,
        Instant validUntil) {
    public AuthorizationLease {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(tunnelId, "tunnelId");
        Objects.requireNonNull(clientKeyFingerprint, "clientKeyFingerprint");
        Objects.requireNonNull(agentKeyFingerprint, "agentKeyFingerprint");
        if (policyVersion < 1) throw new IllegalArgumentException("Policy version must be positive");
        Objects.requireNonNull(validUntil, "validUntil");
    }
}
