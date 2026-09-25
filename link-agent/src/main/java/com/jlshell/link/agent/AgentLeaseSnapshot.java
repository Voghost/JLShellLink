package com.jlshell.link.agent;

import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Last authoritative Website heartbeat state used to gate new target streams. */
public record AgentLeaseSnapshot(UUID agentId, NodeKeyFingerprint agentKeyFingerprint,
                                 long policyVersion, Instant leaseExpiresAt, boolean revoked) {
    public AgentLeaseSnapshot {
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(agentKeyFingerprint, "agentKeyFingerprint");
        if (policyVersion < 1) throw new IllegalArgumentException("policyVersion must be positive");
        Objects.requireNonNull(leaseExpiresAt, "leaseExpiresAt");
    }

    public boolean permitsNewStreams(Instant now) {
        return !revoked && leaseExpiresAt.isAfter(Objects.requireNonNull(now, "now"));
    }
}
