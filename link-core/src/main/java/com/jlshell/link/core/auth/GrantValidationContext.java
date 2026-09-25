package com.jlshell.link.core.auth;

import com.jlshell.link.core.ProtocolVersion;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import java.net.URI;
import java.util.Objects;
import java.util.UUID;

public record GrantValidationContext(
        URI issuer,
        String audience,
        LinkSessionId sessionId,
        TunnelId tunnelId,
        NodeKeyFingerprint clientKeyFingerprint,
        UUID agentId,
        NodeKeyFingerprint agentKeyFingerprint,
        TargetEndpoint target,
        String protocolVersion) {
    public GrantValidationContext {
        Objects.requireNonNull(issuer, "issuer");
        if (audience == null || audience.isBlank()) throw new IllegalArgumentException("Audience is required");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(tunnelId, "tunnelId");
        Objects.requireNonNull(clientKeyFingerprint, "clientKeyFingerprint");
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(agentKeyFingerprint, "agentKeyFingerprint");
        Objects.requireNonNull(target, "target");
        if (!ProtocolVersion.V2.equals(protocolVersion)) throw new IllegalArgumentException("Unsupported protocol");
    }
}
