package com.jlshell.link.core.model;

import com.jlshell.link.core.ProtocolVersion;
import java.net.URI;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public record AccessGrant(
        URI issuer,
        String audience,
        UUID accountId,
        LinkSessionId sessionId,
        TunnelId tunnelId,
        NodeKeyFingerprint clientKeyFingerprint,
        UUID agentId,
        NodeKeyFingerprint agentKeyFingerprint,
        TargetEndpoint target,
        Set<String> capabilities,
        long policyVersion,
        String jti,
        Instant issuedAt,
        Instant notBefore,
        Instant expiresAt,
        String protocolVersion) {

    public AccessGrant {
        Objects.requireNonNull(issuer, "issuer");
        if (!issuer.isAbsolute()) throw new IllegalArgumentException("Issuer must be absolute");
        if (audience == null || audience.isBlank()) throw new IllegalArgumentException("Audience is required");
        Objects.requireNonNull(accountId, "accountId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(tunnelId, "tunnelId");
        Objects.requireNonNull(clientKeyFingerprint, "clientKeyFingerprint");
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(agentKeyFingerprint, "agentKeyFingerprint");
        Objects.requireNonNull(target, "target");
        capabilities = Set.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
        if (capabilities.isEmpty() || capabilities.stream().anyMatch(String::isBlank)) {
            throw new IllegalArgumentException("At least one non-blank capability is required");
        }
        if (policyVersion < 1) throw new IllegalArgumentException("Policy version must be positive");
        if (jti == null || jti.isBlank()) throw new IllegalArgumentException("jti is required");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(notBefore, "notBefore");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (expiresAt.isBefore(notBefore) || notBefore.isBefore(issuedAt.minusSeconds(1))) {
            throw new IllegalArgumentException("Grant timestamps are inconsistent");
        }
        if (!ProtocolVersion.V2.equals(protocolVersion)) {
            throw new IllegalArgumentException("Unsupported protocol version");
        }
    }
}
