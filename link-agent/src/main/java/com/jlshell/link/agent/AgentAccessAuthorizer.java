package com.jlshell.link.agent;

import com.jlshell.link.core.ProtocolVersion;
import com.jlshell.link.core.auth.AccessGrantJwsService;
import com.jlshell.link.core.auth.AccessPolicyEvaluator;
import com.jlshell.link.core.auth.GrantValidationContext;
import com.jlshell.link.core.auth.SigningKeyResolver;
import com.jlshell.link.core.auth.TicketValidationException;
import com.jlshell.link.core.model.AccessPolicy;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.transport.ConnectStreamMultiplexer;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Fail-closed C-side authorization gate. A CONNECT is not allowed to reach the
 * target connector until the signed grant, live control lease and local ACL all
 * pass. Ticket validation consumes jti atomically exactly once.
 */
public final class AgentAccessAuthorizer implements ConnectStreamMultiplexer.AccessAuthorizer {
    private final URI issuer;
    private final UUIDBinding binding;
    private final AccessGrantJwsService grants;
    private final SigningKeyResolver signingKeys;
    private final AccessPolicyEvaluator policies;
    private final AccessPolicy localPolicy;
    private final AtomicReference<AgentLeaseSnapshot> lease;
    private final AtomicReference<Instant> authorizationLeaseExpiresAt;
    private final Clock clock;
    private final Executor authorizationExecutor;
    private final Consumer<String> auditCode;

    public AgentAccessAuthorizer(URI issuer, UUIDBinding binding, AccessGrantJwsService grants,
            SigningKeyResolver signingKeys, AccessPolicy localPolicy, AgentLeaseSnapshot initialLease,
            Clock clock, Executor authorizationExecutor, Consumer<String> auditCode) {
        this(issuer, binding, grants, signingKeys, localPolicy, initialLease,
                initialLease.leaseExpiresAt(), clock, authorizationExecutor, auditCode);
    }

    public AgentAccessAuthorizer(URI issuer, UUIDBinding binding, AccessGrantJwsService grants,
            SigningKeyResolver signingKeys, AccessPolicy localPolicy, AgentLeaseSnapshot initialLease,
            Instant authorizationLeaseExpiresAt, Clock clock, Executor authorizationExecutor,
            Consumer<String> auditCode) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        if (!issuer.isAbsolute() || !"https".equalsIgnoreCase(issuer.getScheme())) {
            throw new IllegalArgumentException("Website issuer must be an absolute HTTPS URI");
        }
        this.binding = Objects.requireNonNull(binding, "binding");
        this.grants = Objects.requireNonNull(grants, "grants");
        this.signingKeys = Objects.requireNonNull(signingKeys, "signingKeys");
        this.localPolicy = Objects.requireNonNull(localPolicy, "localPolicy");
        this.lease = new AtomicReference<>(Objects.requireNonNull(initialLease, "initialLease"));
        this.authorizationLeaseExpiresAt = new AtomicReference<>(
                Objects.requireNonNull(authorizationLeaseExpiresAt, "authorizationLeaseExpiresAt"));
        this.clock = Objects.requireNonNull(clock, "clock");
        this.authorizationExecutor = Objects.requireNonNull(authorizationExecutor, "authorizationExecutor");
        this.auditCode = auditCode == null ? ignored -> { } : auditCode;
        this.policies = new AccessPolicyEvaluator();
        if (!initialLease.agentId().equals(binding.agentId())
                || !initialLease.agentKeyFingerprint().equals(binding.agentKeyFingerprint())) {
            throw new IllegalArgumentException("Lease snapshot does not match the Agent identity");
        }
    }

    @Override
    public CompletionStage<Boolean> authorize(ConnectStreamMultiplexer.AuthorizationRequest request) {
        Objects.requireNonNull(request, "request");
        return CompletableFuture.supplyAsync(() -> authorizeNow(request), authorizationExecutor);
    }

    /** Atomically replaces the Website lease snapshot after an authenticated heartbeat/revocation poll. */
    public void updateLease(AgentLeaseSnapshot next) {
        Objects.requireNonNull(next, "next");
        if (!next.agentId().equals(binding.agentId())
                || !next.agentKeyFingerprint().equals(binding.agentKeyFingerprint())) {
            throw new IllegalArgumentException("Lease update does not match the Agent identity");
        }
        lease.updateAndGet(previous -> {
            if (next.policyVersion() < previous.policyVersion()) {
                throw new IllegalArgumentException("Policy version cannot move backwards");
            }
            if (previous.revoked() && !next.revoked()) {
                throw new IllegalArgumentException("A revoked Agent identity cannot be reactivated in place");
            }
            return next;
        });
    }

    public AgentLeaseSnapshot leaseSnapshot() {
        return lease.get();
    }

    /** Extends this tunnel's independent user authorization lease after an authenticated Website poll. */
    public void updateAuthorizationLease(Instant expiresAt) {
        Objects.requireNonNull(expiresAt, "expiresAt");
        authorizationLeaseExpiresAt.updateAndGet(previous -> expiresAt.isAfter(previous) ? expiresAt : previous);
    }

    private boolean authorizeNow(ConnectStreamMultiplexer.AuthorizationRequest request) {
        AgentLeaseSnapshot current = lease.get();
        Instant now = clock.instant();
        if (!current.permitsNewStreams(now)) return deny("agent-control-lease-inactive");
        if (!authorizationLeaseExpiresAt.get().isAfter(now)) return deny("authorization-lease-inactive");
        try {
            GrantValidationContext expected = new GrantValidationContext(issuer, "jlshell-link-agent",
                    binding.sessionId(), request.tunnelId(), binding.clientKeyFingerprint(), binding.agentId(),
                    binding.agentKeyFingerprint(), request.target(), ProtocolVersion.V2);
            grants.validate(request.accessTicket(), expected, signingKeys, grant ->
                    grant.policyVersion() == current.policyVersion()
                            && grant.capabilities().contains("tcp-connect")
                            && policies.isAllowed(localPolicy, request.target()));
            return true;
        } catch (TicketValidationException | RuntimeException rejected) {
            return deny("access-ticket-rejected");
        }
    }

    private boolean deny(String safeCode) {
        try {
            auditCode.accept(safeCode);
        } catch (RuntimeException ignored) {
            // Auditing is best-effort; an audit sink failure must not turn deny into allow.
        }
        return false;
    }

    /** Expected authenticated identities for the current inner A—C session. */
    public record UUIDBinding(LinkSessionId sessionId, java.util.UUID agentId,
                              NodeKeyFingerprint clientKeyFingerprint,
                              NodeKeyFingerprint agentKeyFingerprint) {
        public UUIDBinding {
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(clientKeyFingerprint, "clientKeyFingerprint");
            Objects.requireNonNull(agentKeyFingerprint, "agentKeyFingerprint");
        }
    }
}
