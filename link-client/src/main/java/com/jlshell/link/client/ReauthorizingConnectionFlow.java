package com.jlshell.link.client;

import com.jlshell.link.core.model.ConnectPolicy;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Owns one Website authorization session and obtains a fresh grant before its single tunnel attempt. */
public final class ReauthorizingConnectionFlow {
    private final ConnectionCoordinator coordinator;
    private final Clock clock;
    private final AtomicReference<LinkSessionId> sessionId = new AtomicReference<>();
    private final AtomicReference<AccessRequestProvider> accessProvider = new AtomicReference<>();
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean sessionClosed = new AtomicBoolean();

    public ReauthorizingConnectionFlow(ConnectionCoordinator coordinator, Clock clock) {
        this.coordinator = Objects.requireNonNull(coordinator, "coordinator");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** A flow is single-use; each new attempt obtains a new session, tunnel ticket, and JTI. */
    public CompletionStage<ConnectionCoordinator.Connection> connect(
            ConnectionCoordinator.Config config, ConnectPolicy policy, long networkGeneration,
            UUID agentId, TargetEndpoint target, AccessRequestProvider access,
            CarrierPlanFactory plans, ConnectionCoordinator.Observer observer) {
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(plans, "plans");
        if (!started.compareAndSet(false, true)) {
            return CompletableFuture.failedFuture(new IllegalStateException(
                    "A Link authorization session can create only one target tunnel"));
        }
        accessProvider.set(access);
        CompletableFuture<ConnectionCoordinator.Connection> result = new CompletableFuture<>();
        AtomicReference<ConnectionCoordinator.ConnectionAttempt> activeAttempt = new AtomicReference<>();
        CompletionStage<AuthorizedTunnel> pending;
        try {
            pending = Objects.requireNonNull(access.request(Optional.empty(), agentId, target, policy),
                    "access request provider returned null");
        } catch (RuntimeException error) {
            return CompletableFuture.failedFuture(error);
        }
        result.whenComplete((connection, error) -> {
            if (result.isCancelled()) {
                ConnectionCoordinator.ConnectionAttempt attempt = activeAttempt.get();
                if (attempt != null) attempt.cancel();
            }
            if (result.isCancelled() || error != null) closeSession();
        });
        pending.whenComplete((grant, authorizationError) -> {
            if (authorizationError != null) {
                result.completeExceptionally(unwrap(authorizationError));
                return;
            }
            if (grant != null && result.isDone()) {
                sessionId.compareAndSet(null, grant.sessionId());
                closeSession();
                return;
            }
            try {
                if (grant != null) sessionId.compareAndSet(null, grant.sessionId());
                validateGrant(grant, target);
                PathPlan pathPlan = Objects.requireNonNull(plans.create(grant), "path plan factory returned null");
                ConnectionCoordinator.TargetRequest targetRequest = new ConnectionCoordinator.TargetRequest(
                        grant.target(), grant.tunnelId(), grant.accessTicket());
                ConnectionCoordinator.ConnectionAttempt attempt = coordinator.connect(config, policy,
                        networkGeneration, targetRequest, pathPlan.direct(), pathPlan.relay(),
                        pathPlan.targetOpener(), observer);
                activeAttempt.set(attempt);
                if (result.isCancelled()) attempt.cancel();
                attempt.result().whenComplete((connection, connectionError) -> {
                    if (connectionError != null) result.completeExceptionally(unwrap(connectionError));
                    else if (!result.complete(connection)) connection.close();
                });
            } catch (Throwable invalid) {
                result.completeExceptionally(invalid);
            }
        });
        return result;
    }

    public Optional<LinkSessionId> sessionId() {
        return Optional.ofNullable(sessionId.get());
    }

    /** Revokes the one-shot Website session; safe to call from every teardown path. */
    public CompletionStage<Void> closeSession() {
        LinkSessionId current = sessionId.get();
        AccessRequestProvider provider = accessProvider.get();
        if (current == null || provider == null || !sessionClosed.compareAndSet(false, true)) {
            return CompletableFuture.completedFuture(null);
        }
        try {
            return Objects.requireNonNull(provider.closeSession(current), "close session provider returned null");
        } catch (RuntimeException error) {
            return CompletableFuture.failedFuture(error);
        }
    }

    private void validateGrant(AuthorizedTunnel grant, TargetEndpoint requestedTarget) {
        Objects.requireNonNull(grant, "access request returned no grant");
        if (!grant.target().equals(requestedTarget)) throw new SecurityException("Website authorized a different target");
        if (!grant.ticketExpiresAt().isAfter(clock.instant())) {
            throw new SecurityException("Website returned an expired access ticket");
        }
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while ((current instanceof java.util.concurrent.CompletionException
                || current instanceof java.util.concurrent.ExecutionException) && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    @FunctionalInterface
    public interface AccessRequestProvider {
        /** Adapter calls Website POST /api/v2/link/access-requests with sessionId=null for a new tunnel session. */
        CompletionStage<AuthorizedTunnel> request(Optional<LinkSessionId> reuseSessionId,
                UUID agentId, TargetEndpoint target, ConnectPolicy policy);

        /** Revokes the one-shot session on tunnel shutdown. */
        default CompletionStage<Void> closeSession(LinkSessionId sessionId) {
            return CompletableFuture.completedFuture(null);
        }
    }

    @FunctionalInterface
    public interface CarrierPlanFactory {
        PathPlan create(AuthorizedTunnel freshGrant);
    }

    public record PathPlan(ConnectionCoordinator.CarrierConnector direct,
                           ConnectionCoordinator.CarrierConnector relay,
                           ConnectionCoordinator.TargetOpener targetOpener) {
        public PathPlan { Objects.requireNonNull(targetOpener, "targetOpener"); }
    }

    /** Ticket-bearing record deliberately redacts its default string representation. */
    public record AuthorizedTunnel(LinkSessionId sessionId, TunnelId tunnelId, UUID agentId,
                                   NodeKeyFingerprint agentKeyFingerprint, TargetEndpoint target,
                                   String accessTicket, Instant ticketExpiresAt,
                                   Instant authorizationLeaseExpiresAt, long policyVersion) {
        /** Compatibility constructor for existing test adapters; product relay plans require the fingerprint. */
        public AuthorizedTunnel(LinkSessionId sessionId, TunnelId tunnelId, UUID agentId,
                                TargetEndpoint target, String accessTicket, Instant ticketExpiresAt,
                                Instant authorizationLeaseExpiresAt, long policyVersion) {
            this(sessionId, tunnelId, agentId, null, target, accessTicket, ticketExpiresAt,
                    authorizationLeaseExpiresAt, policyVersion);
        }
        public AuthorizedTunnel {
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(tunnelId, "tunnelId");
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(target, "target");
            if (accessTicket == null || accessTicket.isBlank()) throw new IllegalArgumentException("ticket required");
            Objects.requireNonNull(ticketExpiresAt, "ticketExpiresAt");
            Objects.requireNonNull(authorizationLeaseExpiresAt, "authorizationLeaseExpiresAt");
            if (policyVersion < 1) throw new IllegalArgumentException("policyVersion must be positive");
        }
        @Override public String toString() { return "AuthorizedTunnel[<redacted>]"; }
    }
}
