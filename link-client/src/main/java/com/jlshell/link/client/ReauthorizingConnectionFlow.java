package com.jlshell.link.client;

import com.jlshell.link.core.model.ConnectPolicy;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;

/** Obtains a fresh Website grant before every new tunnel, including every reconnect after a drop. */
public final class ReauthorizingConnectionFlow {
    private final ConnectionCoordinator coordinator;
    private final Clock clock;
    private final AtomicReference<LinkSessionId> sessionId = new AtomicReference<>();

    public ReauthorizingConnectionFlow(ConnectionCoordinator coordinator, Clock clock) {
        this.coordinator = Objects.requireNonNull(coordinator, "coordinator");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Every invocation requests a new tunnel ticket; the old tunnelId/JTI is never reused. */
    public CompletionStage<ConnectionCoordinator.Connection> connect(
            ConnectionCoordinator.Config config, ConnectPolicy policy, long networkGeneration,
            UUID agentId, TargetEndpoint target, AccessRequestProvider access,
            CarrierPlanFactory plans, ConnectionCoordinator.Observer observer) {
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(plans, "plans");
        LinkSessionId reuse = sessionId.get();
        CompletableFuture<ConnectionCoordinator.Connection> result = new CompletableFuture<>();
        CompletionStage<AuthorizedTunnel> pending;
        try {
            pending = Objects.requireNonNull(access.request(Optional.ofNullable(reuse), agentId, target, policy),
                    "access request provider returned null");
        } catch (RuntimeException error) {
            return CompletableFuture.failedFuture(error);
        }
        pending.whenComplete((grant, authorizationError) -> {
            if (authorizationError != null) {
                result.completeExceptionally(unwrap(authorizationError));
                return;
            }
            try {
                validateGrant(grant, reuse, target);
                sessionId.compareAndSet(null, grant.sessionId());
                if (!grant.sessionId().equals(sessionId.get())) {
                    throw new SecurityException("Concurrent access request created a different session");
                }
                PathPlan pathPlan = Objects.requireNonNull(plans.create(grant), "path plan factory returned null");
                ConnectionCoordinator.TargetRequest targetRequest = new ConnectionCoordinator.TargetRequest(
                        grant.target(), grant.tunnelId(), grant.accessTicket());
                ConnectionCoordinator.ConnectionAttempt attempt = coordinator.connect(config, policy,
                        networkGeneration, targetRequest, pathPlan.direct(), pathPlan.relay(),
                        pathPlan.targetOpener(), observer);
                attempt.result().whenComplete((connection, connectionError) -> {
                    if (connectionError != null) result.completeExceptionally(unwrap(connectionError));
                    else result.complete(connection);
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

    private void validateGrant(AuthorizedTunnel grant, LinkSessionId prior, TargetEndpoint requestedTarget) {
        Objects.requireNonNull(grant, "access request returned no grant");
        if (!grant.target().equals(requestedTarget)) throw new SecurityException("Website authorized a different target");
        if (prior != null && !prior.equals(grant.sessionId())) {
            throw new SecurityException("Website returned a different reused session");
        }
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
        /** Adapter calls Website POST /api/v2/link/access-requests using the current short control credential. */
        CompletionStage<AuthorizedTunnel> request(Optional<LinkSessionId> reuseSessionId,
                UUID agentId, TargetEndpoint target, ConnectPolicy policy);
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
                                   TargetEndpoint target, String accessTicket, Instant ticketExpiresAt,
                                   Instant authorizationLeaseExpiresAt, long policyVersion) {
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
