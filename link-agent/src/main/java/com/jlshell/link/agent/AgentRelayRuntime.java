package com.jlshell.link.agent;

import com.jlshell.link.core.auth.AccessGrantJwsService;
import com.jlshell.link.core.auth.SigningKeyResolver;
import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.model.AccessPolicy;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.ConnectStreamMultiplexer;
import com.jlshell.link.transport.TlsHandshakeGate;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import javax.net.ssl.SSLContext;

/** C-side relay-only runtime: opens a ticket-bound outbound WSS carrier when Website activates a relay request. */
public final class AgentRelayRuntime implements AutoCloseable {
    private final URI relayUri;
    private final String agentCredential;
    private final java.util.UUID agentId;
    private final LocalNodeKey nodeKey;
    private final SSLContext outerTls;
    private final Function<NodeKeyFingerprint, SSLContext> innerTlsForClient;
    private final Function<AgentControlPlaneClient.RelayOpenRequest, AccessPolicy> localPolicy;
    private final EventLoopGroup eventLoops;
    private final AccessGrantJwsService grants;
    private final SigningKeyResolver signingKeys;
    private final URI ticketIssuer;
    private final AgentLeaseSnapshot initialLease;
    private final RelayProofClient relayProof;
    private final TransportBudget budget;
    private final TlsHandshakeGate handshakeGate;
    private final Clock clock;
    private final ConcurrentMap<TunnelId, ActiveRelay> active = new ConcurrentHashMap<>();
    private final ConcurrentMap<TunnelId, java.time.Instant> completed = new ConcurrentHashMap<>();
    private final AtomicReference<AgentLeaseSnapshot> lease;
    private volatile boolean closed;

    public AgentRelayRuntime(URI relayUri, String agentCredential, java.util.UUID agentId,
            LocalNodeKey nodeKey, SSLContext outerTls,
            Function<NodeKeyFingerprint, SSLContext> innerTlsForClient,
            Function<AgentControlPlaneClient.RelayOpenRequest, AccessPolicy> localPolicy,
            EventLoopGroup eventLoops, AccessGrantJwsService grants, SigningKeyResolver signingKeys,
            URI ticketIssuer,
            AgentLeaseSnapshot initialLease, RelayProofClient relayProof, TransportBudget budget,
            TlsHandshakeGate handshakeGate, Clock clock) {
        this.relayUri = Objects.requireNonNull(relayUri, "relayUri");
        if (!"wss".equalsIgnoreCase(relayUri.getScheme()) || relayUri.getHost() == null
                || relayUri.getUserInfo() != null || relayUri.getRawQuery() != null
                || relayUri.getRawFragment() != null || !"/link/v2/relay".equals(relayUri.getPath())) {
            throw new IllegalArgumentException("Relay endpoint must be the configured WSS Link relay path");
        }
        if (agentCredential == null || agentCredential.isBlank()) throw new IllegalArgumentException("credential required");
        this.agentCredential = agentCredential;
        this.agentId = Objects.requireNonNull(agentId, "agentId");
        this.nodeKey = Objects.requireNonNull(nodeKey, "nodeKey");
        this.outerTls = Objects.requireNonNull(outerTls, "outerTls");
        this.innerTlsForClient = Objects.requireNonNull(innerTlsForClient, "innerTlsForClient");
        this.localPolicy = Objects.requireNonNull(localPolicy, "localPolicy");
        this.eventLoops = Objects.requireNonNull(eventLoops, "eventLoops");
        this.grants = Objects.requireNonNull(grants, "grants");
        this.signingKeys = Objects.requireNonNull(signingKeys, "signingKeys");
        this.ticketIssuer = Objects.requireNonNull(ticketIssuer, "ticketIssuer");
        if (!"https".equalsIgnoreCase(ticketIssuer.getScheme()) || ticketIssuer.getHost() == null
                || ticketIssuer.getUserInfo() != null || ticketIssuer.getQuery() != null
                || ticketIssuer.getFragment() != null) {
            throw new IllegalArgumentException("ticket issuer must be an HTTPS origin");
        }
        this.initialLease = Objects.requireNonNull(initialLease, "initialLease");
        if (!agentId.equals(initialLease.agentId())
                || !nodeKey.fingerprint().equals(initialLease.agentKeyFingerprint())) {
            throw new IllegalArgumentException("Agent identity does not match current Website lease");
        }
        this.lease = new AtomicReference<>(initialLease);
        this.relayProof = Objects.requireNonNull(relayProof, "relayProof");
        this.budget = Objects.requireNonNull(budget, "budget");
        this.handshakeGate = Objects.requireNonNull(handshakeGate, "handshakeGate");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public CompletionStage<Void> open(AgentControlPlaneClient.RelayOpenRequest request) {
        Objects.requireNonNull(request, "request");
        if (closed) return CompletableFuture.failedFuture(new IllegalStateException("Agent relay runtime is closed"));
        if (!request.agentId().equals(agentId)
                || !request.agentKeyFingerprint().equals(nodeKey.fingerprint().value())) {
            return CompletableFuture.failedFuture(new SecurityException("Website relay request identity is invalid"));
        }
        TunnelId tunnelId = TunnelId.parse(request.tunnelId().toString());
        LinkSessionId sessionId = LinkSessionId.parse(request.sessionId().toString());
        java.time.Instant now = clock.instant();
        if (!request.authorizationLeaseExpiresAt().isAfter(now)) {
            closeTunnel(tunnelId);
            return CompletableFuture.failedFuture(new SecurityException("Website authorization lease expired"));
        }
        ActiveRelay existing = active.get(tunnelId);
        if (existing != null && existing.channel().isActive()) {
            if (!existing.matches(request)) {
                closeTunnel(tunnelId);
                return CompletableFuture.failedFuture(new SecurityException(
                        "Website changed the binding of an active Link tunnel"));
            }
            existing.renew(request.authorizationLeaseExpiresAt(), eventLoops.next(), clock,
                    () -> closeTunnel(tunnelId));
            completed.put(tunnelId, existing.authorizationLeaseExpiresAt());
            return CompletableFuture.completedFuture(null);
        }
        if (!request.ticketExpiresAt().isAfter(now)) {
            return CompletableFuture.failedFuture(new SecurityException("Website relay ticket expired before opening"));
        }
        completed.entrySet().removeIf(entry -> !entry.getValue().isAfter(clock.instant()));
        if (completed.containsKey(tunnelId)) {
            return CompletableFuture.failedFuture(new SecurityException("Website relay tunnel was already opened"));
        }

        NodeKeyFingerprint clientFingerprint = new NodeKeyFingerprint(request.clientKeyFingerprint());
        NodeKeyFingerprint agentFingerprint = new NodeKeyFingerprint(request.agentKeyFingerprint());
        AgentLeaseSnapshot snapshot = lease.get();
        if (!snapshot.permitsNewStreams(clock.instant()) || request.policyVersion() != snapshot.policyVersion()) {
            return CompletableFuture.failedFuture(new SecurityException("Website authorization state is stale"));
        }
        AgentAccessAuthorizer authorizer = new AgentAccessAuthorizer(
                ticketIssuer,
                new AgentAccessAuthorizer.UUIDBinding(sessionId, agentId, clientFingerprint, agentFingerprint),
                grants, signingKeys, Objects.requireNonNull(localPolicy.apply(request), "local policy"),
                snapshot, request.authorizationLeaseExpiresAt(), clock,
                java.util.concurrent.ForkJoinPool.commonPool(), ignored -> { });
        ConnectStreamMultiplexer multiplexer = new ConnectStreamMultiplexer(budget,
                new TransportBufferBudget(budget.maxBufferedBytesTotal()), authorizer,
                ConnectStreamMultiplexer.tcpConnector(budget));
        SSLContext innerTls = Objects.requireNonNull(innerTlsForClient.apply(clientFingerprint), "inner TLS context");
        String tlsPeerHost = "jlshell-client-" + clientFingerprint.value();
        var connecting = relayProof.connectGateway(eventLoops, relayUri, agentCredential, agentId,
                sessionId, tunnelId, nodeKey, outerTls, innerTls, tlsPeerHost, 443,
                budget, handshakeGate, multiplexer);
        CompletableFuture<Void> opened = new CompletableFuture<>();
        connecting.whenComplete((channel, error) -> {
            if (error != null || channel == null) {
                opened.completeExceptionally(error == null
                        ? new IllegalStateException("WSS relay returned no channel") : error);
                return;
            }
            if (closed || !lease.get().permitsNewStreams(clock.instant())
                    || !request.authorizationLeaseExpiresAt().isAfter(clock.instant())) {
                channel.close();
                opened.completeExceptionally(new SecurityException("Link authorization lease expired"));
                return;
            }
            ActiveRelay relay = new ActiveRelay(channel, multiplexer, authorizer, request);
            ActiveRelay previous = active.putIfAbsent(tunnelId, relay);
            if (previous != null) {
                channel.close();
                if (previous.channel().isActive()) {
                    if (!previous.matches(request)) {
                        closeTunnel(tunnelId);
                        opened.completeExceptionally(new SecurityException(
                                "Website changed the binding of an active Link tunnel"));
                        return;
                    }
                    previous.renew(request.authorizationLeaseExpiresAt(), eventLoops.next(), clock,
                            () -> closeTunnel(tunnelId));
                    completed.put(tunnelId, previous.authorizationLeaseExpiresAt());
                }
                opened.complete(null);
                return;
            }
            relay.renew(request.authorizationLeaseExpiresAt(), eventLoops.next(), clock,
                    () -> closeTunnel(tunnelId));
            completed.put(tunnelId, relay.authorizationLeaseExpiresAt());
            channel.closeFuture().addListener(ignored -> active.remove(tunnelId, relay));
            opened.complete(null);
        });
        return opened;
    }

    public void updateLease(AgentLeaseSnapshot next) {
        Objects.requireNonNull(next, "next");
        if (!next.agentId().equals(agentId) || !next.agentKeyFingerprint().equals(nodeKey.fingerprint())) {
            throw new IllegalArgumentException("Website lease update has another Agent identity");
        }
        lease.updateAndGet(previous -> {
            if (next.policyVersion() < previous.policyVersion()) {
                throw new IllegalArgumentException("Policy version cannot move backwards");
            }
            return next;
        });
        active.values().forEach(relay -> relay.authorizer().updateLease(next));
        if (next.revoked()) closeAll();
    }

    public void closeAll() {
        active.values().forEach(relay -> {
            relay.multiplexer().closeAllAuthorizedStreams();
            relay.cancelLeaseExpiry();
            relay.channel().close();
        });
        active.clear();
        completed.clear();
    }

    /** Closes exactly one session/tunnel when Website stops listing its active lease. */
    public void closeTunnel(TunnelId tunnelId) {
        ActiveRelay relay = active.remove(Objects.requireNonNull(tunnelId, "tunnelId"));
        if (relay == null) return;
        relay.cancelLeaseExpiry();
        relay.multiplexer().closeAllAuthorizedStreams();
        relay.channel().close();
    }

    @Override
    public void close() {
        if (closed) return;
        closed = true;
        closeAll();
    }

    private static final class ActiveRelay {
        private final Channel channel;
        private final ConnectStreamMultiplexer multiplexer;
        private final AgentAccessAuthorizer authorizer;
        private final AgentControlPlaneClient.RelayOpenRequest binding;
        private volatile java.time.Instant authorizationLeaseExpiresAt = java.time.Instant.EPOCH;
        private volatile ScheduledFuture<?> leaseExpiry;

        private ActiveRelay(Channel channel, ConnectStreamMultiplexer multiplexer,
                            AgentAccessAuthorizer authorizer,
                            AgentControlPlaneClient.RelayOpenRequest binding) {
            this.channel = channel;
            this.multiplexer = multiplexer;
            this.authorizer = authorizer;
            this.binding = binding;
        }

        private Channel channel() { return channel; }
        private ConnectStreamMultiplexer multiplexer() { return multiplexer; }
        private AgentAccessAuthorizer authorizer() { return authorizer; }
        private java.time.Instant authorizationLeaseExpiresAt() { return authorizationLeaseExpiresAt; }
        private boolean matches(AgentControlPlaneClient.RelayOpenRequest next) {
            return binding.sessionId().equals(next.sessionId())
                    && binding.agentId().equals(next.agentId())
                    && binding.clientKeyFingerprint().equals(next.clientKeyFingerprint())
                    && binding.agentKeyFingerprint().equals(next.agentKeyFingerprint())
                    && binding.targetIp().equals(next.targetIp())
                    && binding.targetPort() == next.targetPort()
                    && binding.policyVersion() == next.policyVersion();
        }

        private synchronized void renew(java.time.Instant expiresAt,
                java.util.concurrent.ScheduledExecutorService scheduler, Clock clock, Runnable expire) {
            if (expiresAt.isAfter(authorizationLeaseExpiresAt)) authorizationLeaseExpiresAt = expiresAt;
            authorizer.updateAuthorizationLease(authorizationLeaseExpiresAt);
            ScheduledFuture<?> previous = leaseExpiry;
            if (previous != null) previous.cancel(false);
            java.time.Instant scheduledExpiry = authorizationLeaseExpiresAt;
            long delay = Math.max(0, scheduledExpiry.toEpochMilli() - clock.millis());
            leaseExpiry = scheduler.schedule(() -> {
                synchronized (ActiveRelay.this) {
                    if (!authorizationLeaseExpiresAt.equals(scheduledExpiry)
                            || authorizationLeaseExpiresAt.isAfter(clock.instant())) return;
                }
                expire.run();
            }, delay, TimeUnit.MILLISECONDS);
        }

        private synchronized void cancelLeaseExpiry() {
            ScheduledFuture<?> previous = leaseExpiry;
            if (previous != null) previous.cancel(false);
        }
    }
}
