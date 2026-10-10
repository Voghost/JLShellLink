package com.jlshell.link.agent;

import com.jlshell.link.core.auth.AccessGrantJwsService;
import com.jlshell.link.core.auth.SigningKeyResolver;
import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.model.AccessPolicy;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.signal.ControlSignal;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.ConnectStreamMultiplexer;
import com.jlshell.link.transport.Ice4jDirectSession;
import com.jlshell.link.transport.ReliableCarrierBridge;
import com.jlshell.link.transport.SecureConnectPipeline;
import com.jlshell.link.transport.TlsHandshakeGate;
import io.netty.channel.Channel;
import io.netty.channel.DefaultEventLoopGroup;
import io.netty.channel.EventLoopGroup;
import io.netty.handler.ssl.SslHandler;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;

/** C-side direct ICE/KCP/TLS/H2 sessions, gated by Website invites and tickets. */
final class AgentDirectSessionRuntime implements AutoCloseable {
    private final URI ticketIssuer;
    private final UUID agentId;
    private final LocalNodeKey nodeKey;
    private final Function<NodeKeyFingerprint, SSLContext> innerTlsForClient;
    private final Supplier<AccessPolicy> localPolicy;
    private final EventLoopGroup eventLoops;
    private final Executor worker;
    private final ScheduledExecutorService expiryScheduler;
    private final AccessGrantJwsService grants;
    private final SigningKeyResolver signingKeys;
    private final TransportBudget budget;
    private final Ice4jDirectSession.Config iceConfig;
    private final TlsHandshakeGate handshakeGate;
    private final Clock clock;
    private final Consumer<String> status;
    private final AtomicReference<AgentLeaseSnapshot> lease;
    private final ConcurrentMap<LinkSessionId, DirectSession> active = new ConcurrentHashMap<>();
    private volatile boolean closed;

    AgentDirectSessionRuntime(URI ticketIssuer, UUID agentId, LocalNodeKey nodeKey,
            Function<NodeKeyFingerprint, SSLContext> innerTlsForClient,
            Supplier<AccessPolicy> localPolicy, AgentLeaseSnapshot initialLease,
            EventLoopGroup eventLoops, Executor worker, ScheduledExecutorService expiryScheduler,
            AccessGrantJwsService grants, SigningKeyResolver signingKeys, TransportBudget budget,
            Ice4jDirectSession.Config iceConfig, TlsHandshakeGate handshakeGate, Clock clock,
            Consumer<String> status) {
        this.ticketIssuer = Objects.requireNonNull(ticketIssuer, "ticketIssuer");
        this.agentId = Objects.requireNonNull(agentId, "agentId");
        this.nodeKey = Objects.requireNonNull(nodeKey, "nodeKey");
        this.innerTlsForClient = Objects.requireNonNull(innerTlsForClient, "innerTlsForClient");
        this.localPolicy = Objects.requireNonNull(localPolicy, "localPolicy");
        this.lease = new AtomicReference<>(Objects.requireNonNull(initialLease, "initialLease"));
        this.eventLoops = Objects.requireNonNull(eventLoops, "eventLoops");
        this.worker = Objects.requireNonNull(worker, "worker");
        this.expiryScheduler = Objects.requireNonNull(expiryScheduler, "expiryScheduler");
        this.grants = Objects.requireNonNull(grants, "grants");
        this.signingKeys = Objects.requireNonNull(signingKeys, "signingKeys");
        this.budget = Objects.requireNonNull(budget, "budget");
        this.iceConfig = Objects.requireNonNull(iceConfig, "iceConfig");
        this.handshakeGate = Objects.requireNonNull(handshakeGate, "handshakeGate");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.status = status == null ? ignored -> { } : status;
        if (!agentId.equals(initialLease.agentId())
                || !nodeKey.fingerprint().equals(initialLease.agentKeyFingerprint())) {
            throw new IllegalArgumentException("Agent direct runtime identity does not match its Website lease");
        }
    }

    void acceptInvite(ControlSignal.SessionInvite invite, AgentControlSignalClient signaling) {
        Objects.requireNonNull(invite, "invite");
        Objects.requireNonNull(signaling, "signaling");
        if (closed || !invite.iceCredentialsSupported() || !invite.agentId().equals(agentId)
                || !invite.agentKeyFingerprint().equals(nodeKey.fingerprint())
                || !invite.expiresAt().isAfter(clock.instant())) return;
        AgentLeaseSnapshot currentLease = lease.get();
        if (!currentLease.permitsNewStreams(clock.instant())
                || invite.policyVersion() != currentLease.policyVersion()) return;
        LinkSessionId sessionId = invite.sessionId();
        DirectSession next = new DirectSession(invite, signaling);
        AtomicReference<DirectSession> replaced = new AtomicReference<>();
        DirectSession previous = active.compute(sessionId, (ignored, current) -> {
            if (current != null && current.generation() >= invite.generation()) return current;
            replaced.set(current);
            return next;
        });
        if (previous != next) return;
        DirectSession stale = replaced.get();
        if (stale != null) stale.close();
        if (active.size() > 256) {
            active.remove(sessionId, next);
            next.close();
            safeStatus("direct-session-capacity-reached");
            return;
        }
        next.start();
    }

    void acceptSignal(ControlSignal signal) {
        if (closed || signal == null) return;
        if (signal instanceof ControlSignal.SessionRevoked revoked) {
            closeSession(revoked.sessionId());
            return;
        }
        DirectSession session = active.get(signal.sessionId());
        if (session != null) session.accept(signal);
    }

    void updateLease(AgentLeaseSnapshot next) {
        Objects.requireNonNull(next, "next");
        lease.updateAndGet(previous -> {
            if (!next.agentId().equals(agentId) || !next.agentKeyFingerprint().equals(nodeKey.fingerprint())
                    || next.policyVersion() < previous.policyVersion()) {
                throw new IllegalArgumentException("Website lease update is not valid for this Agent");
            }
            return next;
        });
        if (next.revoked()) closeAll();
        else active.values().forEach(session -> session.updateLease(next));
    }

    void closeSession(LinkSessionId sessionId) {
        DirectSession removed = active.remove(Objects.requireNonNull(sessionId, "sessionId"));
        if (removed != null) removed.close();
    }

    void closeAll() {
        active.values().forEach(DirectSession::close);
        active.clear();
    }

    private void safeStatus(String code) {
        try { status.accept(code); } catch (RuntimeException ignored) { }
    }

    @Override public void close() {
        if (closed) return;
        closed = true;
        closeAll();
    }

    private final class DirectSession implements AutoCloseable {
        private final ControlSignal.SessionInvite invite;
        private final AgentControlSignalClient signaling;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicBoolean carrierStarted = new AtomicBoolean();
        private final CompletableFuture<ControlSignal.PathReady> peerReady = new CompletableFuture<>();
        private final AtomicReference<Ice4jDirectSession.SelectedPath> selected = new AtomicReference<>();
        private final EarlyIceSignals earlyIce;
        private volatile Ice4jDirectSession ice;
        private volatile ReliableCarrierBridge bridge;
        private volatile ConnectStreamMultiplexer multiplexer;
        private volatile AgentAccessAuthorizer authorizer;
        private volatile ScheduledFuture<?> expires;

        private DirectSession(ControlSignal.SessionInvite invite, AgentControlSignalClient signaling) {
            this.invite = invite;
            this.signaling = signaling;
            this.earlyIce = new EarlyIceSignals(invite.sessionId(), invite.generation());
        }

        private long generation() { return invite.generation(); }

        private void start() {
            long delay = Math.max(0, invite.expiresAt().toEpochMilli() - clock.millis());
            expires = expiryScheduler.schedule(() -> closeSession(invite.sessionId()), delay, TimeUnit.MILLISECONDS);
            try {
                worker.execute(() -> {
                    if (closed.get() || !currentAuthorization()) {
                        closeSession(invite.sessionId());
                        return;
                    }
                    try {
                        ice = new Ice4jDirectSession(invite.sessionId(), invite.generation(), false, iceConfig);
                        ice.selectedPath().whenComplete((path, error) -> {
                            if (error != null) {
                                fail("direct-ice-unreachable");
                                return;
                            }
                            selected.set(path);
                            send(path.readySignal());
                            maybeStartCarrier();
                        });
                        earlyIce.attach(ice::accept);
                        if (closed.get()) { ice.close(); return; }
                        CompletionStage<Void> offered = CompletableFuture.completedFuture(null);
                        for (ControlSignal signal : ice.localOffer()) {
                            offered = offered.thenCompose(ignored -> signaling.send(signal).thenApply(done -> null));
                        }
                        offered.whenComplete((ignored, error) -> {
                            if (error != null) fail("direct-signaling-unavailable");
                        });
                    } catch (IOException | RuntimeException error) {
                        fail("direct-ice-unavailable");
                    }
                });
            } catch (RuntimeException rejected) {
                fail("direct-worker-unavailable");
            }
        }

        private boolean currentAuthorization() {
            AgentLeaseSnapshot current = lease.get();
            return !closed.get() && invite.expiresAt().isAfter(clock.instant())
                    && current.permitsNewStreams(clock.instant())
                    && invite.policyVersion() == current.policyVersion();
        }

        private void accept(ControlSignal signal) {
            if (closed.get() || signal.generation() != invite.generation()) return;
            try {
                if (signal instanceof ControlSignal.IceCredentials
                        || signal instanceof ControlSignal.IceCandidate || signal instanceof ControlSignal.IceEnd) {
                    earlyIce.accept(signal);
                } else if (signal instanceof ControlSignal.PathReady ready) {
                    if (ready.path() != ControlSignal.Path.DIRECT) {
                        fail("direct-path-selection-mismatch");
                        return;
                    }
                    if (!peerReady.complete(ready)) {
                        fail("direct-path-selection-repeated");
                        return;
                    }
                    maybeStartCarrier();
                }
            } catch (RuntimeException invalid) {
                fail("direct-signaling-rejected");
            }
        }

        private void send(ControlSignal signal) {
            signaling.send(signal).whenComplete((ignored, error) -> {
                if (error != null) fail("direct-signaling-unavailable");
            });
        }

        private void maybeStartCarrier() {
            Ice4jDirectSession.SelectedPath local = selected.get();
            ControlSignal.PathReady remote = peerReady.getNow(null);
            if (local == null || remote == null || closed.get() || !currentAuthorization()
                    || !carrierStarted.compareAndSet(false, true)) return;
            if (!local.remoteCandidateId().equals(remote.localCandidateId())
                    || !local.localCandidateId().equals(remote.remoteCandidateId())) {
                fail("direct-path-selection-mismatch");
                return;
            }
            try {
                var key = invite.clientKeyFingerprint();
                AgentLeaseSnapshot currentLease = lease.get();
                authorizer = new AgentAccessAuthorizer(ticketIssuer,
                        new AgentAccessAuthorizer.UUIDBinding(invite.sessionId(), agentId, key,
                                invite.agentKeyFingerprint()), grants, signingKeys,
                        Objects.requireNonNull(localPolicy.get(), "local target policy"), currentLease,
                        invite.expiresAt(), clock, worker, safeAudit());
                multiplexer = new ConnectStreamMultiplexer(budget,
                        new TransportBufferBudget(budget.maxBufferedBytesTotal()), authorizer,
                        ConnectStreamMultiplexer.tcpConnector(budget));
                KcpReliableDuplexChannelHolder holder = new KcpReliableDuplexChannelHolder(
                        conversationId(invite.sessionId(), invite.generation()), local.datagrams(), budget);
                ReliableCarrierBridge.open(eventLoops, holder.channel, budget).whenComplete((opened, error) -> {
                    if (error != null || opened == null || closed.get()) {
                        if (opened != null) opened.close();
                        fail("direct-carrier-unavailable");
                        return;
                    }
                    bridge = opened;
                    opened.closed().whenComplete((ignored, closedError) -> closeSession(invite.sessionId()));
                    Channel endpoint = opened.endpoint();
                    endpoint.eventLoop().execute(() -> {
                        if (closed.get() || !currentAuthorization()) {
                            closeSession(invite.sessionId());
                            return;
                        }
                        CompletionStage<Void> secure;
                        try {
                            SSLContext tls = Objects.requireNonNull(innerTlsForClient.apply(key),
                                    "TLS context for authorized client");
                            secure = SecureConnectPipeline.installServerOnActiveCarrier(endpoint.pipeline(), tls,
                                    "jlshell-client-" + key.value(), 443, budget, handshakeGate, multiplexer);
                        } catch (RuntimeException failure) {
                            fail("direct-tls-setup-failed");
                            return;
                        }
                        opened.start().whenComplete((started, startError) -> {
                            if (startError != null) fail("direct-carrier-start-failed");
                        });
                        secure.whenComplete((ignored, tlsError) -> {
                            if (tlsError != null) {
                                fail("direct-tls-handshake-failed");
                                return;
                            }
                            try {
                                SslHandler ssl = (SslHandler) endpoint.pipeline().get("jlshell-link-tls");
                                if (ssl == null || !"TLSv1.3".equals(ssl.engine().getSession().getProtocol())
                                        || !key.equals(NodeKeyFingerprint.from(
                                                ssl.engine().getSession().getPeerCertificates()[0].getPublicKey()))) {
                                    fail("direct-client-identity-mismatch");
                                    return;
                                }
                                safeStatus("direct-session-ready");
                            } catch (RuntimeException | javax.net.ssl.SSLPeerUnverifiedException rejected) {
                                fail("direct-client-identity-unverified");
                            }
                        });
                    });
                });
            } catch (IOException | RuntimeException failure) {
                fail("direct-carrier-unavailable");
            }
        }

        private Consumer<String> safeAudit() {
            return AgentDirectSessionRuntime.this::safeStatus;
        }

        private void updateLease(AgentLeaseSnapshot next) {
            AgentAccessAuthorizer current = authorizer;
            if (!next.permitsNewStreams(clock.instant()) || next.policyVersion() != invite.policyVersion()) {
                closeSession(invite.sessionId());
            } else if (current != null) {
                current.updateLease(next);
            }
        }

        private void fail(String code) {
            safeStatus(code);
            closeSession(invite.sessionId());
        }

        @Override public void close() {
            if (!closed.compareAndSet(false, true)) return;
            earlyIce.close();
            ScheduledFuture<?> expiry = expires;
            if (expiry != null) expiry.cancel(false);
            ConnectStreamMultiplexer currentMultiplexer = multiplexer;
            if (currentMultiplexer != null) currentMultiplexer.closeAllAuthorizedStreams();
            ReliableCarrierBridge currentBridge = bridge;
            if (currentBridge != null) currentBridge.close();
            Ice4jDirectSession currentIce = ice;
            if (currentIce != null) currentIce.close();
        }
    }

    private static int conversationId(LinkSessionId sessionId, long generation) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(
                    (sessionId.value() + ":" + generation).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            int id = ByteBuffer.wrap(digest).getInt();
            java.util.Arrays.fill(digest, (byte) 0);
            return id == 0 ? 1 : id;
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static final class KcpReliableDuplexChannelHolder {
        private final com.jlshell.link.transport.KcpReliableDuplexChannel channel;
        private KcpReliableDuplexChannelHolder(int conversationId,
                com.jlshell.link.transport.DatagramPath datagrams, TransportBudget budget) throws IOException {
            channel = new com.jlshell.link.transport.KcpReliableDuplexChannel(conversationId, datagrams, budget);
        }
    }
}
