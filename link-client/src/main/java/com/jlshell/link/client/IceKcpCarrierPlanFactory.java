package com.jlshell.link.client;

import com.jlshell.link.core.model.LinkPath;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.ConnectClientMultiplexer;
import com.jlshell.link.transport.DatagramPath;
import com.jlshell.link.transport.KcpReliableDuplexChannel;
import com.jlshell.link.transport.ReliableCarrierBridge;
import com.jlshell.link.transport.SecureConnectPipeline;
import com.jlshell.link.transport.TlsHandshakeGate;
import io.netty.channel.Channel;
import io.netty.channel.DefaultEventLoopGroup;
import io.netty.channel.EventLoopGroup;
import io.netty.handler.ssl.SslHandler;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import javax.net.ssl.SSLContext;

/**
 * Composes an authenticated ICE-selected datagram path, KCP, TLS 1.3 and H2
 * CONNECT into the direct leg of an existing Website-authorized connection plan.
 * The direct-session provider owns only WSS signaling and ICE nomination; the
 * Website access ticket is deliberately not passed to it.
 */
public final class IceKcpCarrierPlanFactory implements ReauthorizingConnectionFlow.CarrierPlanFactory {
    private final RelayCarrierPlanFactory relayPlans;
    private final DirectPathProvider directPaths;
    private final EventLoopGroup localChannelLoops;
    private final TransportBudget budget;
    private final UUID clientDeviceId;
    private final NodeKeyFingerprint clientKeyFingerprint;
    private final Function<NodeKeyFingerprint, SSLContext> innerTlsForAgent;
    private final String tlsPeerHost;
    private final TlsHandshakeGate handshakeGate;
    private final Function<com.jlshell.link.core.model.LinkSessionId,
            ? extends CompletionStage<Void>> releaseUnusedRelay;

    public IceKcpCarrierPlanFactory(RelayCarrierPlanFactory relayPlans, DirectPathProvider directPaths,
            EventLoopGroup localChannelLoops, TransportBudget budget, UUID clientDeviceId,
            LocalNodeKey clientNodeKey,
            Function<NodeKeyFingerprint, SSLContext> innerTlsForAgent,
            String tlsPeerHost, TlsHandshakeGate handshakeGate,
            Function<com.jlshell.link.core.model.LinkSessionId,
                    ? extends CompletionStage<Void>> releaseUnusedRelay) {
        this.relayPlans = Objects.requireNonNull(relayPlans, "relayPlans");
        this.directPaths = Objects.requireNonNull(directPaths, "directPaths");
        this.localChannelLoops = Objects.requireNonNull(localChannelLoops, "localChannelLoops");
        if (localChannelLoops instanceof io.netty.channel.nio.NioEventLoopGroup) {
            throw new IllegalArgumentException("LocalChannel requires a DefaultEventLoopGroup-compatible group");
        }
        this.budget = Objects.requireNonNull(budget, "budget");
        this.clientDeviceId = Objects.requireNonNull(clientDeviceId, "clientDeviceId");
        this.clientKeyFingerprint = Objects.requireNonNull(clientNodeKey, "clientNodeKey").fingerprint();
        this.innerTlsForAgent = Objects.requireNonNull(innerTlsForAgent, "innerTlsForAgent");
        if (tlsPeerHost == null || tlsPeerHost.isBlank() || tlsPeerHost.length() > 253) {
            throw new IllegalArgumentException("TLS peer host is invalid");
        }
        this.tlsPeerHost = tlsPeerHost;
        this.handshakeGate = Objects.requireNonNull(handshakeGate, "handshakeGate");
        this.releaseUnusedRelay = Objects.requireNonNull(releaseUnusedRelay, "releaseUnusedRelay");
    }

    @Override
    public ReauthorizingConnectionFlow.PathPlan create(ReauthorizingConnectionFlow.AuthorizedTunnel grant) {
        Objects.requireNonNull(grant, "grant");
        NodeKeyFingerprint expectedAgent = Objects.requireNonNull(grant.agentKeyFingerprint(),
                "Website grant must bind an Agent key fingerprint");
        ReauthorizingConnectionFlow.PathPlan relayPlan = relayPlans.create(grant);
        ConnectionCoordinator.CarrierConnector direct = context -> {
            if (context.isCancelled()) {
                return CompletableFuture.failedFuture(new CancellationException("direct path setup cancelled"));
            }
            DirectSessionRequest request = new DirectSessionRequest(grant.sessionId(), clientDeviceId,
                    clientKeyFingerprint, grant.agentId(), expectedAgent, grant.policyVersion(),
                    grant.authorizationLeaseExpiresAt());
            return directPaths.establish(request, context)
                    .thenCompose(path -> createDirectCarrier(path, grant, expectedAgent, context));
        };
        ConnectionCoordinator.TargetOpener open = (carrier, request, context) -> {
            if (carrier instanceof DirectCarrier selected) {
                try {
                    releaseUnusedRelay.apply(grant.sessionId()).exceptionally(ignored -> null);
                } catch (RuntimeException ignored) { }
                return new ConnectClientMultiplexer(selected.endpoint, budget,
                        new TransportBufferBudget(budget.maxBufferedBytesTotal()))
                        .open(request.target(), request.tunnelId(), request.accessTicket());
            }
            return relayPlan.targetOpener().open(carrier, request, context);
        };
        return new ReauthorizingConnectionFlow.PathPlan(direct, relayPlan.relay(), open);
    }

    private CompletionStage<? extends ConnectionCoordinator.SecureCarrier> createDirectCarrier(
            DirectPathLease path, ReauthorizingConnectionFlow.AuthorizedTunnel grant,
            NodeKeyFingerprint expectedAgent, ConnectionCoordinator.AttemptContext context) {
        Objects.requireNonNull(path, "direct path provider returned no path");
        if (!grant.sessionId().equals(path.sessionId()) || path.generation() < 1) {
            path.close();
            return CompletableFuture.failedFuture(new SecurityException(
                    "nominated ICE path does not match the authorized Website session"));
        }
        if (context.isCancelled()) {
            path.close();
            return CompletableFuture.failedFuture(new CancellationException("direct path setup cancelled"));
        }

        KcpReliableDuplexChannel kcp;
        try {
            kcp = new KcpReliableDuplexChannel(conversationId(path.sessionId(), path.generation()),
                    path.datagrams(), budget);
        } catch (IOException | RuntimeException error) {
            path.close();
            return CompletableFuture.failedFuture(error);
        }
        CompletableFuture<ConnectionCoordinator.SecureCarrier> result = new CompletableFuture<>();
        ReliableCarrierBridge.open(localChannelLoops, kcp, budget).whenComplete((bridge, openError) -> {
            if (openError != null || bridge == null) {
                path.close();
                result.completeExceptionally(openError == null
                        ? new IOException("direct carrier bridge could not be created") : openError);
                return;
            }
            AtomicBoolean released = new AtomicBoolean();
            AtomicBoolean setupComplete = new AtomicBoolean();
            Runnable release = () -> {
                if (!released.compareAndSet(false, true)) return;
                bridge.close();
                path.close();
            };
            context.cancelled().whenComplete((ignored, error) -> {
                if (setupComplete.compareAndSet(false, true)) {
                    release.run();
                    result.completeExceptionally(new CancellationException("direct path setup cancelled"));
                }
            });
            bridge.closed().whenComplete((ignored, error) -> {
                if (!result.isDone()) {
                    result.completeExceptionally(error == null
                            ? new IOException("direct carrier closed during setup") : error);
                }
            });
            Channel endpoint = bridge.endpoint();
            endpoint.eventLoop().execute(() -> {
                if (context.isCancelled() || !endpoint.isActive()) {
                    release.run();
                    result.completeExceptionally(new CancellationException("direct path setup cancelled"));
                    return;
                }
                CompletionStage<Void> secureReady;
                try {
                    SSLContext tls = Objects.requireNonNull(innerTlsForAgent.apply(expectedAgent),
                            "TLS provider returned no pinned Agent context");
                    secureReady = SecureConnectPipeline.installClientOnActiveCarrier(endpoint.pipeline(), tls,
                            tlsPeerHost, 443, budget, handshakeGate);
                } catch (RuntimeException invalid) {
                    release.run();
                    result.completeExceptionally(invalid);
                    return;
                }
                bridge.start().whenComplete((started, startError) -> {
                    if (startError != null) {
                        release.run();
                        result.completeExceptionally(startError);
                    }
                });
                secureReady.whenComplete((ignored, tlsError) -> {
                    if (tlsError != null) {
                        release.run();
                        result.completeExceptionally(tlsError);
                        return;
                    }
                    try {
                        SslHandler tls = (SslHandler) endpoint.pipeline().get("jlshell-link-tls");
                        if (tls == null || !"TLSv1.3".equals(tls.engine().getSession().getProtocol())
                                || !expectedAgent.equals(NodeKeyFingerprint.from(
                                        tls.engine().getSession().getPeerCertificates()[0].getPublicKey()))) {
                            throw new SecurityException("direct peer identity does not match the Website grant");
                        }
                        if (context.isCancelled()) {
                            throw new CancellationException("direct path setup cancelled");
                        }
                        setupComplete.set(true);
                        DirectCarrier carrier = new DirectCarrier(bridge, path, endpoint);
                        if (!result.complete(carrier)) carrier.close();
                    } catch (RuntimeException | javax.net.ssl.SSLPeerUnverifiedException rejected) {
                        release.run();
                        result.completeExceptionally(new SecurityException(
                                "direct peer identity could not be verified", rejected));
                    }
                });
            });
        });
        result.whenComplete((carrier, error) -> {
            if (result.isCancelled()) {
                path.close();
            } else if (error != null) {
                // The path provider contract requires idempotent close, so this also covers
                // failures that occur before the bridge lifecycle callback is registered.
                path.close();
            }
        });
        return result;
    }

    private static int conversationId(com.jlshell.link.core.model.LinkSessionId sessionId, long generation) {
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

    /** Carries only Website authorization identity and expiry, never the access ticket or target. */
    public record DirectSessionRequest(com.jlshell.link.core.model.LinkSessionId sessionId,
            UUID clientDeviceId, NodeKeyFingerprint clientKeyFingerprint,
            UUID agentId, NodeKeyFingerprint agentKeyFingerprint, long policyVersion,
            Instant authorizationLeaseExpiresAt) {
        public DirectSessionRequest {
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(clientDeviceId, "clientDeviceId");
            Objects.requireNonNull(clientKeyFingerprint, "clientKeyFingerprint");
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(agentKeyFingerprint, "agentKeyFingerprint");
            Objects.requireNonNull(authorizationLeaseExpiresAt, "authorizationLeaseExpiresAt");
            if (policyVersion < 1) throw new IllegalArgumentException("policyVersion must be positive");
        }
        @Override public String toString() { return "DirectSessionRequest[<redacted>]"; }
    }

    @FunctionalInterface
    public interface DirectPathProvider {
        CompletionStage<? extends DirectPathLease> establish(
                DirectSessionRequest request, ConnectionCoordinator.AttemptContext context);
    }

    /** A successfully nominated ICE path; close must be idempotent and release its ICE generation. */
    public interface DirectPathLease extends AutoCloseable {
        com.jlshell.link.core.model.LinkSessionId sessionId();
        long generation();
        DatagramPath datagrams();
        @Override void close();
    }

    private static final class DirectCarrier implements ConnectionCoordinator.SecureCarrier {
        private final ReliableCarrierBridge bridge;
        private final DirectPathLease path;
        private final Channel endpoint;
        private final AtomicBoolean closed = new AtomicBoolean();

        private DirectCarrier(ReliableCarrierBridge bridge, DirectPathLease path, Channel endpoint) {
            this.bridge = bridge;
            this.path = path;
            this.endpoint = endpoint;
        }

        @Override public LinkPath path() { return LinkPath.DIRECT; }

        @Override public void close() {
            if (!closed.compareAndSet(false, true)) return;
            bridge.close();
            path.close();
        }
    }
}
