package com.jlshell.link.server;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.signal.ControlSignal;
import com.jlshell.link.core.signal.ControlSignalJsonCodec;
import com.jlshell.link.core.transport.TransportBufferBudget;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolConfig;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketCloseStatus;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.AttributeKey;
import io.netty.util.concurrent.GlobalEventExecutor;
import io.netty.util.ReferenceCountUtil;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

/** TLS-only WebSocket relay listener. Authentication/database work is delegated off event loops. */
public final class WssRelayServer implements AutoCloseable {
    public static final String RELAY_PATH = "/link/v2/relay";
    public static final String CHALLENGE_PATH = "/link/v2/relay-challenges";
    public static final String CONTROL_PATH = "/link/v2/control";
    public static final String CONTROL_CHALLENGE_PATH = "/link/v2/control-challenges";
    private static final AttributeKey<RelayPairingService.AuthorizedPeer> AUTHORIZED_PEER =
            AttributeKey.valueOf("jlshell-link-authorized-relay-peer");
    private static final AttributeKey<ControlAuthContext> AUTHORIZED_CONTROL_PEER =
            AttributeKey.valueOf("jlshell-link-authorized-control-peer");

    private final InetSocketAddress bindAddress;
    private final SSLContext tlsContext;
    private final RelayControlAuthenticator authenticator;
    private final RelayPairingService pairings;
    private final RelayChallengeStore challenges;
    private final UsageRecorder usage;
    private final TransportBufferBudget serverBuffers;
    private final int maxFrameBytes;
    private final Duration handshakeTimeout;
    private final ControlPeerAuthenticator controlAuthenticator;
    private final ControlChallengeStore controlChallenges;
    private final SignalRouter signalRouter;
    private final ControlSignalJsonCodec controlCodec = new ControlSignalJsonCodec();
    private final EventLoopGroup boss = new NioEventLoopGroup(1);
    private final EventLoopGroup workers;
    private final ChannelGroup channels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
    private final java.util.concurrent.ConcurrentHashMap<LinkSessionId, java.util.Set<Channel>> relaySessions =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<LinkSessionId, Long> revokedRelaySessions =
            new java.util.concurrent.ConcurrentHashMap<>();
    private volatile Channel serverChannel;

    public WssRelayServer(InetSocketAddress bindAddress, SSLContext tlsContext,
            RelayControlAuthenticator authenticator, RelayPairingService pairings,
            RelayChallengeStore challenges, UsageRecorder usage,
            TransportBufferBudget serverBuffers, int maxFrameBytes,
            Duration handshakeTimeout, int workerThreads) {
        this(bindAddress, tlsContext, authenticator, pairings, challenges, usage, serverBuffers,
                maxFrameBytes, handshakeTimeout, workerThreads, null, null, null);
    }

    public WssRelayServer(InetSocketAddress bindAddress, SSLContext tlsContext,
            RelayControlAuthenticator authenticator, RelayPairingService pairings,
            RelayChallengeStore challenges, UsageRecorder usage,
            TransportBufferBudget serverBuffers, int maxFrameBytes,
            Duration handshakeTimeout, int workerThreads,
            ControlPeerAuthenticator controlAuthenticator, ControlChallengeStore controlChallenges,
            SignalRouter signalRouter) {
        this.bindAddress = Objects.requireNonNull(bindAddress, "bindAddress");
        this.tlsContext = Objects.requireNonNull(tlsContext, "tlsContext");
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.pairings = Objects.requireNonNull(pairings, "pairings");
        this.challenges = Objects.requireNonNull(challenges, "challenges");
        this.usage = usage == null ? UsageRecorder.NOOP : usage;
        this.serverBuffers = Objects.requireNonNull(serverBuffers, "serverBuffers");
        if (maxFrameBytes < 1 || maxFrameBytes > 1_048_576) {
            throw new IllegalArgumentException("maxFrameBytes must be between 1 and 1048576");
        }
        this.maxFrameBytes = maxFrameBytes;
        this.handshakeTimeout = Objects.requireNonNull(handshakeTimeout, "handshakeTimeout");
        if ((controlAuthenticator == null) != (controlChallenges == null)
                || (controlAuthenticator == null) != (signalRouter == null)) {
            throw new IllegalArgumentException("control WSS requires authenticator, challenge store, and router together");
        }
        this.controlAuthenticator = controlAuthenticator;
        this.controlChallenges = controlChallenges;
        this.signalRouter = signalRouter;
        if (handshakeTimeout.isZero() || handshakeTimeout.isNegative()) {
            throw new IllegalArgumentException("handshakeTimeout must be positive");
        }
        if (workerThreads < 1 || workerThreads > 1024) throw new IllegalArgumentException("invalid workerThreads");
        this.workers = new NioEventLoopGroup(workerThreads);
    }

    public CompletionStage<InetSocketAddress> start() {
        if (serverChannel != null) throw new IllegalStateException("WSS relay server already started");
        CompletableFuture<InetSocketAddress> started = new CompletableFuture<>();
        ServerBootstrap bootstrap = new ServerBootstrap()
                .group(boss, workers)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, 128)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) {
                        channels.add(channel);
                        SSLEngine engine = tlsContext.createSSLEngine();
                        engine.setUseClientMode(false);
                        SSLParameters parameters = engine.getSSLParameters();
                        parameters.setProtocols(new String[] {"TLSv1.3"});
                        parameters.setApplicationProtocols(new String[] {"http/1.1"});
                        engine.setSSLParameters(parameters);
                        SslHandler ssl = new SslHandler(engine);
                        ssl.setHandshakeTimeoutMillis(timeoutMillis(handshakeTimeout));
                        channel.pipeline().addLast("jlshell-link-wss-tls", ssl);
                        channel.pipeline().addLast("jlshell-link-http", new HttpServerCodec());
                        channel.pipeline().addLast("jlshell-link-http-aggregate", new HttpObjectAggregator(16_384));
                        channel.pipeline().addLast("jlshell-link-auth", new AuthAndRouteHandler());
                        channel.pipeline().addLast("jlshell-link-websocket",
                                new WebSocketServerProtocolHandler(WebSocketServerProtocolConfig.newBuilder()
                                        .websocketPath("/")
                                        .checkStartsWith(true)
                                        .allowExtensions(false)
                                        .maxFramePayloadLength(maxFrameBytes)
                                        .handshakeTimeoutMillis(timeoutMillis(handshakeTimeout))
                                        .handleCloseFrames(true)
                                        .dropPongFrames(false)
                                        .build()));
                        channel.pipeline().addLast("jlshell-link-relay-pair", new PairOnWebSocketReadyHandler());
                    }
                });
        ChannelFuture bind = bootstrap.bind(bindAddress);
        bind.addListener(result -> {
            if (result.isSuccess()) {
                serverChannel = bind.channel();
                started.complete((InetSocketAddress) bind.channel().localAddress());
            } else {
                started.completeExceptionally(result.cause());
            }
        });
        return started;
    }

    public boolean isRunning() {
        Channel channel = serverChannel;
        return channel != null && channel.isActive();
    }

    /** Closes the listening socket while leaving existing authenticated carriers alive. */
    public void stopAccepting() {
        Channel listener = serverChannel;
        serverChannel = null;
        if (listener != null) listener.close().syncUninterruptibly();
    }

    /** Waits only for established relay carriers; control channels are closed at final shutdown. */
    public void awaitRelayDrain(Duration timeout) {
        Objects.requireNonNull(timeout, "timeout");
        long deadline = System.nanoTime() + timeout.toNanos();
        while (!relaySessions.isEmpty() && System.nanoTime() < deadline) {
            java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(25));
            if (Thread.currentThread().isInterrupted()) break;
        }
    }

    /** Terminates an authorized session's active data carriers immediately after Website revocation commits. */
    public void closeSession(LinkSessionId sessionId) {
        Objects.requireNonNull(sessionId, "sessionId");
        revokedRelaySessions.put(sessionId, System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(5));
        if (revokedRelaySessions.size() > 100_000) {
            long now = System.currentTimeMillis();
            revokedRelaySessions.entrySet().removeIf(entry -> entry.getValue() < now);
        }
        java.util.Set<Channel> active = relaySessions.remove(sessionId);
        if (active != null) active.forEach(Channel::close);
    }

    private boolean registerRelaySession(LinkSessionId sessionId, Channel first, Channel second) {
        Long revokedUntil = revokedRelaySessions.get(sessionId);
        if (revokedUntil != null && revokedUntil >= System.currentTimeMillis()) return false;
        java.util.Set<Channel> active = relaySessions.computeIfAbsent(sessionId,
                ignored -> java.util.concurrent.ConcurrentHashMap.newKeySet());
        active.add(first);
        active.add(second);
        first.closeFuture().addListener(ignored -> {
            active.remove(first);
            if (active.isEmpty()) relaySessions.remove(sessionId, active);
        });
        second.closeFuture().addListener(ignored -> {
            active.remove(second);
            if (active.isEmpty()) relaySessions.remove(sessionId, active);
        });
        revokedUntil = revokedRelaySessions.get(sessionId);
        if (revokedUntil != null && revokedUntil >= System.currentTimeMillis()) {
            closeSession(sessionId);
            return false;
        }
        return true;
    }

    @Override
    public void close() {
        stopAccepting();
        channels.close().awaitUninterruptibly();
        relaySessions.clear();
        revokedRelaySessions.clear();
        if (signalRouter != null) signalRouter.close();
        boss.shutdownGracefully().syncUninterruptibly();
        workers.shutdownGracefully().syncUninterruptibly();
    }

    private final class AuthAndRouteHandler extends io.netty.channel.ChannelInboundHandlerAdapter {
        private boolean upgraded;

        @Override
        public void channelRead(ChannelHandlerContext context, Object message) {
            if (upgraded) {
                if (message instanceof FullHttpRequest) {
                    ReferenceCountUtil.release(message);
                    context.close();
                } else {
                    context.fireChannelRead(message);
                }
                return;
            }
            if (!(message instanceof FullHttpRequest request)) {
                ReferenceCountUtil.release(message);
                respond(context, HttpResponseStatus.BAD_REQUEST, "invalid_request");
                return;
            }
            try {
                URI requestUri = URI.create(request.uri());
                if (requestUri.getRawQuery() != null || requestUri.getRawFragment() != null) {
                    throw new IllegalArgumentException("relay URI query and fragment are not accepted");
                }
                String path = requestUri.getPath();
                String bearer = bearer(request);
                if ("POST".equals(request.method().name()) && CONTROL_CHALLENGE_PATH.equals(path)) {
                    if (controlAuthenticator == null || request.content().isReadable()) {
                        respond(context, controlAuthenticator == null
                                ? HttpResponseStatus.NOT_FOUND : HttpResponseStatus.BAD_REQUEST,
                                controlAuthenticator == null ? "not_found" : "invalid_request_body");
                        return;
                    }
                    ControlHandshake handshake = parseControlHandshake(request);
                    CompletionStage<ControlPeerAuthenticator.AuthenticatedPeer> auth =
                            controlAuthenticator.authenticate(handshake, bearer);
                    auth.whenComplete((principal, error) -> execute(context, () -> {
                        if (error != null || principal == null || !principal.matches(handshake)) {
                            respond(context, HttpResponseStatus.UNAUTHORIZED, "control_authentication_failed");
                            return;
                        }
                        try {
                            ControlChallengeStore.ChallengeResponse challenge =
                                    controlChallenges.issue(handshake, principal);
                            respond(context, HttpResponseStatus.CREATED,
                                    "{\"challengeId\":\"" + challenge.challengeId()
                                            + "\",\"challenge\":\"" + challenge.challenge()
                                            + "\",\"expiresAt\":\"" + challenge.expiresAt() + "\"}");
                        } catch (RuntimeException failure) {
                            respond(context, HttpResponseStatus.TOO_MANY_REQUESTS,
                                    "control_challenge_unavailable");
                        }
                    }, context::close));
                    return;
                }
                if ("GET".equals(request.method().name()) && CONTROL_PATH.equals(path)) {
                    if (controlAuthenticator == null) {
                        respond(context, HttpResponseStatus.NOT_FOUND, "not_found");
                        return;
                    }
                    startControlUpgrade(context, request, bearer);
                    return;
                }
                if (!("POST".equals(request.method().name()) && CHALLENGE_PATH.equals(path))
                        && !("GET".equals(request.method().name()) && RELAY_PATH.equals(path))) {
                    respond(context, HttpResponseStatus.NOT_FOUND, "not_found");
                    return;
                }
                RelayHandshake handshake = parseHandshake(request);
                if ("POST".equals(request.method().name()) && CHALLENGE_PATH.equals(path)) {
                    CompletionStage<RelayControlAuthenticator.AuthenticatedPeer> auth =
                            authenticator.authenticate(handshake, bearer);
                    auth.whenComplete((principal, error) -> execute(context, () -> {
                        if (error != null || principal == null || !principal.matches(handshake)) {
                            respond(context, HttpResponseStatus.UNAUTHORIZED, "relay_authentication_failed");
                            return;
                        }
                        try {
                            RelayChallengeStore.Challenge challenge = challenges.issue(handshake, principal);
                            respond(context, HttpResponseStatus.CREATED,
                                    "{\"challengeId\":\"" + challenge.challengeId()
                                            + "\",\"challenge\":\"" + challenge.challenge()
                                            + "\",\"expiresAt\":\"" + challenge.expiresAt() + "\"}");
                        } catch (RuntimeException failure) {
                            respond(context, HttpResponseStatus.TOO_MANY_REQUESTS, "relay_challenge_unavailable");
                        }
                    }, context::close));
                    return;
                }
                if (!"GET".equals(request.method().name()) || !RELAY_PATH.equals(path)) {
                    respond(context, HttpResponseStatus.NOT_FOUND, "not_found");
                    return;
                }
                String challengeId = requiredHeader(request, "X-Link-Challenge-Id");
                String proof = requiredHeader(request, "X-Link-Proof");
                CompletionStage<RelayControlAuthenticator.AuthenticatedPeer> auth =
                        authenticator.authenticate(handshake, bearer);
                FullHttpRequest retainedRequest = request.retain();
                auth.whenComplete((principal, error) -> execute(context, () -> {
                    if (!context.channel().isActive()) {
                        ReferenceCountUtil.release(retainedRequest);
                        return;
                    }
                    if (error != null || principal == null || !principal.matches(handshake)) {
                        ReferenceCountUtil.release(retainedRequest);
                        respond(context, HttpResponseStatus.UNAUTHORIZED, "relay_authentication_failed");
                        return;
                    }
                    boolean valid;
                    try {
                        valid = challenges.consume(UUID.fromString(challengeId), handshake, principal, proof);
                    } catch (RuntimeException invalid) {
                        valid = false;
                    }
                    if (!valid) {
                        ReferenceCountUtil.release(retainedRequest);
                        respond(context, HttpResponseStatus.UNAUTHORIZED, "relay_proof_rejected");
                        return;
                    }
                    RelayPairingService.AuthorizedPeer peer = new RelayPairingService.AuthorizedPeer(
                            principal.role(), principal.accountId(), principal.agentId(), handshake.sessionId(),
                            handshake.tunnelId(), principal.keyFingerprint(), principal.clientKeyFingerprint(),
                            principal.agentKeyFingerprint(), principal.ticketExpiresAt());
                    context.channel().attr(AUTHORIZED_PEER).set(peer);
                    upgraded = true;
                    context.fireChannelRead(retainedRequest);
                }, () -> {
                    ReferenceCountUtil.release(retainedRequest);
                    context.close();
                }));
            } catch (RuntimeException invalid) {
                respond(context, HttpResponseStatus.BAD_REQUEST, "invalid_relay_handshake");
            } finally {
                ReferenceCountUtil.release(request);
            }
        }

        private void startControlUpgrade(ChannelHandlerContext context, FullHttpRequest request, String bearer) {
            ControlHandshake handshake = parseControlHandshake(request);
            String challengeId = requiredHeader(request, "X-Link-Challenge-Id");
            String proof = requiredHeader(request, "X-Link-Proof");
            CompletionStage<ControlPeerAuthenticator.AuthenticatedPeer> auth =
                    controlAuthenticator.authenticate(handshake, bearer);
            FullHttpRequest retainedRequest = request.retain();
            auth.whenComplete((principal, error) -> execute(context, () -> {
                if (!context.channel().isActive()) {
                    ReferenceCountUtil.release(retainedRequest);
                    return;
                }
                if (error != null || principal == null || !principal.matches(handshake)) {
                    ReferenceCountUtil.release(retainedRequest);
                    respond(context, HttpResponseStatus.UNAUTHORIZED, "control_authentication_failed");
                    return;
                }
                boolean valid;
                try {
                    valid = controlChallenges.consume(UUID.fromString(challengeId), handshake, principal, proof);
                } catch (RuntimeException invalid) {
                    valid = false;
                }
                if (!valid) {
                    ReferenceCountUtil.release(retainedRequest);
                    respond(context, HttpResponseStatus.UNAUTHORIZED, "control_proof_rejected");
                    return;
                }
                context.channel().attr(AUTHORIZED_CONTROL_PEER)
                        .set(new ControlAuthContext(handshake, bearer, principal));
                upgraded = true;
                context.fireChannelRead(retainedRequest);
            }, () -> {
                ReferenceCountUtil.release(retainedRequest);
                context.close();
            }));
        }

        private void execute(ChannelHandlerContext context, Runnable action, Runnable rejected) {
            if (context.executor().inEventLoop()) {
                action.run();
                return;
            }
            try {
                context.executor().execute(action);
            } catch (java.util.concurrent.RejectedExecutionException stopping) {
                rejected.run();
            }
        }

        private void respond(ChannelHandlerContext context, HttpResponseStatus status, String body) {
            byte[] bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            DefaultFullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status,
                    io.netty.buffer.Unpooled.wrappedBuffer(bytes));
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json; charset=utf-8");
            response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, bytes.length);
            response.headers().set(HttpHeaderNames.CONNECTION, "close");
            context.writeAndFlush(response).addListener(ignored -> context.close());
        }

        private RelayHandshake parseHandshake(FullHttpRequest request) {
            NodeRole role = switch (requiredHeader(request, "X-Link-Role")) {
                case "client" -> NodeRole.CLIENT;
                case "agent" -> NodeRole.AGENT;
                default -> throw new IllegalArgumentException("invalid role");
            };
            return new RelayHandshake(role,
                    UUID.fromString(requiredHeader(request, "X-Link-Node-Id")),
                    UUID.fromString(requiredHeader(request, "X-Link-Agent-Id")),
                    LinkSessionId.parse(requiredHeader(request, "X-Link-Session-Id")),
                    TunnelId.parse(requiredHeader(request, "X-Link-Tunnel-Id")),
                    new com.jlshell.link.core.model.NodeKeyFingerprint(
                            requiredHeader(request, "X-Link-Key-Fingerprint")));
        }

        private ControlHandshake parseControlHandshake(FullHttpRequest request) {
            NodeRole role = switch (requiredHeader(request, "X-Link-Role")) {
                case "client" -> NodeRole.CLIENT;
                case "agent" -> NodeRole.AGENT;
                default -> throw new IllegalArgumentException("invalid role");
            };
            return new ControlHandshake(role, UUID.fromString(requiredHeader(request, "X-Link-Node-Id")),
                    new NodeKeyFingerprint(requiredHeader(request, "X-Link-Key-Fingerprint")));
        }

        private String bearer(FullHttpRequest request) {
            String value = requiredHeader(request, HttpHeaderNames.AUTHORIZATION.toString());
            if (!value.startsWith("Bearer ") || value.length() < 8 || value.length() > 8192) {
                throw new IllegalArgumentException("invalid bearer credential");
            }
            return value.substring(7);
        }

        private String requiredHeader(FullHttpRequest request, String name) {
            String value = request.headers().get(name);
            if (value == null || value.isBlank() || value.length() > 8192
                    || request.headers().getAll(name).size() != 1) {
                throw new IllegalArgumentException("missing or repeated relay header");
            }
            return value.trim();
        }
    }

    private final class PairOnWebSocketReadyHandler extends io.netty.channel.ChannelInboundHandlerAdapter {
        @Override
        public void userEventTriggered(ChannelHandlerContext context, Object event) throws Exception {
            if (event != WebSocketServerProtocolHandler.ServerHandshakeStateEvent.HANDSHAKE_COMPLETE) {
                context.fireUserEventTriggered(event);
                return;
            }
            ControlAuthContext controlPeer = context.channel().attr(AUTHORIZED_CONTROL_PEER).getAndSet(null);
            if (controlPeer != null) {
                context.pipeline().remove(this);
                context.pipeline().addLast("jlshell-link-control-channel", new ControlWebSocketHandler(controlPeer));
                return;
            }
            RelayPairingService.AuthorizedPeer peer = context.channel().attr(AUTHORIZED_PEER).getAndSet(null);
            if (peer == null) {
                context.close();
                return;
            }
            context.channel().config().setAutoRead(false);
            java.util.concurrent.CompletionStage<RelayPairingService.PairedChannels> joining;
            try {
                joining = pairings.join(peer, context.channel());
            } catch (RuntimeException rejected) {
                context.close();
                return;
            }
            joining.whenComplete((pair, error) -> {
                if (error != null || pair == null) {
                    context.close();
                    return;
                }
                if (!registerRelaySession(peer.sessionId(), pair.aChannel(), pair.cChannel())) {
                    pair.aChannel().close();
                    pair.cChannel().close();
                    return;
                }
                try {
                    context.executor().execute(() -> {
                        if (!context.channel().isActive()) return;
                        Channel other;
                        UsageRecorder.Direction direction;
                        if (pair.aChannel() == context.channel()) {
                            other = pair.cChannel();
                            direction = UsageRecorder.Direction.CLIENT_TO_AGENT;
                        } else if (pair.cChannel() == context.channel()) {
                            other = pair.aChannel();
                            direction = UsageRecorder.Direction.AGENT_TO_CLIENT;
                        } else {
                            context.close();
                            return;
                        }
                        LinkSessionId sessionId = peer.sessionId();
                        TunnelId tunnelId = peer.tunnelId();
                        context.pipeline().remove(this);
                        context.pipeline().addLast("jlshell-link-opaque-relay",
                                new RelayFrameBridgeHandler(other, sessionId, tunnelId, direction,
                                        pair.bufferBudget(), serverBuffers, usage, maxFrameBytes));
                        context.channel().config().setAutoRead(true);
                        try {
                            other.eventLoop().execute(() -> {
                                if (other.isActive()) other.config().setAutoRead(true);
                            });
                        } catch (java.util.concurrent.RejectedExecutionException stopping) {
                            pair.aChannel().close();
                            pair.cChannel().close();
                        }
                    });
                } catch (java.util.concurrent.RejectedExecutionException stopping) {
                    pair.aChannel().close();
                    pair.cChannel().close();
                }
            });
        }
    }

    private final class ControlWebSocketHandler extends io.netty.channel.SimpleChannelInboundHandler<WebSocketFrame> {
        private final ControlAuthContext auth;
        private SignalRouter.ControlConnection connection;
        private ScheduledFuture<?> helloTimeout;
        private ScheduledFuture<?> reauthentication;
        private boolean helloAccepted;

        private ControlWebSocketHandler(ControlAuthContext auth) {
            this.auth = auth;
        }

        @Override
        public void handlerAdded(ChannelHandlerContext context) {
            helloTimeout = context.executor().schedule(() -> {
                if (!helloAccepted) reject(context, "PROTOCOL_ERROR");
            }, timeoutMillis(handshakeTimeout), java.util.concurrent.TimeUnit.MILLISECONDS);
        }

        @Override
        protected void channelRead0(ChannelHandlerContext context, WebSocketFrame frame) {
            if (frame instanceof PingWebSocketFrame ping) {
                context.writeAndFlush(new PongWebSocketFrame(ping.content().retain()));
                return;
            }
            if (frame instanceof PongWebSocketFrame) return;
            if (frame instanceof CloseWebSocketFrame) {
                context.close();
                return;
            }
            if (!(frame instanceof TextWebSocketFrame text)) {
                reject(context, "PROTOCOL_ERROR");
                return;
            }
            if (!helloAccepted) {
                acceptHello(context, text.text());
                return;
            }
            try {
                signalRouter.route(connection, controlCodec.decodeSignal(text.text()));
            } catch (SecurityException rejected) {
                reject(context, "AUTH_DENIED");
            } catch (RuntimeException invalid) {
                reject(context, "PROTOCOL_ERROR");
            }
        }

        private void acceptHello(ChannelHandlerContext context, String payload) {
            try {
                ControlSignalJsonCodec.Hello hello = controlCodec.decodeHello(payload);
                if (hello.role() != auth.handshake().role()
                        || !hello.nodeId().equals(auth.handshake().nodeId())
                        || !hello.keyFingerprint().equals(auth.handshake().keyFingerprint())) {
                    reject(context, "IDENTITY_MISMATCH");
                    return;
                }
                if (!"link-v2".equals(hello.minProtocol())
                        || !"link-v2".equals(hello.maxProtocol())) {
                    reject(context, "PROTOCOL_UNSUPPORTED");
                    return;
                }
                ControlPeerAuthenticator.AuthenticatedPeer principal = auth.principal();
                SignalRouter.ControlPeer peer = new SignalRouter.ControlPeer(principal.role(),
                        principal.accountId(), principal.nodeId(), principal.agentId(), principal.keyFingerprint());
                connection = signalRouter.register(peer, signal -> send(context, signal), context.channel()::close);
                helloAccepted = true;
                helloTimeout.cancel(false);
                context.writeAndFlush(new TextWebSocketFrame(
                        controlCodec.encodeReady(peer.nodeId(), connection.generation())));
                reauthentication = context.executor().scheduleAtFixedRate(
                        () -> reauthenticate(context), 30, 30, java.util.concurrent.TimeUnit.SECONDS);
            } catch (RuntimeException invalid) {
                reject(context, "PROTOCOL_ERROR");
            }
        }

        private void send(ChannelHandlerContext context, ControlSignal signal) {
            if (!context.channel().isActive()) throw new IllegalStateException("control channel is closed");
            Runnable write = () -> {
                if (context.channel().isActive()) {
                    context.writeAndFlush(new TextWebSocketFrame(controlCodec.encode(signal)));
                }
            };
            context.executor().execute(write);
        }

        private void reauthenticate(ChannelHandlerContext context) {
            if (!context.channel().isActive()) return;
            CompletionStage<ControlPeerAuthenticator.AuthenticatedPeer> stage;
            try {
                stage = controlAuthenticator.authenticate(auth.handshake(), auth.bearerCredential());
            } catch (RuntimeException rejected) {
                context.close();
                return;
            }
            stage.whenComplete((current, error) -> executeOnEventLoop(context, () -> {
                if (error != null || current == null || !sameIdentity(auth.principal(), current)) {
                    context.close();
                }
            }, context::close));
        }

        private void reject(ChannelHandlerContext context, String code) {
            if (!context.channel().isActive()) return;
            if (helloTimeout != null) helloTimeout.cancel(false);
            if (reauthentication != null) reauthentication.cancel(false);
            context.writeAndFlush(new TextWebSocketFrame(controlCodec.encodeError(code)))
                    .addListener(ignored -> context.writeAndFlush(
                            new CloseWebSocketFrame(WebSocketCloseStatus.PROTOCOL_ERROR))
                            .addListener(done -> context.close()));
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) throws Exception {
            if (helloTimeout != null) helloTimeout.cancel(false);
            if (reauthentication != null) reauthentication.cancel(false);
            if (connection != null) connection.close();
            super.channelInactive(context);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
            context.close();
        }
    }

    private static boolean sameIdentity(ControlPeerAuthenticator.AuthenticatedPeer left,
                                        ControlPeerAuthenticator.AuthenticatedPeer right) {
        return left.role() == right.role() && left.accountId().equals(right.accountId())
                && left.nodeId().equals(right.nodeId())
                && Objects.equals(left.agentId(), right.agentId())
                && left.keyFingerprint().equals(right.keyFingerprint())
                && java.security.MessageDigest.isEqual(
                        left.nodePublicKey().getEncoded(), right.nodePublicKey().getEncoded());
    }

    private static void executeOnEventLoop(ChannelHandlerContext context, Runnable action, Runnable rejected) {
        if (context.executor().inEventLoop()) {
            action.run();
            return;
        }
        try {
            context.executor().execute(action);
        } catch (java.util.concurrent.RejectedExecutionException stopping) {
            rejected.run();
        }
    }

    private record ControlAuthContext(ControlHandshake handshake, String bearerCredential,
                                      ControlPeerAuthenticator.AuthenticatedPeer principal) { }

    private static long timeoutMillis(Duration duration) {
        return Math.max(1, Math.min(Integer.MAX_VALUE, duration.toMillis()));
    }
}
