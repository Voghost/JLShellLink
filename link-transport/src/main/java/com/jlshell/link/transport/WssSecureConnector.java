package com.jlshell.link.transport;

import com.jlshell.link.core.transport.TransportBudget;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolConfig;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler;
import io.netty.handler.ssl.SslHandler;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

/**
 * Outbound WSS carrier for A and C. B authenticates and pairs both connections;
 * this class adds a separate pinned A-C TLS session and HTTP/2 on the opaque
 * binary relay. The caller owns the NIO event loop group and both SSL contexts.
 */
public final class WssSecureConnector {
    private WssSecureConnector() { }

    /** A-side connection. Complete only after outer WSS and inner mTLS/h2 are ready. */
    public static CompletionStage<Channel> connectClient(EventLoopGroup group, URI relayUri,
            SSLContext outerTls, HttpHeaders relayHeaders, SSLContext innerTls,
            String innerPeerHost, int innerPeerPort, TransportBudget budget, TlsHandshakeGate gate) {
        return connect(group, relayUri, outerTls, relayHeaders, innerTls, innerPeerHost,
                innerPeerPort, budget, gate, null);
    }

    /** C-side connection. Every CONNECT stream still requires the supplied authorizer. */
    public static CompletionStage<Channel> connectGateway(EventLoopGroup group, URI relayUri,
            SSLContext outerTls, HttpHeaders relayHeaders, SSLContext innerTls,
            String innerPeerHost, int innerPeerPort, TransportBudget budget, TlsHandshakeGate gate,
            ConnectStreamMultiplexer multiplexer) {
        return connect(group, relayUri, outerTls, relayHeaders, innerTls, innerPeerHost,
                innerPeerPort, budget, gate, Objects.requireNonNull(multiplexer, "multiplexer"));
    }

    private static CompletionStage<Channel> connect(EventLoopGroup group, URI relayUri,
            SSLContext outerTls, HttpHeaders relayHeaders, SSLContext innerTls,
            String innerPeerHost, int innerPeerPort, TransportBudget budget, TlsHandshakeGate gate,
            ConnectStreamMultiplexer multiplexer) {
        Objects.requireNonNull(group, "group");
        Objects.requireNonNull(relayUri, "relayUri");
        Objects.requireNonNull(outerTls, "outerTls");
        Objects.requireNonNull(relayHeaders, "relayHeaders");
        Objects.requireNonNull(innerTls, "innerTls");
        Objects.requireNonNull(budget, "budget");
        Objects.requireNonNull(gate, "gate");
        if (!"wss".equalsIgnoreCase(relayUri.getScheme()) || relayUri.getHost() == null
                || relayUri.getUserInfo() != null || relayUri.getRawQuery() != null
                || relayUri.getRawFragment() != null) {
            throw new IllegalArgumentException("relay endpoint must be a credential-free wss URI");
        }
        if (!relayHeaders.contains("Authorization")
                || relayHeaders.get("Authorization").isBlank()) {
            throw new IllegalArgumentException("relay authorization header is required");
        }
        int port = relayUri.getPort() < 0 ? 443 : relayUri.getPort();
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("invalid WSS port");
        }
        HttpHeaders headers = new DefaultHttpHeaders().add(relayHeaders);
        long timeout = timeoutMillis(budget.handshakeTimeout());
        int frameLimit = Math.min(budget.maxFrameBytes(), budget.maxBufferedBytesPerStream());
        WebSocketClientProtocolConfig webSocket = WebSocketClientProtocolConfig.newBuilder()
                .webSocketUri(relayUri)
                .customHeaders(headers)
                .allowExtensions(false)
                .maxFramePayloadLength(frameLimit)
                .handshakeTimeoutMillis(timeout)
                .handleCloseFrames(false)
                .dropPongFrames(false)
                .build();
        CompletableFuture<Channel> ready = new CompletableFuture<>();
        Bootstrap bootstrap = new Bootstrap()
                .group(group)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) Math.min(Integer.MAX_VALUE, timeout))
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) {
                        SSLEngine engine = outerTls.createSSLEngine(relayUri.getHost(), port);
                        engine.setUseClientMode(true);
                        SSLParameters parameters = engine.getSSLParameters();
                        parameters.setProtocols(new String[] {"TLSv1.3"});
                        parameters.setEndpointIdentificationAlgorithm("HTTPS");
                        engine.setSSLParameters(parameters);
                        SslHandler outerHandler = new SslHandler(engine);
                        outerHandler.setHandshakeTimeoutMillis(timeout);
                        channel.pipeline().addLast("jlshell-link-wss-tls", outerHandler);
                        channel.pipeline().addLast("jlshell-link-wss-http",
                                new HttpClientCodec(4_096, budget.maxHeaderBytes(), frameLimit));
                        channel.pipeline().addLast("jlshell-link-wss-aggregate",
                                new HttpObjectAggregator(budget.maxHeaderBytes()));
                        channel.pipeline().addLast("jlshell-link-wss-protocol",
                                new WebSocketClientProtocolHandler(webSocket));
                        channel.pipeline().addLast("jlshell-link-wss-ready",
                                new ReadyHandler(ready, innerTls, innerPeerHost, innerPeerPort,
                                        budget, gate, multiplexer));
                        channel.closeFuture().addListener(ignored -> ready.completeExceptionally(
                                new IOException("WSS carrier closed before inner HTTP/2 was ready")));
                    }
                });
        ChannelFuture attempt = bootstrap.connect(relayUri.getHost(), port);
        attempt.addListener(connected -> {
            if (!connected.isSuccess()) {
                ready.completeExceptionally(connected.cause());
            }
        });
        ready.whenComplete((channel, error) -> {
            if (error != null) {
                attempt.channel().close();
            }
        });
        return ready;
    }

    private static long timeoutMillis(Duration timeout) {
        return Math.max(1, Math.min(Integer.MAX_VALUE, timeout.toMillis()));
    }

    private static final class ReadyHandler extends ChannelInboundHandlerAdapter {
        private final CompletableFuture<Channel> ready;
        private final SSLContext innerTls;
        private final String innerPeerHost;
        private final int innerPeerPort;
        private final TransportBudget budget;
        private final TlsHandshakeGate gate;
        private final ConnectStreamMultiplexer multiplexer;

        private ReadyHandler(CompletableFuture<Channel> ready, SSLContext innerTls,
                String innerPeerHost, int innerPeerPort, TransportBudget budget,
                TlsHandshakeGate gate, ConnectStreamMultiplexer multiplexer) {
            this.ready = ready;
            this.innerTls = innerTls;
            this.innerPeerHost = innerPeerHost;
            this.innerPeerPort = innerPeerPort;
            this.budget = budget;
            this.gate = gate;
            this.multiplexer = multiplexer;
        }

        @Override
        public void userEventTriggered(ChannelHandlerContext context, Object event) throws Exception {
            if (event != WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE) {
                context.fireUserEventTriggered(event);
                return;
            }
            try {
                context.pipeline().addBefore(context.name(), "jlshell-link-wss-bytes",
                        new WebSocketByteStreamCodec(budget));
                context.pipeline().remove(this);
                CompletionStage<Void> secure = multiplexer == null
                        ? SecureConnectPipeline.installClientOnActiveCarrier(context.pipeline(), innerTls,
                                innerPeerHost, innerPeerPort, budget, gate)
                        : SecureConnectPipeline.installServerOnActiveCarrier(context.pipeline(), innerTls,
                                innerPeerHost, innerPeerPort, budget, gate, multiplexer);
                secure.whenComplete((ignored, error) -> {
                    if (error == null) {
                        ready.complete(context.channel());
                    } else {
                        ready.completeExceptionally(error);
                        context.close();
                    }
                });
            } catch (RuntimeException error) {
                ready.completeExceptionally(error);
                context.close();
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext context, Throwable error) {
            ready.completeExceptionally(error);
            context.close();
        }
    }
}
