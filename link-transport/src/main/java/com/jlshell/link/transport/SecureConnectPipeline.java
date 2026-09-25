package com.jlshell.link.transport;

import com.jlshell.link.core.transport.TransportBudget;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import io.netty.handler.codec.http2.Http2Settings;
import io.netty.handler.codec.http2.Http2StreamChannel;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;

/**
 * Installs the shared TLS 1.3 and HTTP/2 boundary on a Netty carrier channel.
 * Callers must create a fresh, peer-pinned context with {@code TlsPeerContext}
 * for each A-C session and share one handshake gate across their listener.
 */
public final class SecureConnectPipeline {
    private SecureConnectPipeline() { }

    /** Install before channel activation; open CONNECT streams only after the returned stage completes. */
    public static CompletionStage<Void> installClient(ChannelPipeline pipeline, SSLContext context, String peerHost,
            int peerPort, TransportBudget budget, TlsHandshakeGate gate) {
        return install(pipeline, context, peerHost, peerPort, true, budget, gate, null);
    }

    /** Install before channel activation; the authorizer belongs to this authenticated A-C session. */
    public static CompletionStage<Void> installServer(ChannelPipeline pipeline, SSLContext context, String peerHost,
            int peerPort, TransportBudget budget, TlsHandshakeGate gate,
            ConnectStreamMultiplexer multiplexer) {
        return install(pipeline, context, peerHost, peerPort, false, budget, gate,
                Objects.requireNonNull(multiplexer, "multiplexer"));
    }

    private static CompletionStage<Void> install(ChannelPipeline pipeline, SSLContext context, String peerHost,
            int peerPort, boolean client, TransportBudget budget, TlsHandshakeGate gate,
            ConnectStreamMultiplexer multiplexer) {
        Objects.requireNonNull(pipeline, "pipeline");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(budget, "budget");
        Objects.requireNonNull(gate, "gate");
        if (pipeline.channel().isActive()) {
            throw new IllegalStateException("secure pipeline must be installed before channel activation");
        }
        if (budget.maxFrameBytes() < 16_384 || budget.maxFrameBytes() > 16_777_215) {
            throw new IllegalArgumentException("HTTP/2 frame budget must be between 16384 and 16777215 bytes");
        }
        SslHandler tls = TlsPeerHandler.create(context, peerHost, peerPort, client, budget);
        CompletableFuture<Void> ready = new CompletableFuture<>();
        gate.install(pipeline, tls);
        pipeline.addLast("jlshell-link-alpn", new AlpnGate(tls, client, budget, multiplexer, ready));
        return ready;
    }

    private static final class AlpnGate extends ChannelInboundHandlerAdapter {
        private final SslHandler tls;
        private final boolean client;
        private final TransportBudget budget;
        private final ConnectStreamMultiplexer multiplexer;
        private final CompletableFuture<Void> ready;

        private AlpnGate(SslHandler tls, boolean client, TransportBudget budget,
                ConnectStreamMultiplexer multiplexer, CompletableFuture<Void> ready) {
            this.tls = tls;
            this.client = client;
            this.budget = budget;
            this.multiplexer = multiplexer;
            this.ready = ready;
        }

        @Override
        public void userEventTriggered(ChannelHandlerContext context, Object event) throws Exception {
            if (!(event instanceof SslHandshakeCompletionEvent handshake)) {
                context.fireUserEventTriggered(event);
                return;
            }
            if (!handshake.isSuccess()) {
                ready.completeExceptionally(handshake.cause());
                context.close();
                return;
            }
            if (!"h2".equals(tls.engine().getApplicationProtocol())) {
                SSLHandshakeException error = new SSLHandshakeException("Link requires negotiated h2 ALPN");
                ready.completeExceptionally(error);
                context.close();
                return;
            }
            try {
                if (client) {
                    Http2Settings settings = new Http2Settings()
                            .maxConcurrentStreams(budget.maxConcurrentStreams())
                            .maxFrameSize(budget.maxFrameBytes())
                            .initialWindowSize(budget.maxBufferedBytesPerStream())
                            .maxHeaderListSize(budget.maxHeaderBytes())
                            .pushEnabled(false);
                    context.pipeline().addAfter(context.name(), "jlshell-link-h2",
                            Http2FrameCodecBuilder.forClient().initialSettings(settings).build());
                    context.pipeline().addAfter("jlshell-link-h2", "jlshell-link-h2-streams",
                            new Http2MultiplexHandler(new ChannelInitializer<Http2StreamChannel>() {
                                @Override
                                protected void initChannel(Http2StreamChannel stream) {
                                    stream.close();
                                }
                            }));
                } else {
                    multiplexer.installServerPipeline(context.pipeline());
                }
            } catch (RuntimeException error) {
                ready.completeExceptionally(error);
                context.close();
                return;
            }
            context.pipeline().remove(this);
            ready.complete(null);
            context.fireUserEventTriggered(event);
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) throws Exception {
            ready.completeExceptionally(new IOException("carrier closed before secure HTTP/2 was ready"));
            context.fireChannelInactive();
        }
    }
}
