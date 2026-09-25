package com.jlshell.link.transport;

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.ssl.SslHandler;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Bounds concurrent TLS handshakes for all channels sharing this gate. */
public final class TlsHandshakeGate {
    private final Semaphore permits;
    private final AtomicInteger inFlight = new AtomicInteger();

    public TlsHandshakeGate(int maxConcurrentHandshakes) {
        if (maxConcurrentHandshakes <= 0) {
            throw new IllegalArgumentException("maxConcurrentHandshakes must be positive");
        }
        permits = new Semaphore(maxConcurrentHandshakes);
    }

    /**
     * Install the gate immediately before TLS so channel activation is withheld
     * when the shared handshake budget is exhausted.
     */
    public void install(ChannelPipeline pipeline, SslHandler sslHandler) {
        Objects.requireNonNull(pipeline, "pipeline");
        Objects.requireNonNull(sslHandler, "sslHandler");
        if (pipeline.channel().isActive()) {
            throw new IllegalStateException("TLS handshake gate must be installed before channel activation");
        }
        pipeline.addLast("jlshell-link-tls-gate", newHandler(sslHandler));
        pipeline.addLast("jlshell-link-tls", sslHandler);
    }

    /**
     * Installs inner TLS after an outer carrier such as WSS has completed its
     * handshake. The permit is acquired before adding TLS to the active
     * channel, because SslHandler may start its handshake in handlerAdded.
     * Must run on the channel event loop.
     */
    boolean installOnActive(ChannelPipeline pipeline, SslHandler sslHandler, ChannelHandler afterTls) {
        Objects.requireNonNull(pipeline, "pipeline");
        Objects.requireNonNull(sslHandler, "sslHandler");
        Objects.requireNonNull(afterTls, "afterTls");
        if (!pipeline.channel().isActive() || !pipeline.channel().eventLoop().inEventLoop()) {
            throw new IllegalStateException("active TLS installation requires the active channel event loop");
        }
        if (!permits.tryAcquire()) {
            pipeline.channel().close();
            return false;
        }
        AtomicBoolean held = new AtomicBoolean(true);
        Runnable release = () -> {
            if (held.compareAndSet(true, false)) {
                inFlight.decrementAndGet();
                permits.release();
            }
        };
        inFlight.incrementAndGet();
        sslHandler.handshakeFuture().addListener(ignored -> release.run());
        pipeline.channel().closeFuture().addListener(ignored -> release.run());
        try {
            pipeline.addLast("jlshell-link-alpn", afterTls);
            pipeline.addBefore("jlshell-link-alpn", "jlshell-link-tls", sslHandler);
            return true;
        } catch (RuntimeException error) {
            release.run();
            pipeline.channel().close();
            throw error;
        }
    }

    /** Creates a per-channel handler backed by this gate's shared permit pool. */
    public ChannelHandler newHandler(SslHandler sslHandler) {
        return new GateHandler(Objects.requireNonNull(sslHandler, "sslHandler"));
    }

    public int inFlightHandshakes() {
        return inFlight.get();
    }

    private final class GateHandler extends ChannelInboundHandlerAdapter {
        private final SslHandler sslHandler;
        private final AtomicBoolean held = new AtomicBoolean();

        private GateHandler(SslHandler sslHandler) {
            this.sslHandler = sslHandler;
        }

        @Override
        public void channelActive(ChannelHandlerContext context) {
            if (!permits.tryAcquire()) {
                context.close();
                return;
            }
            held.set(true);
            inFlight.incrementAndGet();
            sslHandler.handshakeFuture().addListener(ignored -> release());
            context.fireChannelActive();
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) {
            release();
            context.fireChannelInactive();
        }

        @Override
        public void handlerRemoved(ChannelHandlerContext context) {
            release();
        }

        private void release() {
            if (held.compareAndSet(true, false)) {
                inFlight.decrementAndGet();
                permits.release();
            }
        }
    }
}
