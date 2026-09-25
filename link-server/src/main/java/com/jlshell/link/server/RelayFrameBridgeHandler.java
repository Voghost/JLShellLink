package com.jlshell.link.server;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.TransportBufferBudget;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.util.ReferenceCountUtil;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/** Opaque, bounded WSS relay. It forwards binary ciphertext only and records byte counts without payloads. */
public final class RelayFrameBridgeHandler extends ChannelDuplexHandler {
    private final Channel peer;
    private final LinkSessionId sessionId;
    private final TunnelId tunnelId;
    private final UsageRecorder.Direction direction;
    private final TransportBufferBudget pairBudget;
    private final TransportBufferBudget serverBudget;
    private final UsageRecorder usage;
    private final int maxFrameBytes;
    private final AtomicBoolean closed = new AtomicBoolean();

    public RelayFrameBridgeHandler(Channel peer, LinkSessionId sessionId, TunnelId tunnelId,
            UsageRecorder.Direction direction, TransportBufferBudget pairBudget,
            TransportBufferBudget serverBudget, UsageRecorder usage, int maxFrameBytes) {
        this.peer = Objects.requireNonNull(peer, "peer");
        this.sessionId = Objects.requireNonNull(sessionId, "sessionId");
        this.tunnelId = Objects.requireNonNull(tunnelId, "tunnelId");
        this.direction = Objects.requireNonNull(direction, "direction");
        this.pairBudget = Objects.requireNonNull(pairBudget, "pairBudget");
        this.serverBudget = Objects.requireNonNull(serverBudget, "serverBudget");
        this.usage = Objects.requireNonNull(usage, "usage");
        if (maxFrameBytes < 1 || maxFrameBytes > 16_777_215) {
            throw new IllegalArgumentException("invalid maximum WebSocket frame length");
        }
        this.maxFrameBytes = maxFrameBytes;
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
        if (message instanceof BinaryWebSocketFrame frame) {
            forward(context, frame);
        } else if (message instanceof PingWebSocketFrame ping) {
            context.writeAndFlush(new PongWebSocketFrame(ping.content().retainedDuplicate()));
            ping.release();
        } else if (message instanceof PongWebSocketFrame pong) {
            pong.release();
        } else if (message instanceof CloseWebSocketFrame close) {
            close.release();
            closePair(context);
        } else {
            ReferenceCountUtil.release(message);
            closePair(context);
        }
    }

    private void forward(ChannelHandlerContext context, BinaryWebSocketFrame frame) {
        ByteBuf payload = frame.content();
        int bytes = payload.readableBytes();
        if (frame.rsv() != 0 || bytes > maxFrameBytes) {
            frame.release();
            closePair(context);
            return;
        }
        if (bytes == 0) {
            peer.writeAndFlush(new BinaryWebSocketFrame(payload.retainedDuplicate()));
            frame.release();
            return;
        }
        boolean pairReserved = pairBudget.tryReserve(bytes);
        boolean serverReserved = pairReserved && serverBudget.tryReserve(bytes);
        if (!pairReserved || !serverReserved) {
            if (pairReserved) pairBudget.release(bytes);
            frame.release();
            closePair(context);
            return;
        }
        if (!peer.isWritable()) context.channel().config().setAutoRead(false);
        peer.writeAndFlush(new BinaryWebSocketFrame(payload.retainedDuplicate())).addListener(result -> {
            pairBudget.release(bytes);
            serverBudget.release(bytes);
            if (result.isSuccess()) {
                try {
                    usage.record(sessionId, tunnelId, direction, bytes);
                } catch (RuntimeException ignored) {
                    // Usage recording must never block or change an already-authorized data path.
                }
                if (context.channel().isActive() && peer.isWritable()
                        && pairBudget.inUseBytes() < pairBudget.limitBytes() / 2
                        && serverBudget.inUseBytes() < serverBudget.limitBytes() / 2) {
                    context.channel().eventLoop().execute(() -> context.channel().config().setAutoRead(true));
                }
            } else {
                closePair(context);
            }
        });
        frame.release();
    }

    private void closePair(ChannelHandlerContext context) {
        if (closed.compareAndSet(false, true)) {
            context.close();
            peer.close();
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext context) throws Exception {
        closePair(context);
        context.fireChannelInactive();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
        closePair(context);
    }
}
