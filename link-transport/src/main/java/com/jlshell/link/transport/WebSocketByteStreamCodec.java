package com.jlshell.link.transport;

import com.jlshell.link.core.transport.TransportBudget;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.ContinuationWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PingWebSocketFrame;
import io.netty.handler.codec.http.websocketx.PongWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.PromiseCombiner;
import java.io.IOException;
import java.util.Objects;

/**
 * Converts an authenticated WSS binary-message connection into an ordered byte
 * stream for the inner TLS handler. Install after the outer WebSocket protocol
 * handler and before the inner TLS handler. A new instance is required for each
 * connection. Configure the outer WebSocket decoder with the same frame bound
 * before it allocates payloads, and disable WebSocket compression extensions.
 * Outer WSS authentication and pairing are the caller's boundary.
 */
public final class WebSocketByteStreamCodec extends ChannelDuplexHandler {
    private final int maxFrameBytes;
    private final int maxMessageBytes;
    private final int maxQueuedWriteBytes;
    private long queuedWriteBytes;
    private long currentMessageBytes;
    private boolean inBinaryMessage;

    public WebSocketByteStreamCodec(TransportBudget budget) {
        Objects.requireNonNull(budget, "budget");
        maxFrameBytes = Math.min(budget.maxFrameBytes(), budget.maxBufferedBytesPerStream());
        maxMessageBytes = budget.maxBufferedBytesPerStream();
        maxQueuedWriteBytes = budget.maxQueuedWriteBytes();
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) throws Exception {
        if (message instanceof BinaryWebSocketFrame binary) {
            if (inBinaryMessage) {
                reject(context, binary, "new binary message before previous message ended");
                return;
            }
            acceptBinary(context, binary, !binary.isFinalFragment());
        } else if (message instanceof ContinuationWebSocketFrame continuation) {
            if (!inBinaryMessage) {
                reject(context, continuation, "unexpected WebSocket continuation");
                return;
            }
            acceptBinary(context, continuation, !continuation.isFinalFragment());
        } else if (message instanceof PingWebSocketFrame ping) {
            context.writeAndFlush(new PongWebSocketFrame(ping.content().retainedDuplicate()));
            ping.release();
        } else if (message instanceof PongWebSocketFrame pong) {
            pong.release();
        } else if (message instanceof CloseWebSocketFrame close) {
            close.release();
            context.close();
        } else {
            reject(context, message, "WSS Link carrier accepts only binary data");
        }
    }

    private void acceptBinary(ChannelHandlerContext context, WebSocketFrame frame, boolean moreFragments) {
        if (frame.rsv() != 0) {
            reject(context, frame, "WSS Link carrier does not allow WebSocket extensions");
            return;
        }
        int bytes = frame.content().readableBytes();
        if (bytes > maxFrameBytes || currentMessageBytes + bytes > maxMessageBytes) {
            reject(context, frame, "WSS binary message exceeds transport budget");
            return;
        }
        currentMessageBytes += bytes;
        inBinaryMessage = moreFragments;
        if (!moreFragments) {
            currentMessageBytes = 0;
        }
        if (bytes > 0) {
            context.fireChannelRead(frame.content().retain());
        }
        frame.release();
    }

    @Override
    public void write(ChannelHandlerContext context, Object message, ChannelPromise promise) {
        if (!(message instanceof ByteBuf bytes)) {
            ReferenceCountUtil.release(message);
            promise.tryFailure(new IOException("inner TLS must write bytes to the WSS carrier"));
            context.close();
            return;
        }
        int length = bytes.readableBytes();
        if (length == 0) {
            bytes.release();
            promise.trySuccess();
            return;
        }
        if (length > maxQueuedWriteBytes - queuedWriteBytes) {
            bytes.release();
            promise.tryFailure(new IOException("WSS output queue exceeds transport budget"));
            context.close();
            return;
        }
        queuedWriteBytes += length;
        promise.addListener(done -> {
            queuedWriteBytes -= length;
            if (!done.isSuccess()) {
                context.close();
            }
        });
        PromiseCombiner writes = new PromiseCombiner(context.executor());
        try {
            while (bytes.isReadable()) {
                ByteBuf slice = bytes.readRetainedSlice(Math.min(bytes.readableBytes(), maxFrameBytes));
                BinaryWebSocketFrame frame = new BinaryWebSocketFrame(slice);
                ChannelPromise part = context.newPromise();
                writes.add((Future<Void>) part);
                try {
                    context.write(frame, part);
                } catch (Throwable error) {
                    frame.release();
                    part.tryFailure(error);
                    throw error;
                }
            }
            writes.finish(promise);
        } catch (Throwable error) {
            promise.tryFailure(error);
            context.close();
        } finally {
            bytes.release();
        }
    }

    private static void reject(ChannelHandlerContext context, Object message, String reason) {
        ReferenceCountUtil.release(message);
        context.fireExceptionCaught(new CorruptedFrameException(reason));
        context.close();
    }
}
