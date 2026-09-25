package com.jlshell.link.transport;

import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.ReliableDuplexChannel;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.Http2DataFrame;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2ResetFrame;
import io.netty.handler.codec.http2.Http2StreamChannel;
import io.netty.handler.codec.http2.Http2StreamChannelBootstrap;
import io.netty.util.ReferenceCountUtil;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Opens bounded, independently authorized CONNECT streams on an authenticated HTTP/2 connection. */
public final class ConnectClientMultiplexer {
    private final Channel parent;
    private final TransportBudget budget;
    private final TransportBufferBudget sharedBuffers;
    private final AtomicInteger activeStreams = new AtomicInteger();

    public ConnectClientMultiplexer(Channel parent, TransportBudget budget,
            TransportBufferBudget sharedBuffers) {
        this.parent = Objects.requireNonNull(parent, "parent");
        this.budget = Objects.requireNonNull(budget, "budget");
        this.sharedBuffers = Objects.requireNonNull(sharedBuffers, "sharedBuffers");
        if (sharedBuffers.limitBytes() > budget.maxBufferedBytesTotal()) {
            throw new IllegalArgumentException("shared buffer ledger cannot exceed total transport budget");
        }
    }

    /**
     * Opens one authorized TCP tunnel. The HTTP/2 parent must already have its
     * client frame codec and multiplex handler installed.
     */
    public CompletionStage<ConnectTunnel> open(TargetEndpoint target, TunnelId tunnelId, String accessTicket) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(tunnelId, "tunnelId");
        if (accessTicket == null || accessTicket.isBlank()) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("accessTicket is required"));
        }
        if (!headersFitBudget(target, tunnelId, accessTicket)) {
            return CompletableFuture.failedFuture(
                    new RejectedExecutionException("CONNECT authorization headers exceed the header budget"));
        }
        if (!parent.isActive()) {
            return CompletableFuture.failedFuture(new IOException("HTTP/2 connection is not active"));
        }
        if (!reserveStreamSlot()) {
            return CompletableFuture.failedFuture(new RejectedExecutionException("HTTP/2 stream limit reached"));
        }

        AtomicBoolean released = new AtomicBoolean();
        Runnable releaseSlot = () -> {
            if (released.compareAndSet(false, true)) {
                activeStreams.decrementAndGet();
            }
        };
        ConnectTunnel tunnel = new ConnectTunnel(target, tunnelId, accessTicket, releaseSlot);
        tunnel.ready.whenComplete((opened, error) -> {
            if (tunnel.ready.isCancelled()) {
                tunnel.close();
            }
        });
        new Http2StreamChannelBootstrap(parent)
                .handler(tunnel)
                .open()
                .addListener(opened -> {
                    if (!opened.isSuccess()) {
                        releaseSlot.run();
                        tunnel.openFailed(opened.cause());
                        return;
                    }
                    Http2StreamChannel stream = (Http2StreamChannel) opened.getNow();
                    tunnel.streamOpened(stream);
                });
        return tunnel.ready;
    }

    public int activeStreams() {
        return activeStreams.get();
    }

    private boolean reserveStreamSlot() {
        while (true) {
            int active = activeStreams.get();
            if (active >= budget.maxConcurrentStreams()) {
                return false;
            }
            if (activeStreams.compareAndSet(active, active + 1)) {
                return true;
            }
        }
    }

    private boolean headersFitBudget(TargetEndpoint target, TunnelId tunnelId, String ticket) {
        String authority = target.address().indexOf(':') >= 0
                ? "[" + target.address() + "]:" + target.port()
                : target.address() + ":" + target.port();
        long total = headerSize(":method", "CONNECT")
                + headerSize(":authority", authority)
                + headerSize("x-jlshell-target-ip", target.address())
                + headerSize("x-jlshell-target-port", Integer.toString(target.port()))
                + headerSize("x-jlshell-tunnel-id", tunnelId.toString())
                + headerSize("x-jlshell-access-ticket", ticket);
        return total <= budget.maxHeaderBytes();
    }

    private static long headerSize(String name, String value) {
        return 32L + name.getBytes(StandardCharsets.UTF_8).length
                + value.getBytes(StandardCharsets.UTF_8).length;
    }

    public final class ConnectTunnel extends ChannelInboundHandlerAdapter implements ReliableDuplexChannel {
        private final TargetEndpoint target;
        private final TunnelId tunnelId;
        private final String accessTicket;
        private final Runnable releaseSlot;
        private final CompletableFuture<ConnectTunnel> ready = new CompletableFuture<>();
        private final CompletableFuture<Void> closed = new CompletableFuture<>();
        private final ArrayDeque<HeldData> inbound = new ArrayDeque<>();
        private final ArrayDeque<ReadWaiter> readWaiters = new ArrayDeque<>();
        private final ArrayDeque<CompletableFuture<Void>> writableWaiters = new ArrayDeque<>();
        private final AtomicInteger queuedWriteBytes = new AtomicInteger();
        private CompletableFuture<Void> writeTail = CompletableFuture.completedFuture(null);
        private Http2StreamChannel stream;
        private ScheduledFuture<?> responseTimeout;
        private volatile State state = State.OPENING;
        private Throwable failure;
        private int bufferedReadBytes;
        private boolean inputEnded;
        private boolean outputEnded;
        private boolean outputClosing;

        private ConnectTunnel(TargetEndpoint target, TunnelId tunnelId, String accessTicket, Runnable releaseSlot) {
            this.target = target;
            this.tunnelId = tunnelId;
            this.accessTicket = accessTicket;
            this.releaseSlot = releaseSlot;
        }

        private void streamOpened(Http2StreamChannel openedStream) {
            stream = openedStream;
            stream.closeFuture().addListener(ignored -> releaseSlot.run());
            if (state == State.CLOSED) {
                stream.close();
                releaseSlot.run();
                return;
            }
            long timeoutMillis = Math.max(1, budget.handshakeTimeout().toMillis());
            responseTimeout = stream.eventLoop().schedule(() -> {
                if (state == State.OPENING) {
                    fail(new IOException("CONNECT response timed out"));
                }
            }, timeoutMillis, TimeUnit.MILLISECONDS);

            String address = target.address().indexOf(':') >= 0
                    ? "[" + target.address() + "]:" + target.port()
                    : target.address() + ":" + target.port();
            Http2Headers headers = new DefaultHttp2Headers()
                    .method("CONNECT")
                    .authority(address)
                    .set("x-jlshell-target-ip", target.address())
                    .set("x-jlshell-target-port", Integer.toString(target.port()))
                    .set("x-jlshell-tunnel-id", tunnelId.toString())
                    .set("x-jlshell-access-ticket", accessTicket);
            stream.writeAndFlush(new io.netty.handler.codec.http2.DefaultHttp2HeadersFrame(headers))
                    .addListener(result -> {
                        if (!result.isSuccess()) {
                            fail(result.cause());
                        }
                    });
        }

        private void openFailed(Throwable cause) {
            failure = cause == null ? new IOException("HTTP/2 stream could not be opened") : cause;
            state = State.CLOSED;
            ready.completeExceptionally(failure);
            closed.completeExceptionally(failure);
        }

        @Override
        public void channelRead(ChannelHandlerContext context, Object message) {
            boolean release = true;
            try {
                if (message instanceof Http2HeadersFrame headers) {
                    onHeaders(headers);
                } else if (message instanceof Http2DataFrame data) {
                    release = !onData(data);
                } else if (message instanceof Http2ResetFrame) {
                    fail(new IOException("CONNECT stream was reset by peer"));
                } else {
                    fail(new IOException("unexpected frame on CONNECT stream"));
                }
            } catch (Throwable error) {
                fail(error);
            } finally {
                if (release) {
                    ReferenceCountUtil.release(message);
                }
            }
        }

        private void onHeaders(Http2HeadersFrame frame) {
            if (state != State.OPENING) {
                throw new IllegalStateException("duplicate CONNECT response headers");
            }
            CharSequence status = frame.headers().status();
            if (status == null || !"200".contentEquals(status)) {
                String value = status == null ? "missing" : status.toString();
                fail(new ConnectRejectedException(value));
                return;
            }
            if (frame.isEndStream()) {
                throw new IllegalStateException("successful CONNECT response ended before data phase");
            }
            state = State.OPEN;
            cancelResponseTimeout();
            ready.complete(this);
        }

        private boolean onData(Http2DataFrame frame) {
            if (state != State.OPEN || inputEnded) {
                fail(new IOException("DATA received outside an open CONNECT stream"));
                return false;
            }
            int length = frame.content().readableBytes();
            if (length > 0) {
                if ((long) bufferedReadBytes + length > budget.maxBufferedBytesPerStream()
                        || !sharedBuffers.tryReserve(length)) {
                    fail(new IOException("CONNECT inbound buffer budget exceeded"));
                    return false;
                }
                bufferedReadBytes += length;
                inbound.addLast(new HeldData(frame, length));
                if (bufferedReadBytes >= budget.maxBufferedBytesPerStream()) {
                    stream.config().setAutoRead(false);
                }
                if (frame.isEndStream()) {
                    inputEnded = true;
                }
                deliverReads();
                return true;
            }
            if (frame.isEndStream()) {
                inputEnded = true;
                deliverReads();
            }
            return false;
        }

        @Override
        public CompletionStage<ByteBuffer> read(int maxBytes) {
            if (maxBytes <= 0) {
                return CompletableFuture.failedFuture(new IllegalArgumentException("maxBytes must be positive"));
            }
            CompletableFuture<ByteBuffer> result = new CompletableFuture<>();
            executeOnStream(() -> {
                if (failure != null) {
                    result.completeExceptionally(failure);
                } else if (state == State.CLOSED && inbound.isEmpty() && !inputEnded) {
                    result.completeExceptionally(new CancellationException("CONNECT stream is closed"));
                } else {
                    readWaiters.addLast(new ReadWaiter(result, maxBytes));
                    deliverReads();
                }
            }, result);
            result.whenComplete((ignored, error) -> {
                if (result.isCancelled()) {
                    executeOnStream(() -> {
                        readWaiters.removeIf(waiter -> waiter.future() == result);
                        resumeReads();
                    }, new CompletableFuture<>());
                }
            });
            return result;
        }

        private void deliverReads() {
            while (!readWaiters.isEmpty()) {
                ReadWaiter waiter = readWaiters.peekFirst();
                HeldData head = inbound.peekFirst();
                if (head == null) {
                    if (inputEnded) {
                        readWaiters.removeFirst();
                        waiter.future().complete(ByteBuffer.allocate(0).asReadOnlyBuffer());
                        continue;
                    }
                    break;
                }
                ByteBuf content = head.frame().content();
                int count = Math.min(content.readableBytes(), waiter.maxBytes());
                byte[] data = new byte[count];
                content.readBytes(data);
                if (!content.isReadable()) {
                    inbound.removeFirst();
                    bufferedReadBytes -= head.reservedBytes();
                    sharedBuffers.release(head.reservedBytes());
                    ReferenceCountUtil.release(head.frame());
                }
                readWaiters.removeFirst();
                waiter.future().complete(ByteBuffer.wrap(data).asReadOnlyBuffer());
            }
            resumeReads();
        }

        private void resumeReads() {
            if (stream != null && bufferedReadBytes < Math.max(1, budget.maxBufferedBytesPerStream() / 2)
                    && stream.isActive()) {
                stream.config().setAutoRead(true);
            }
        }

        @Override
        public CompletionStage<Void> write(ByteBuffer data) {
            Objects.requireNonNull(data, "data");
            ByteBuffer source = data.asReadOnlyBuffer();
            int length = source.remaining();
            if (length == 0) {
                return CompletableFuture.completedFuture(null);
            }
            if (length > budget.maxQueuedWriteBytes()) {
                return CompletableFuture.failedFuture(
                        new RejectedExecutionException("write exceeds CONNECT queue budget"));
            }
            byte[] copy = new byte[length];
            source.get(copy);
            CompletableFuture<Void> result = new CompletableFuture<>();
            synchronized (this) {
                if (state != State.OPEN || outputClosing || outputEnded || closed.isDone()) {
                    return CompletableFuture.failedFuture(new IOException("CONNECT output is closed"));
                }
                int queued = queuedWriteBytes.addAndGet(length);
                if (queued > budget.maxQueuedWriteBytes()) {
                    queuedWriteBytes.addAndGet(-length);
                    return CompletableFuture.failedFuture(new RejectedExecutionException("CONNECT write queue is full"));
                }
                if (!sharedBuffers.tryReserve(length)) {
                    queuedWriteBytes.addAndGet(-length);
                    return CompletableFuture.failedFuture(
                            new RejectedExecutionException("shared transport buffer budget is full"));
                }
                CompletableFuture<Void> previous = writeTail;
                CompletableFuture<Void> tail = new CompletableFuture<>();
                writeTail = tail;
                previous.whenComplete((ignored, previousError) -> {
                    if (previousError != null) {
                        finishWrite(length, result, tail, previousError);
                        return;
                    }
                    executeWrite(copy, length, result, tail);
                });
            }
            return result;
        }

        private void executeWrite(byte[] copy, int length, CompletableFuture<Void> result,
                CompletableFuture<Void> tail) {
            Runnable operation = () -> {
                if (failure != null || state != State.OPEN || stream == null || !stream.isActive()) {
                    finishWrite(length, result, tail,
                            failure == null ? new IOException("CONNECT stream is not active") : failure);
                    return;
                }
                int chunks = (length + budget.maxFrameBytes() - 1) / budget.maxFrameBytes();
                AtomicInteger pending = new AtomicInteger(chunks);
                AtomicReference<Throwable> writeFailure = new AtomicReference<>();
                for (int offset = 0; offset < length;) {
                    int count = Math.min(budget.maxFrameBytes(), length - offset);
                    ByteBuf payload = Unpooled.wrappedBuffer(copy, offset, count);
                    Http2DataFrame frame = new DefaultHttp2DataFrame(payload, false);
                    try {
                        stream.writeAndFlush(frame).addListener(done -> {
                            if (!done.isSuccess()) {
                                writeFailure.compareAndSet(null, done.cause());
                            }
                            if (pending.decrementAndGet() == 0) {
                                Throwable error = writeFailure.get();
                                finishWrite(length, result, tail, error);
                            }
                        });
                    } catch (Throwable error) {
                        ReferenceCountUtil.release(frame);
                        writeFailure.compareAndSet(null, error);
                        if (pending.decrementAndGet() == 0) {
                            finishWrite(length, result, tail, writeFailure.get());
                        }
                    }
                    offset += count;
                }
            };
            try {
                stream.eventLoop().execute(operation);
            } catch (RejectedExecutionException error) {
                finishWrite(length, result, tail, error);
            }
        }

        private void finishWrite(int length, CompletableFuture<Void> result,
                CompletableFuture<Void> tail, Throwable error) {
            queuedWriteBytes.addAndGet(-length);
            sharedBuffers.release(length);
            if (error == null) {
                result.complete(null);
                tail.complete(null);
            } else {
                result.completeExceptionally(error);
                tail.completeExceptionally(error);
                fail(error);
            }
            executeOnStream(this::notifyWritable, new CompletableFuture<>());
        }

        @Override
        public CompletionStage<Void> whenWritable() {
            CompletableFuture<Void> result = new CompletableFuture<>();
            executeOnStream(() -> {
                if (failure != null) {
                    result.completeExceptionally(failure);
                } else if (isWritable()) {
                    result.complete(null);
                } else {
                    writableWaiters.addLast(result);
                }
            }, result);
            return result;
        }

        private boolean isWritable() {
            return stream != null && stream.isActive() && stream.isWritable()
                    && queuedWriteBytes.get() < budget.maxQueuedWriteBytes()
                    && sharedBuffers.inUseBytes() < sharedBuffers.limitBytes();
        }

        private void notifyWritable() {
            if (failure != null) {
                while (!writableWaiters.isEmpty()) {
                    writableWaiters.removeFirst().completeExceptionally(failure);
                }
            } else if (state == State.CLOSED || stream == null || !stream.isActive()) {
                IOException error = new IOException("CONNECT stream is closed");
                while (!writableWaiters.isEmpty()) {
                    writableWaiters.removeFirst().completeExceptionally(error);
                }
            } else if (isWritable()) {
                while (!writableWaiters.isEmpty()) {
                    writableWaiters.removeFirst().complete(null);
                }
            }
        }

        @Override
        public CompletionStage<Void> shutdownOutput() {
            synchronized (this) {
                if (outputEnded || outputClosing) {
                    return CompletableFuture.completedFuture(null);
                }
                if (state != State.OPEN) {
                    return CompletableFuture.failedFuture(new IOException("CONNECT stream is not open"));
                }
                outputClosing = true;
                CompletableFuture<Void> result = new CompletableFuture<>();
                writeTail.whenComplete((ignored, writeError) -> {
                    if (writeError != null) {
                        result.completeExceptionally(writeError);
                        return;
                    }
                    executeOnStream(() -> {
                        if (failure != null || stream == null || !stream.isActive()) {
                            result.completeExceptionally(
                                    failure == null ? new IOException("CONNECT stream is not active") : failure);
                            return;
                        }
                        stream.writeAndFlush(new DefaultHttp2DataFrame(Unpooled.buffer(0), true))
                                .addListener(done -> {
                                    if (done.isSuccess()) {
                                        outputEnded = true;
                                        result.complete(null);
                                    } else {
                                        result.completeExceptionally(done.cause());
                                        fail(done.cause());
                                    }
                                });
                    }, result);
                });
                return result;
            }
        }

        @Override
        public CompletionStage<Void> closed() {
            return closed;
        }

        @Override
        public void abort(Throwable cause) {
            fail(cause == null ? new IOException("CONNECT stream aborted") : cause);
        }

        @Override
        public void close() {
            executeOnStream(() -> {
                if (state == State.CLOSED) {
                    return;
                }
                state = State.CLOSED;
                cancelResponseTimeout();
                CancellationException cancelled = new CancellationException("CONNECT stream closed");
                discardInbound();
                while (!readWaiters.isEmpty()) {
                    readWaiters.removeFirst().future().completeExceptionally(cancelled);
                }
                while (!writableWaiters.isEmpty()) {
                    writableWaiters.removeFirst().completeExceptionally(cancelled);
                }
                if (!ready.isDone()) {
                    ready.completeExceptionally(cancelled);
                }
                if (stream != null) {
                    stream.close();
                } else {
                    releaseSlot.run();
                    closed.complete(null);
                }
            }, closed);
        }

        private void fail(Throwable cause) {
            if (stream != null && !stream.eventLoop().inEventLoop()) {
                executeOnStream(() -> fail(cause), new CompletableFuture<>());
                return;
            }
            if (state == State.CLOSED) {
                return;
            }
            failure = cause == null ? new IOException("CONNECT stream failed") : cause;
            state = State.CLOSED;
            cancelResponseTimeout();
            discardInbound();
            while (!readWaiters.isEmpty()) {
                readWaiters.removeFirst().future().completeExceptionally(failure);
            }
            notifyWritable();
            ready.completeExceptionally(failure);
            closed.completeExceptionally(failure);
            if (stream != null) {
                stream.close();
            } else {
                releaseSlot.run();
            }
        }

        private void discardInbound() {
            while (!inbound.isEmpty()) {
                HeldData frame = inbound.removeFirst();
                sharedBuffers.release(frame.reservedBytes());
                ReferenceCountUtil.release(frame.frame());
            }
            bufferedReadBytes = 0;
        }

        private void cancelResponseTimeout() {
            ScheduledFuture<?> timeout = responseTimeout;
            responseTimeout = null;
            if (timeout != null) {
                timeout.cancel(false);
            }
        }

        private void executeOnStream(Runnable task, CompletableFuture<?> result) {
            Http2StreamChannel current = stream;
            if (current == null || current.eventLoop().inEventLoop()) {
                try {
                    task.run();
                } catch (Throwable error) {
                    result.completeExceptionally(error);
                }
            } else {
                try {
                    current.eventLoop().execute(() -> {
                        try {
                            task.run();
                        } catch (Throwable error) {
                            result.completeExceptionally(error);
                        }
                    });
                } catch (RejectedExecutionException error) {
                    result.completeExceptionally(error);
                }
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) {
            cancelResponseTimeout();
            if (!ready.isDone()) {
                fail(new IOException("CONNECT stream closed before it was established"));
            } else if (failure == null) {
                inputEnded = true;
                state = State.CLOSED;
                deliverReads();
                notifyWritable();
                closed.complete(null);
            }
            releaseSlot.run();
            context.fireChannelInactive();
        }

        @Override
        public void channelWritabilityChanged(ChannelHandlerContext context) {
            notifyWritable();
            context.fireChannelWritabilityChanged();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
            fail(cause);
        }
    }

    private enum State { OPENING, OPEN, CLOSED }

    private record HeldData(Http2DataFrame frame, int reservedBytes) { }

    private record ReadWaiter(CompletableFuture<ByteBuffer> future, int maxBytes) { }

    private static final class ConnectRejectedException extends IOException {
        private static final long serialVersionUID = 1L;

        private ConnectRejectedException(String status) {
            super("CONNECT rejected with HTTP/2 status " + status);
        }
    }
}
