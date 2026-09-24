package com.jlshell.link.transport;

import com.jlshell.link.core.transport.ReliableDuplexChannel;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * Bounded byte-stream view over a Netty channel. Install after any framing or
 * TLS handlers that must consume/produce the bytes first. All channels for one
 * multiplexed connection should share a {@link TransportBufferBudget}. The
 * supplied output shutdown action maps half-close to the carrier protocol.
 */
public final class NettyReliableDuplexChannel implements ReliableDuplexChannel {
    private final Channel channel;
    private final TransportBudget budget;
    private final TransportBufferBudget sharedBufferBudget;
    private final Supplier<? extends CompletionStage<Void>> outputShutdown;
    private final ArrayDeque<ByteBuffer> inbound = new ArrayDeque<>();
    private final ArrayDeque<ReadRequest> readWaiters = new ArrayDeque<>();
    private final List<CompletableFuture<Void>> writableWaiters = new ArrayList<>();
    private final AtomicInteger queuedWriteBytes = new AtomicInteger();
    private final CompletableFuture<Void> closed = new CompletableFuture<>();
    private CompletableFuture<Void> writeTail = new CompletableFuture<>();

    private int bufferedReadBytes;
    private boolean inputClosed;
    private boolean outputClosed;
    private Throwable failure;

    public NettyReliableDuplexChannel(Channel channel, TransportBudget budget,
            Supplier<? extends CompletionStage<Void>> outputShutdown) {
        this(channel, budget, new TransportBufferBudget(budget.maxBufferedBytesTotal()), outputShutdown);
    }

    public NettyReliableDuplexChannel(Channel channel, TransportBudget budget,
            TransportBufferBudget sharedBufferBudget,
            Supplier<? extends CompletionStage<Void>> outputShutdown) {
        this.channel = Objects.requireNonNull(channel, "channel");
        this.budget = Objects.requireNonNull(budget, "budget");
        this.sharedBufferBudget = Objects.requireNonNull(sharedBufferBudget, "sharedBufferBudget");
        if (sharedBufferBudget.limitBytes() > budget.maxBufferedBytesTotal()) {
            throw new IllegalArgumentException("shared buffer ledger cannot exceed the transport total budget");
        }
        this.outputShutdown = Objects.requireNonNull(outputShutdown, "outputShutdown");
        writeTail.complete(null);
        channel.pipeline().addLast("jlshell-reliable-duplex", new InboundHandler());
        if (!channel.isOpen()) {
            inputClosed = true;
            closed.complete(null);
        }
    }

    @Override
    public CompletionStage<ByteBuffer> read(int maxBytes) {
        if (maxBytes <= 0) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("maxBytes must be positive"));
        }
        ReadRequest result = new ReadRequest(maxBytes);
        runOnEventLoop(() -> {
            if (result.isCancelled()) {
                return;
            }
            if (failure != null) {
                result.completeExceptionally(failure);
            } else {
                readWaiters.addLast(result);
                deliverReads();
            }
        }, result);
        result.whenComplete((ignored, error) -> {
            if (result.isCancelled()) {
                runOnEventLoop(() -> {
                    readWaiters.remove(result);
                    resumeReads();
                }, new CompletableFuture<>());
            } else {
                resumeReads();
            }
        });
        return result;
    }

    @Override
    public CompletionStage<Void> write(ByteBuffer data) {
        Objects.requireNonNull(data, "data");
        ByteBuffer source = data.asReadOnlyBuffer();
        int bytes = source.remaining();
        if (bytes == 0) {
            return CompletableFuture.completedFuture(null);
        }
        if (bytes > budget.maxQueuedWriteBytes()) {
            return CompletableFuture.failedFuture(new RejectedExecutionException("write exceeds transport queue budget"));
        }

        byte[] copy = new byte[bytes];
        source.get(copy);
        CompletableFuture<Void> result = new CompletableFuture<>();
        synchronized (this) {
            if (outputClosed || closed.isDone()) {
                return CompletableFuture.failedFuture(new IOException("channel output is closed"));
            }
            int queued = queuedWriteBytes.addAndGet(bytes);
            if (queued > budget.maxQueuedWriteBytes()) {
                queuedWriteBytes.addAndGet(-bytes);
                return CompletableFuture.failedFuture(new RejectedExecutionException("write queue is full"));
            }
            if (!sharedBufferBudget.tryReserve(bytes)) {
                queuedWriteBytes.addAndGet(-bytes);
                return CompletableFuture.failedFuture(new RejectedExecutionException("shared transport buffer budget is full"));
            }
            CompletionStage<Void> previous = writeTail;
            writeTail = new CompletableFuture<>();
            CompletableFuture<Void> tail = writeTail;
            previous.whenComplete((ignored, priorError) -> {
                if (priorError != null) {
                    finishWrite(copy, bytes, result, tail, priorError);
                    return;
                }
                runOnEventLoop(() -> {
                    if (failure != null || !channel.isActive()) {
                        finishWrite(copy, bytes, result, tail,
                                failure != null ? failure : new IOException("carrier is not active"));
                        return;
                    }
                    ByteBuf payload = Unpooled.wrappedBuffer(copy);
                    ChannelFuture future = channel.writeAndFlush(payload);
                    future.addListener(done -> {
                        if (done.isSuccess()) {
                            finishWrite(copy, bytes, result, tail, null);
                        } else {
                            finishWrite(copy, bytes, result, tail, done.cause());
                            abort(done.cause());
                        }
                    });
                }, result, copy, bytes, tail);
            });
        }
        return result;
    }

    @Override
    public CompletionStage<Void> whenWritable() {
        CompletableFuture<Void> result = new CompletableFuture<>();
        runOnEventLoop(() -> {
            if (failure != null) {
                result.completeExceptionally(failure);
            } else if (isWritable()) {
                result.complete(null);
            } else {
                writableWaiters.add(result);
            }
        }, result);
        return result;
    }

    @Override
    public CompletionStage<Void> shutdownOutput() {
        synchronized (this) {
            if (outputClosed) {
                return CompletableFuture.completedFuture(null);
            }
            outputClosed = true;
            CompletableFuture<Void> result = new CompletableFuture<>();
            writeTail.whenComplete((ignored, writeError) -> {
                if (writeError != null) {
                    result.completeExceptionally(writeError);
                    return;
                }
                runOnEventLoop(() -> {
                    if (failure != null) {
                        result.completeExceptionally(failure);
                        return;
                    }
                    try {
                        outputShutdown.get().whenComplete((done, error) -> {
                            if (error == null) {
                                result.complete(null);
                            } else {
                                result.completeExceptionally(error);
                                abort(error);
                            }
                        });
                    } catch (Throwable error) {
                        result.completeExceptionally(error);
                        abort(error);
                    }
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
        Throwable error = cause == null ? new IOException("channel aborted") : cause;
        runOnEventLoop(() -> fail(error), closed);
    }

    @Override
    public void close() {
        runOnEventLoop(() -> {
            inputClosed = true;
            discardInbound();
            while (!readWaiters.isEmpty()) {
                readWaiters.removeFirst().completeExceptionally(new CancellationException("channel closed"));
            }
            channel.close();
        }, closed);
    }

    private boolean isWritable() {
        return channel.isActive() && channel.isWritable()
                && queuedWriteBytes.get() < budget.maxQueuedWriteBytes();
    }

    private void finishWrite(byte[] copy, int bytes, CompletableFuture<Void> result,
            CompletableFuture<Void> tail, Throwable error) {
        queuedWriteBytes.addAndGet(-bytes);
        sharedBufferBudget.release(bytes);
        if (error == null) {
            result.complete(null);
            tail.complete(null);
        } else {
            result.completeExceptionally(error);
            tail.completeExceptionally(error);
        }
        runOnEventLoop(this::notifyWritable, result);
    }

    private void deliverReads() {
        while (!readWaiters.isEmpty()) {
            ReadRequest waiter = readWaiters.peekFirst();
            if (!inbound.isEmpty()) {
                ByteBuffer head = inbound.removeFirst();
                int count = Math.min(head.remaining(), requestedBytes(waiter));
                byte[] bytes = new byte[count];
                head.get(bytes);
                bufferedReadBytes -= count;
                if (head.hasRemaining()) {
                    inbound.addFirst(head);
                }
                sharedBufferBudget.release(count);
                readWaiters.removeFirst();
                waiter.complete(ByteBuffer.wrap(bytes).asReadOnlyBuffer());
                continue;
            }
            if (inputClosed) {
                readWaiters.removeFirst();
                waiter.complete(ByteBuffer.allocate(0).asReadOnlyBuffer());
                continue;
            }
            break;
        }
        resumeReads();
    }

    private int requestedBytes(ReadRequest waiter) {
        return waiter.maxBytes;
    }

    private void resumeReads() {
        if (!channel.eventLoop().inEventLoop()) {
            channel.eventLoop().execute(this::resumeReads);
            return;
        }
        if (bufferedReadBytes < budget.maxBufferedBytesPerStream() / 2 && channel.isActive()) {
            channel.config().setAutoRead(true);
        }
    }

    private void notifyWritable() {
        if (!channel.eventLoop().inEventLoop()) {
            channel.eventLoop().execute(this::notifyWritable);
            return;
        }
        if (failure != null) {
            writableWaiters.forEach(waiter -> waiter.completeExceptionally(failure));
            writableWaiters.clear();
        } else if (!channel.isActive()) {
            IOException error = new IOException("carrier is closed");
            writableWaiters.forEach(waiter -> waiter.completeExceptionally(error));
            writableWaiters.clear();
        } else if (isWritable()) {
            writableWaiters.forEach(waiter -> waiter.complete(null));
            writableWaiters.clear();
        }
    }

    private void fail(Throwable error) {
        if (failure != null || closed.isDone()) {
            return;
        }
        failure = error;
        inputClosed = true;
        discardInbound();
        bufferedReadBytes = 0;
        while (!readWaiters.isEmpty()) {
            readWaiters.removeFirst().completeExceptionally(error);
        }
        notifyWritable();
        closed.completeExceptionally(error);
        channel.close();
    }

    private void runOnEventLoop(Runnable action, CompletableFuture<?> result) {
        Runnable safe = () -> {
            try {
                action.run();
            } catch (Throwable error) {
                result.completeExceptionally(error);
            }
        };
        if (channel.eventLoop().inEventLoop()) {
            safe.run();
        } else {
            try {
                channel.eventLoop().execute(safe);
            } catch (RejectedExecutionException error) {
                result.completeExceptionally(error);
            }
        }
    }

    private void runOnEventLoop(Runnable action, CompletableFuture<Void> result,
            byte[] copy, int bytes, CompletableFuture<Void> tail) {
        Runnable safe = () -> {
            try {
                action.run();
            } catch (Throwable error) {
                if (result != null) {
                    result.completeExceptionally(error);
                }
                if (copy != null) {
                    finishWrite(copy, bytes, result, tail, error);
                }
            }
        };
        if (channel.eventLoop().inEventLoop()) {
            safe.run();
        } else {
            try {
                channel.eventLoop().execute(safe);
            } catch (RejectedExecutionException error) {
                if (result != null) {
                    result.completeExceptionally(error);
                }
                if (copy != null) {
                    finishWrite(copy, bytes, result, tail, error);
                }
            }
        }
    }

    private void discardInbound() {
        if (bufferedReadBytes > 0) {
            sharedBufferBudget.release(bufferedReadBytes);
        }
        inbound.clear();
        bufferedReadBytes = 0;
    }

    private final class InboundHandler extends ChannelInboundHandlerAdapter {
        @Override
        public void channelRead(ChannelHandlerContext context, Object message) {
            if (!(message instanceof ByteBuf buffer)) {
                context.fireChannelRead(message);
                return;
            }
            int length = buffer.readableBytes();
            if (length == 0) {
                ReferenceCountUtil.release(message);
                return;
            }
            if ((long) bufferedReadBytes + length > budget.maxBufferedBytesPerStream()) {
                ReferenceCountUtil.release(message);
                fail(new IOException("inbound transport queue budget exceeded"));
                return;
            }
            if (!sharedBufferBudget.tryReserve(length)) {
                ReferenceCountUtil.release(message);
                fail(new IOException("shared transport buffer budget exceeded"));
                return;
            }
            byte[] bytes = new byte[length];
            buffer.readBytes(bytes);
            ReferenceCountUtil.release(message);
            inbound.addLast(ByteBuffer.wrap(bytes));
            bufferedReadBytes += length;
            if (bufferedReadBytes >= budget.maxBufferedBytesPerStream()) {
                channel.config().setAutoRead(false);
            }
            deliverReads();
        }

        @Override
        public void channelWritabilityChanged(ChannelHandlerContext context) {
            notifyWritable();
            context.fireChannelWritabilityChanged();
        }

        @Override
        public void channelActive(ChannelHandlerContext context) {
            notifyWritable();
            context.fireChannelActive();
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) {
            inputClosed = true;
            deliverReads();
            notifyWritable();
            if (failure == null) {
                closed.complete(null);
            }
            context.fireChannelInactive();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
            fail(cause);
            context.fireExceptionCaught(cause);
        }
    }

    private static final class ReadRequest extends CompletableFuture<ByteBuffer> {
        private final int maxBytes;

        private ReadRequest(int maxBytes) {
            this.maxBytes = maxBytes;
        }
    }
}
