package com.jlshell.link.transport;

import com.jlshell.link.core.transport.ReliableDuplexChannel;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import kcp.IKcp;
import kcp.Kcp;

/**
 * Reliable byte-stream adapter for a nominated ICE datagram path. KCP carries
 * bounded DATA/EOF messages; TLS is layered above this API and supplies all
 * identity and confidentiality guarantees. The conversation ID must be a
 * fresh, unpredictable value exchanged by the authenticated session setup.
 */
public final class KcpReliableDuplexChannel implements ReliableDuplexChannel {
    private static final int KCP_MTU = 1_200;
    private static final int DATA = 1;
    private static final int EOF = 2;
    private static final int KCP_TICK_MILLIS = 10;

    private final DatagramPath path;
    private final TransportBudget budget;
    private final TransportBufferBudget sharedBudget;
    private final int maxPayloadBytes;
    private final ScheduledThreadPoolExecutor loop;
    private final ArrayBlockingQueue<byte[]> inboundDatagrams;
    private final AtomicLong inboundDatagramBytes = new AtomicLong();
    private final AtomicReference<Throwable> pathFailure = new AtomicReference<>();
    private final AtomicInteger pendingApiOperations = new AtomicInteger();
    private final AtomicInteger pendingWriteCount = new AtomicInteger();
    private final int maxPendingApiOperations;
    private final ArrayDeque<ByteBuffer> inbound = new ArrayDeque<>();
    private final ArrayDeque<ReadRequest> readers = new ArrayDeque<>();
    private final ArrayDeque<PendingWrite> pendingWrites = new ArrayDeque<>();
    private final ArrayList<CompletableFuture<Void>> writableWaiters = new ArrayList<>();
    private final CompletableFuture<Void> closed = new CompletableFuture<>();
    private final Object submissionLock = new Object();
    private final AtomicInteger queuedWriteBytes = new AtomicInteger();
    private final CompletableFuture<Void> outputShutdown = new CompletableFuture<>();
    private final Kcp engine;
    private int bufferedReadBytes;
    private boolean inputClosed;
    private boolean outputShutdownRequested;
    private boolean outputEofSent;
    private boolean outputClosed;
    private volatile boolean terminated;
    private boolean orderlyClosed;

    public KcpReliableDuplexChannel(int conversationId, DatagramPath path, TransportBudget budget) throws IOException {
        this(conversationId, path, budget, new TransportBufferBudget(budget.maxBufferedBytesTotal()));
    }

    public KcpReliableDuplexChannel(int conversationId, DatagramPath path, TransportBudget budget,
            TransportBufferBudget sharedBudget) throws IOException {
        if (conversationId == 0) {
            throw new IllegalArgumentException("conversationId must be non-zero");
        }
        this.path = Objects.requireNonNull(path, "path");
        this.budget = Objects.requireNonNull(budget, "budget");
        this.sharedBudget = Objects.requireNonNull(sharedBudget, "sharedBudget");
        if (budget.maxBufferedBytesTotal() < KCP_MTU) {
            throw new IllegalArgumentException("total transport budget must hold at least one KCP datagram");
        }
        if (sharedBudget.limitBytes() > budget.maxBufferedBytesTotal()) {
            throw new IllegalArgumentException("shared buffer ledger cannot exceed the channel total budget");
        }
        this.maxPayloadBytes = Math.min(budget.maxFrameBytes(), budget.maxBufferedBytesPerStream());
        this.maxPendingApiOperations = Math.max(32, Math.min(4_096, budget.maxConcurrentStreams() * 8));
        long maxDatagramQueueBytes = budget.maxBufferedBytesTotal();
        int datagramQueueCapacity = (int) Math.max(1,
                Math.min(4_096, maxDatagramQueueBytes / KCP_MTU));
        this.inboundDatagrams = new ArrayBlockingQueue<>(datagramQueueCapacity);
        this.loop = new ScheduledThreadPoolExecutor(1,
                Thread.ofPlatform().name("jlshell-kcp-channel-" + Integer.toUnsignedString(conversationId))
                        .daemon().factory());
        this.loop.setRemoveOnCancelPolicy(true);
        this.engine = new Kcp(conversationId, this::sendSegment);
        this.engine.nodelay(true, KCP_TICK_MILLIS, 2, false);
        this.engine.setSndWnd(64);
        this.engine.setRcvWnd(64);
        this.engine.setMtu(KCP_MTU);
        this.engine.setStream(false);
        try {
            path.setReceiver(this::receiveDatagram, error -> pathFailure.compareAndSet(null, error));
        } catch (IOException | RuntimeException error) {
            engine.release();
            loop.shutdownNow();
            throw error;
        }
        loop.scheduleAtFixedRate(this::tick, KCP_TICK_MILLIS, KCP_TICK_MILLIS, TimeUnit.MILLISECONDS);
    }

    @Override
    public CompletionStage<ByteBuffer> read(int maxBytes) {
        if (maxBytes <= 0) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("maxBytes must be positive"));
        }
        if (terminated) {
            return orderlyClosed
                    ? CompletableFuture.completedFuture(ByteBuffer.allocate(0).asReadOnlyBuffer())
                    : CompletableFuture.failedFuture(new CancellationException("KCP channel is closed"));
        }
        ReadRequest result = new ReadRequest(maxBytes);
        executeBounded(() -> {
            if (result.isCancelled()) {
                return;
            }
            if (terminated) {
                if (orderlyClosed) {
                    result.complete(ByteBuffer.allocate(0).asReadOnlyBuffer());
                } else {
                    result.completeExceptionally(new CancellationException("KCP channel is closed"));
                }
                return;
            }
            if (readers.size() >= maxPendingApiOperations) {
                result.completeExceptionally(new RejectedExecutionException("KCP read queue is full"));
                return;
            }
            readers.addLast(result);
            deliverReads();
            drainKcpMessages();
        }, result);
        result.whenComplete((ignored, error) -> {
            if (result.isCancelled()) {
                executeBounded(() -> readers.remove(result), new CompletableFuture<>());
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
            return CompletableFuture.failedFuture(
                    new RejectedExecutionException("write exceeds KCP queue budget"));
        }
        CompletableFuture<Void> result = new CompletableFuture<>();
        synchronized (submissionLock) {
            if (terminated || outputShutdownRequested) {
                return CompletableFuture.failedFuture(new IOException("KCP channel output is closed"));
            }
            int queued = queuedWriteBytes.addAndGet(bytes);
            if (queued > budget.maxQueuedWriteBytes()) {
                queuedWriteBytes.addAndGet(-bytes);
                return CompletableFuture.failedFuture(
                        new RejectedExecutionException("KCP write queue is full"));
            }
            if (!sharedBudget.tryReserve(bytes)) {
                queuedWriteBytes.addAndGet(-bytes);
                return CompletableFuture.failedFuture(
                        new RejectedExecutionException("shared transport buffer budget is full"));
            }
            int writes = pendingWriteCount.incrementAndGet();
            if (writes > maxPendingApiOperations) {
                pendingWriteCount.decrementAndGet();
                releaseWrite(bytes);
                return CompletableFuture.failedFuture(
                        new RejectedExecutionException("KCP pending write count is full"));
            }
            byte[] copy;
            try {
                copy = new byte[bytes];
                source.get(copy);
            } catch (Throwable error) {
                pendingWriteCount.decrementAndGet();
                releaseWrite(bytes);
                throw error;
            }
            executeBounded(() -> sendWrite(copy, result), result, () -> {
                pendingWriteCount.decrementAndGet();
                releaseWrite(bytes);
            });
        }
        return result;
    }

    @Override
    public CompletionStage<Void> whenWritable() {
        CompletableFuture<Void> result = new CompletableFuture<>();
        executeBounded(() -> {
            if (terminated || outputShutdownRequested || outputClosed) {
                result.completeExceptionally(new IOException("KCP channel is closed"));
            } else if (isWritable()) {
                result.complete(null);
            } else if (writableWaiters.size() >= maxPendingApiOperations) {
                result.completeExceptionally(new RejectedExecutionException("KCP writable waiter queue is full"));
            } else {
                writableWaiters.add(result);
            }
        }, result);
        result.whenComplete((ignored, error) -> {
            if (result.isCancelled()) {
                executeBounded(() -> writableWaiters.remove(result), new CompletableFuture<>());
            }
        });
        return result;
    }

    @Override
    public CompletionStage<Void> shutdownOutput() {
        synchronized (submissionLock) {
            if (outputShutdownRequested) {
                return outputShutdown;
            }
            if (terminated) {
                return CompletableFuture.failedFuture(new IOException("KCP channel is closed"));
            }
            outputShutdownRequested = true;
            executeTerminal(this::maybeSendOutputEof, outputShutdown);
            return outputShutdown;
        }
    }

    @Override
    public CompletionStage<Void> closed() {
        return closed;
    }

    @Override
    public void abort(Throwable cause) {
        Throwable error = cause == null ? new IOException("KCP channel aborted") : cause;
        executeTerminal(() -> terminate(error));
    }

    @Override
    public void close() {
        executeTerminal(() -> terminate(null));
    }

    private void executeBounded(Runnable task, CompletableFuture<?> result) {
        executeBounded(task, result, () -> { });
    }

    private void executeBounded(Runnable task, CompletableFuture<?> result, Runnable rejectedCleanup) {
        int queued = pendingApiOperations.incrementAndGet();
        if (queued > maxPendingApiOperations) {
            pendingApiOperations.decrementAndGet();
            rejectedCleanup.run();
            result.completeExceptionally(new RejectedExecutionException("KCP operation queue is full"));
            return;
        }
        try {
            loop.execute(() -> {
                pendingApiOperations.decrementAndGet();
                try {
                    task.run();
                } catch (Throwable error) {
                    terminate(error);
                }
            });
        } catch (RejectedExecutionException error) {
            pendingApiOperations.decrementAndGet();
            rejectedCleanup.run();
            result.completeExceptionally(error);
        }
    }

    private void executeTerminal(Runnable task) {
        executeTerminal(task, null);
    }

    private void executeTerminal(Runnable task, CompletableFuture<?> rejectedResult) {
        try {
            loop.execute(task);
        } catch (RejectedExecutionException error) {
            path.close();
            if (rejectedResult != null) {
                rejectedResult.completeExceptionally(error);
            }
            closed.completeExceptionally(error);
        }
    }

    private void sendWrite(byte[] bytes, CompletableFuture<Void> result) {
        if (terminated || outputClosed) {
            releaseWrite(bytes.length);
            pendingWriteCount.decrementAndGet();
            result.completeExceptionally(new IOException("KCP channel output is closed"));
            return;
        }
        try {
            for (int offset = 0; offset < bytes.length; ) {
                int count = Math.min(maxPayloadBytes, bytes.length - offset);
                ByteBuf message = Unpooled.buffer(count + 1, count + 1);
                try {
                    message.writeByte(DATA).writeBytes(bytes, offset, count);
                    if (engine.send(message) < 0) {
                        throw new IOException("KCP rejected an outbound message");
                    }
                } finally {
                    message.release();
                }
                offset += count;
            }
            pendingWrites.addLast(new PendingWrite(bytes.length, result));
            engine.update(System.currentTimeMillis());
        } catch (Throwable error) {
            releaseWrite(bytes.length);
            pendingWriteCount.decrementAndGet();
            result.completeExceptionally(error);
            terminate(error);
        }
    }

    private void receiveDatagram(ByteBuffer datagram) {
        if (terminated || datagram.remaining() == 0 || datagram.remaining() > KCP_MTU) {
            return;
        }
        byte[] copy = new byte[datagram.remaining()];
        datagram.asReadOnlyBuffer().get(copy);
        long queued = inboundDatagramBytes.addAndGet(copy.length);
        if (queued > budget.maxBufferedBytesTotal() || !inboundDatagrams.offer(copy)) {
            inboundDatagramBytes.addAndGet(-copy.length);
            // UDP cannot apply backpressure; drop a full-queue packet and let KCP retransmit it.
        }
    }

    private void sendSegment(ByteBuf segment, IKcp ignored) {
        try {
            if (segment.readableBytes() > KCP_MTU) {
                throw new IOException("KCP emitted a datagram above the configured MTU");
            }
            path.send(segment.nioBuffer(segment.readerIndex(), segment.readableBytes()));
        } catch (Throwable error) {
            pathFailure.compareAndSet(null, error);
        } finally {
            segment.release();
        }
    }

    private void tick() {
        if (terminated) {
            return;
        }
        Throwable failedPath = pathFailure.getAndSet(null);
        if (failedPath != null) {
            terminate(failedPath);
            return;
        }
        long now = System.currentTimeMillis();
        byte[] packet;
        while ((packet = inboundDatagrams.poll()) != null) {
            inboundDatagramBytes.addAndGet(-packet.length);
            ByteBuf input = Unpooled.wrappedBuffer(packet);
            try {
                engine.input(input, true, now);
            } finally {
                input.release();
            }
        }
        engine.update(now);
        drainKcpMessages();
        completeAcknowledgedWrites();
        maybeSendOutputEof();
        notifyWritable();
        if (engine.getState() < 0) {
            terminate(new IOException("KCP peer stopped acknowledging data"));
        }
    }

    private void drainKcpMessages() {
        while (!terminated && engine.canRecv()) {
            int size = engine.peekSize();
            if (size <= 0) {
                return;
            }
            if (size > maxPayloadBytes + 1) {
                terminate(new IOException("KCP peer sent a message above the configured stream limit"));
                return;
            }
            if (size > 1 && bufferedReadBytes + size - 1 > budget.maxBufferedBytesPerStream()) {
                return;
            }
            if (size > 1 && !sharedBudget.tryReserve(size)) {
                return;
            }
            List<ByteBuf> fragments = new ArrayList<>();
            int received = engine.recv(fragments);
            if (received <= 0) {
                if (size > 1) {
                    sharedBudget.release(size);
                }
                return;
            }
            byte[] message = new byte[received];
            int offset = 0;
            try {
                for (ByteBuf fragment : fragments) {
                    int count = fragment.readableBytes();
                    fragment.readBytes(message, offset, count);
                    offset += count;
                }
            } finally {
                fragments.forEach(ByteBuf::release);
            }
            if (offset != received || received != size || received < 1) {
                if (size > 1) {
                    sharedBudget.release(size);
                }
                terminate(new IOException("invalid KCP message framing"));
                return;
            }
            int type = Byte.toUnsignedInt(message[0]);
            if (type == DATA && received > 1 && !inputClosed) {
                sharedBudget.release(1);
                byte[] payload = java.util.Arrays.copyOfRange(message, 1, message.length);
                bufferedReadBytes += payload.length;
                inbound.addLast(ByteBuffer.wrap(payload));
                deliverReads();
            } else if (type == EOF && received == 1 && !inputClosed) {
                inputClosed = true;
                deliverReads();
            } else {
                if (size > 1) {
                    sharedBudget.release(size);
                }
                terminate(new IOException("invalid or out-of-order KCP stream control message"));
                return;
            }
        }
    }

    private void deliverReads() {
        while (!readers.isEmpty()) {
            ReadRequest reader = readers.peekFirst();
            if (reader.isCancelled()) {
                readers.removeFirst();
                continue;
            }
            if (!inbound.isEmpty()) {
                ByteBuffer head = inbound.removeFirst();
                int count = Math.min(head.remaining(), reader.maxBytes);
                byte[] bytes = new byte[count];
                head.get(bytes);
                bufferedReadBytes -= count;
                sharedBudget.release(count);
                notifyWritable();
                if (head.hasRemaining()) {
                    inbound.addFirst(head);
                }
                readers.removeFirst();
                reader.complete(ByteBuffer.wrap(bytes).asReadOnlyBuffer());
                continue;
            }
            if (inputClosed || terminated) {
                readers.removeFirst();
                if (terminated && !orderlyClosed) {
                    reader.completeExceptionally(new CancellationException("KCP channel closed"));
                } else {
                    reader.complete(ByteBuffer.allocate(0).asReadOnlyBuffer());
                }
                continue;
            }
            break;
        }
        finishOrderlyIfDone();
    }

    private void completeAcknowledgedWrites() {
        if (engine.waitSnd() != 0) {
            return;
        }
        while (!pendingWrites.isEmpty()) {
            PendingWrite write = pendingWrites.removeFirst();
            releaseWrite(write.bytes);
            pendingWriteCount.decrementAndGet();
            write.result.complete(null);
        }
        notifyWritable();
        if (outputEofSent && !outputClosed) {
            outputClosed = true;
            outputShutdown.complete(null);
        }
        finishOrderlyIfDone();
    }

    private void maybeSendOutputEof() {
        if (terminated || !outputShutdownRequested || outputEofSent || !pendingWrites.isEmpty()
                || engine.waitSnd() != 0) {
            return;
        }
        ByteBuf message = Unpooled.buffer(1, 1).writeByte(EOF);
        try {
            if (engine.send(message) < 0) {
                throw new IOException("KCP rejected output EOF");
            }
            outputEofSent = true;
            engine.update(System.currentTimeMillis());
        } catch (Throwable error) {
            outputShutdown.completeExceptionally(error);
            terminate(error);
        } finally {
            message.release();
        }
    }

    private boolean isWritable() {
        return queuedWriteBytes.get() < budget.maxQueuedWriteBytes()
                && sharedBudget.inUseBytes() < sharedBudget.limitBytes();
    }

    private void notifyWritable() {
        if (!isWritable()) {
            return;
        }
        for (CompletableFuture<Void> waiter : List.copyOf(writableWaiters)) {
            if (writableWaiters.remove(waiter)) {
                waiter.complete(null);
            }
        }
    }

    private void finishOrderlyIfDone() {
        if (inputClosed && outputClosed && inbound.isEmpty() && !terminated) {
            orderlyClosed = true;
            terminate(null);
        }
    }

    private void releaseWrite(int bytes) {
        queuedWriteBytes.addAndGet(-bytes);
        sharedBudget.release(bytes);
    }

    private void terminate(Throwable cause) {
        if (terminated) {
            return;
        }
        terminated = true;
        path.close();
        loop.shutdown();
        engine.release();
        Throwable error = cause == null ? new CancellationException("KCP channel closed") : cause;
        while (!readers.isEmpty()) {
            ReadRequest reader = readers.removeFirst();
            reader.completeExceptionally(error);
        }
        while (!inbound.isEmpty()) {
            ByteBuffer data = inbound.removeFirst();
            int bytes = data.remaining();
            bufferedReadBytes -= bytes;
            sharedBudget.release(bytes);
        }
        while (!pendingWrites.isEmpty()) {
            PendingWrite write = pendingWrites.removeFirst();
            releaseWrite(write.bytes);
            pendingWriteCount.decrementAndGet();
            write.result.completeExceptionally(error);
        }
        for (CompletableFuture<Void> waiter : writableWaiters) {
            waiter.completeExceptionally(error);
        }
        writableWaiters.clear();
        outputShutdown.completeExceptionally(error);
        if (cause == null) {
            closed.complete(null);
        } else {
            closed.completeExceptionally(cause);
        }
    }

    private static final class ReadRequest extends CompletableFuture<ByteBuffer> {
        private final int maxBytes;

        private ReadRequest(int maxBytes) {
            this.maxBytes = maxBytes;
        }
    }

    private record PendingWrite(int bytes, CompletableFuture<Void> result) { }
}
