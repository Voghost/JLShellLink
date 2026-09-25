package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.core.transport.TransportBufferBudget;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

class KcpReliableDuplexChannelTest {
    private static final TransportBudget BUDGET = new TransportBudget(
            16_384, 8_192, 8, 131_072, 65_535, 262_144, 4, Duration.ofSeconds(5));

    @Test
    void directKcpUsesSharedReliableDuplexContractAndMapsHalfClose() throws Exception {
        LocalDatagramPath[] paths = LocalDatagramPath.pair(2, true);
        TransportBufferBudget shared = new TransportBufferBudget(BUDGET.maxBufferedBytesTotal());
        try (KcpReliableDuplexChannel client = new KcpReliableDuplexChannel(
                        0x4A4C0001, paths[0], BUDGET, shared);
                KcpReliableDuplexChannel gateway = new KcpReliableDuplexChannel(
                        0x4A4C0001, paths[1], BUDGET, shared)) {
            CompletableFuture<Void> echo = CompletableFuture.runAsync(() -> echoUntilHalfClosed(gateway));
            ReliableDuplexChannelContract.assertEchoAndHalfClose(client, payload(49_173));
            echo.get(10, TimeUnit.SECONDS);
            org.junit.jupiter.api.Assertions.assertEquals(2, paths[0].droppedPackets.get());
            org.junit.jupiter.api.Assertions.assertTrue(paths[0].reorderedPackets.get());
            client.closed().toCompletableFuture().get(5, TimeUnit.SECONDS);
            gateway.closed().toCompletableFuture().get(5, TimeUnit.SECONDS);
            org.junit.jupiter.api.Assertions.assertEquals(0, shared.inUseBytes());
        }
    }

    @Test
    void rejectsWritesLargerThanTheConfiguredQueueAndCancelsPendingReadsOnClose() throws Exception {
        TransportBudget smallBudget = new TransportBudget(
                1_024, 512, 4, 4, 8, 4_096, 2, Duration.ofSeconds(2));
        LocalDatagramPath[] paths = LocalDatagramPath.pair();
        try (KcpReliableDuplexChannel channel = new KcpReliableDuplexChannel(0x4A4C0002,
                paths[0], smallBudget)) {
            assertThrows(CompletionException.class, () -> channel.write(ByteBuffer.wrap(new byte[5]))
                    .toCompletableFuture().join());
            CompletableFuture<ByteBuffer> pendingRead = channel.read(1).toCompletableFuture();
            channel.close();
            assertThrows(CancellationException.class, pendingRead::join);
        } finally {
            paths[1].close();
        }
    }

    private static void echoUntilHalfClosed(KcpReliableDuplexChannel gateway) {
        try {
            while (true) {
                ByteBuffer part = gateway.read(4_096).toCompletableFuture().get(10, TimeUnit.SECONDS);
                if (!part.hasRemaining()) {
                    break;
                }
                gateway.write(part).toCompletableFuture().get(10, TimeUnit.SECONDS);
            }
            gateway.shutdownOutput().toCompletableFuture().get(10, TimeUnit.SECONDS);
        } catch (Exception error) {
            throw new CompletionException(error);
        }
    }

    private static byte[] payload(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (i * 37 + (i >>> 5));
        }
        return bytes;
    }

    private static final class LocalDatagramPath implements DatagramPath {
        private final AtomicBoolean open = new AtomicBoolean(true);
        private final AtomicInteger outboundPackets = new AtomicInteger();
        private final AtomicInteger droppedPackets = new AtomicInteger();
        private final AtomicReference<byte[]> delayedPacket = new AtomicReference<>();
        private final AtomicBoolean reorderedPackets = new AtomicBoolean();
        private final int dropFirstPackets;
        private final boolean reorderFirstPair;
        private LocalDatagramPath peer;
        private volatile Consumer<ByteBuffer> receiver;
        private volatile Consumer<Throwable> failure;

        private static LocalDatagramPath[] pair() {
            return pair(0, false);
        }

        private static LocalDatagramPath[] pair(int dropFirstPackets, boolean reorderFirstPair) {
            LocalDatagramPath first = new LocalDatagramPath(dropFirstPackets, reorderFirstPair);
            LocalDatagramPath second = new LocalDatagramPath(0, false);
            first.peer = second;
            second.peer = first;
            return new LocalDatagramPath[] {first, second};
        }

        private LocalDatagramPath(int dropFirstPackets, boolean reorderFirstPair) {
            this.dropFirstPackets = dropFirstPackets;
            this.reorderFirstPair = reorderFirstPair;
        }

        private LocalDatagramPath() {
            this(0, false);
        }

        @Override
        public void setReceiver(Consumer<ByteBuffer> receiver, Consumer<Throwable> failure) {
            if (this.receiver != null) {
                throw new IllegalStateException("receiver already installed");
            }
            this.receiver = Objects.requireNonNull(receiver, "receiver");
            this.failure = Objects.requireNonNull(failure, "failure");
        }

        @Override
        public void send(ByteBuffer datagram) throws IOException {
            if (!isOpen() || !peer.isOpen()) {
                throw new IOException("test datagram path is closed");
            }
            Consumer<ByteBuffer> target = peer.receiver;
            if (target == null) {
                throw new IOException("peer receiver is not installed");
            }
            byte[] copy = new byte[datagram.remaining()];
            datagram.asReadOnlyBuffer().get(copy);
            if (outboundPackets.getAndIncrement() < dropFirstPackets) {
                droppedPackets.incrementAndGet();
                return;
            }
            byte[] delayed = delayedPacket.getAndSet(null);
            if (reorderFirstPair && !reorderedPackets.get()) {
                if (delayed == null) {
                    delayedPacket.set(copy);
                    return;
                }
                peer.deliver(copy);
                peer.deliver(delayed);
                reorderedPackets.set(true);
                return;
            }
            peer.deliver(copy);
        }

        private void deliver(byte[] copy) throws IOException {
            if (!isOpen()) {
                throw new IOException("test datagram path is closed");
            }
            Consumer<ByteBuffer> callback = receiver;
            if (callback == null) {
                throw new IOException("test datagram receiver is not installed");
            }
            callback.accept(ByteBuffer.wrap(copy).asReadOnlyBuffer());
        }

        @Override
        public boolean isOpen() {
            return open.get();
        }

        @Override
        public void close() {
            open.set(false);
        }
    }
}
