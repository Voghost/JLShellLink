package com.jlshell.link.transport.poc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import kcp.IKcp;
import kcp.Kcp;
import org.junit.jupiter.api.Test;

class KcpDatagramAdapterTest {
    private static final int APPLICATION_QUEUE_CAPACITY = 4;

    @Test
    void kcpUsesTheIceSelectedDatagramChannels() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        DatagramChannel channelA = DatagramChannel.open();
        DatagramChannel channelC = DatagramChannel.open();
        channelA.bind(new InetSocketAddress(loopback, 0));
        channelC.bind(new InetSocketAddress(loopback, 0));
        SocketAddress addressA = channelA.getLocalAddress();
        SocketAddress addressC = channelC.getLocalAddress();
        byte[] payload = "same socket KCP probe".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        try (KcpPeer peerA = new KcpPeer(channelA, addressC);
                KcpPeer peerC = new KcpPeer(channelC, addressA)) {
            peerA.send(payload);

            byte[] received = peerC.received.poll(5, TimeUnit.SECONDS);
            assertNotNull(received, "KCP payload did not arrive");
            assertArrayEquals(payload, received);
            assertEquals(addressA, peerA.adapter.localAddress());
            assertEquals(addressC, peerC.adapter.localAddress());
        }
        assertFalse(channelA.isOpen());
        assertFalse(channelC.isOpen());
    }

    @Test
    void slowConsumerKeepsApplicationQueueBoundedAndPreservesTheStream() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        DatagramChannel channelA = DatagramChannel.open();
        DatagramChannel channelC = DatagramChannel.open();
        channelA.bind(new InetSocketAddress(loopback, 0));
        channelC.bind(new InetSocketAddress(loopback, 0));
        SocketAddress addressA = channelA.getLocalAddress();
        SocketAddress addressC = channelC.getLocalAddress();
        byte[] payload = new byte[256 * 1_024];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i * 19 + (i >>> 5));
        }

        try (KcpPeer peerA = new KcpPeer(channelA, addressC);
                KcpPeer peerC = new KcpPeer(channelC, addressA)) {
            peerA.send(payload);
            assertArrayEquals(payload, peerC.receiveExactly(payload.length, true));
            assertTrue(peerC.maxQueuedChunks.get() <= APPLICATION_QUEUE_CAPACITY,
                    "application receive queue exceeded its configured bound");
            assertTrue(peerC.deferredReads.get() > 0,
                    "slow consumer did not stop draining KCP's receive window");
        }
        assertFalse(channelA.isOpen());
        assertFalse(channelC.isOpen());
    }

    @Test
    void closingTheTransportCancelsABlockedReceiveAndReleasesItsResources() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        DatagramChannel channelA = DatagramChannel.open();
        DatagramChannel channelC = DatagramChannel.open();
        channelA.bind(new InetSocketAddress(loopback, 0));
        channelC.bind(new InetSocketAddress(loopback, 0));
        KcpPeer peerA = new KcpPeer(channelA, channelC.getLocalAddress());
        KcpPeer peerC = new KcpPeer(channelC, channelA.getLocalAddress());
        CompletableFuture<byte[]> blockedRead = CompletableFuture.supplyAsync(() -> {
            try {
                return peerC.receiveExactly(1, false);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new java.util.concurrent.CompletionException(e);
            }
        });
        Thread.sleep(50);
        peerC.close();
        try {
            java.util.concurrent.ExecutionException cancelled = assertThrows(
                    java.util.concurrent.ExecutionException.class,
                    () -> blockedRead.get(2, TimeUnit.SECONDS));
            assertTrue(cancelled.getCause() instanceof CancellationException,
                    "blocked receive did not report cancellation");
            assertFalse(channelC.isOpen(), "cancelled receive left the UDP socket open");
            assertTrue(peerC.closed.get(), "cancelled receive did not close its transport");
        } finally {
            peerA.close();
            peerC.close();
        }
        assertFalse(channelA.isOpen());
    }

    private static final class KcpPeer implements AutoCloseable {
        private final DatagramChannel channel;
        private final SocketAddress remote;
        private final Kcp engine;
        private final KcpDatagramAdapter adapter;
        private final ArrayBlockingQueue<byte[]> received = new ArrayBlockingQueue<>(APPLICATION_QUEUE_CAPACITY);
        private final AtomicInteger maxQueuedChunks = new AtomicInteger();
        private final AtomicInteger deferredReads = new AtomicInteger();
        private final AtomicBoolean closed = new AtomicBoolean();
        private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform().name("kcp-poc-timer-", 0).factory());
        private final IceDatagramDispatcher dispatcher;
        private final Thread receiveThread;

        private KcpPeer(DatagramChannel channel, SocketAddress remote) throws IOException {
            this.channel = channel;
            this.remote = remote;
            this.adapter = new KcpDatagramAdapter(channel, remote, this::receiveSegment);
            this.engine = new Kcp(0x4A4C5348, this::sendSegment);
            engine.nodelay(true, 10, 2, true);
            engine.setSndWnd(64);
            engine.setRcvWnd(64);
            engine.setMtu(1_200);
            engine.setStream(true);
            this.dispatcher = new IceDatagramDispatcher(channel, (source, packet) -> {}, adapter::receive, 1_200);
            this.receiveThread = Thread.ofVirtual().start(this::receiveLoop);
            timer.scheduleAtFixedRate(this::update, 0, 10, TimeUnit.MILLISECONDS);
        }

        private void send(byte[] payload) {
            synchronized (engine) {
                ByteBuf data = Unpooled.wrappedBuffer(payload.clone());
                int result = engine.send(data);
                data.release();
                if (result < 0) {
                    throw new IllegalStateException("KCP rejected the POC payload: " + result);
                }
                engine.update(System.currentTimeMillis());
            }
        }

        private void sendSegment(ByteBuf segment, IKcp ignored) {
            try {
                byte[] bytes = new byte[segment.readableBytes()];
                segment.getBytes(segment.readerIndex(), bytes);
                adapter.send(ByteBuffer.wrap(bytes));
            } catch (IOException e) {
                throw new IllegalStateException("Unable to send KCP datagram", e);
            } finally {
                segment.release();
            }
        }

        private void receiveSegment(ByteBuffer datagram) {
            byte[] bytes = new byte[datagram.remaining()];
            datagram.get(bytes);
            synchronized (engine) {
                engine.input(Unpooled.wrappedBuffer(bytes), true, System.currentTimeMillis());
                drainKcpToApplicationQueue();
                if (engine.checkFlush()) {
                    engine.flush(false, System.currentTimeMillis());
                }
            }
        }

        private void drainKcpToApplicationQueue() {
            while (received.remainingCapacity() > 0) {
                List<ByteBuf> completed = new ArrayList<>(1);
                int bytes = engine.recv(completed);
                if (bytes <= 0) {
                    break;
                }
                for (ByteBuf message : completed) {
                    try {
                        byte[] payload = new byte[message.readableBytes()];
                        message.readBytes(payload);
                        if (!received.offer(payload)) {
                            throw new IllegalStateException("bounded application queue rejected a KCP chunk");
                        }
                        maxQueuedChunks.accumulateAndGet(received.size(), Math::max);
                    } finally {
                        message.release();
                    }
                }
            }
            if (received.remainingCapacity() == 0 && engine.canRecv()) {
                deferredReads.incrementAndGet();
            }
        }

        private byte[] receiveExactly(int length, boolean slowConsumer) throws InterruptedException {
            byte[] result = new byte[length];
            int offset = 0;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
            while (offset < length && System.nanoTime() < deadline) {
                if (closed.get()) {
                    throw new CancellationException("KCP receive cancelled because the transport closed");
                }
                byte[] chunk = received.poll(100, TimeUnit.MILLISECONDS);
                if (chunk == null) {
                    continue;
                }
                int count = Math.min(chunk.length, length - offset);
                System.arraycopy(chunk, 0, result, offset, count);
                offset += count;
                if (slowConsumer) {
                    Thread.sleep(1);
                }
                synchronized (engine) {
                    drainKcpToApplicationQueue();
                    if (engine.checkFlush()) {
                        engine.flush(false, System.currentTimeMillis());
                    }
                }
            }
            return offset == length ? result : java.util.Arrays.copyOf(result, offset);
        }

        private void update() {
            synchronized (engine) {
                engine.update(System.currentTimeMillis());
            }
        }

        private void receiveLoop() {
            try {
                while (channel.isOpen()) {
                    dispatcher.dispatchOne();
                }
            } catch (IOException e) {
                if (channel.isOpen()) {
                    throw new IllegalStateException("KCP POC receiver failed", e);
                }
            }
        }

        @Override
        public void close() throws IOException {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            timer.shutdownNow();
            try {
                if (!timer.awaitTermination(1, TimeUnit.SECONDS)) {
                    throw new IOException("KCP POC timer did not stop");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while stopping KCP POC timer", e);
            }
            synchronized (engine) {
                engine.release();
            }
            dispatcher.close();
            try {
                receiveThread.join(1_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while stopping KCP POC receiver", e);
            }
        }
    }
}
