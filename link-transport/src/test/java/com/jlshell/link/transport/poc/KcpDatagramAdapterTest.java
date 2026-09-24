package com.jlshell.link.transport.poc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import kcp.IKcp;
import kcp.Kcp;
import org.junit.jupiter.api.Test;

class KcpDatagramAdapterTest {
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

    private static final class KcpPeer implements AutoCloseable {
        private final DatagramChannel channel;
        private final SocketAddress remote;
        private final Kcp engine;
        private final KcpDatagramAdapter adapter;
        private final ArrayBlockingQueue<byte[]> received = new ArrayBlockingQueue<>(4);
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
                List<ByteBuf> completed = new ArrayList<>();
                engine.recv(completed);
                for (ByteBuf message : completed) {
                    try {
                        byte[] payload = new byte[message.readableBytes()];
                        message.readBytes(payload);
                        received.offer(payload);
                    } finally {
                        message.release();
                    }
                }
                if (engine.checkFlush()) {
                    engine.flush(false, System.currentTimeMillis());
                }
            }
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
