package com.jlshell.link.transport.poc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.FutureTask;
import org.junit.jupiter.api.Test;

class IceDatagramDispatcherTest {
    @Test
    void dispatchesStunAndLinkDatagramsFromTheSameBoundSocket() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        DatagramChannel shared = DatagramChannel.open();
        shared.bind(new InetSocketAddress(loopback, 0));
        SocketAddress boundAddress = shared.getLocalAddress();
        ArrayBlockingQueue<byte[]> stunPackets = new ArrayBlockingQueue<>(1);
        ArrayBlockingQueue<byte[]> linkPackets = new ArrayBlockingQueue<>(1);
        FutureTask<Void> receiver;

        try (IceDatagramDispatcher dispatcher = new IceDatagramDispatcher(
                shared,
                (source, packet) -> stunPackets.offer(bytes(packet)),
                (source, packet) -> linkPackets.offer(bytes(packet)),
                1_200)) {
            receiver = new FutureTask<>(() -> {
                dispatcher.dispatchOne();
                dispatcher.dispatchOne();
                return null;
            });
            Thread thread = Thread.ofVirtual().start(receiver);

            try (DatagramChannel sender = DatagramChannel.open()) {
                sender.bind(new InetSocketAddress(loopback, 0));
                sender.send(stunBindingRequest(), boundAddress);
                sender.send(ByteBuffer.wrap(new byte[] {0x4a, 0x4c, 0x01, 0x02}), boundAddress);
            }

            receiver.get();
            assertArrayEquals(stunBindingRequestBytes(), stunPackets.poll());
            assertArrayEquals(new byte[] {0x4a, 0x4c, 0x01, 0x02}, linkPackets.poll());
            assertEquals(boundAddress, dispatcher.localAddress());
        } finally {
            if (shared.isOpen()) {
                shared.close();
            }
        }
        assertFalse(shared.isOpen());
    }

    @Test
    void recognizesOnlyStunWithTheMagicCookieAndMinimumHeader() {
        assertTrue(IceDatagramDispatcher.isStun(stunBindingRequest()));
        assertFalse(IceDatagramDispatcher.isStun(ByteBuffer.wrap(new byte[] {0, 1, 2, 3})));
        ByteBuffer wrongCookie = stunBindingRequest();
        wrongCookie.putInt(4, 0x01020304);
        assertFalse(IceDatagramDispatcher.isStun(wrongCookie));
    }

    private static ByteBuffer stunBindingRequest() {
        return ByteBuffer.wrap(stunBindingRequestBytes());
    }

    private static byte[] stunBindingRequestBytes() {
        return new byte[] {
            0x00, 0x01, 0x00, 0x00,
            0x21, 0x12, (byte) 0xA4, 0x42,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C
        };
    }

    private static byte[] bytes(ByteBuffer source) {
        ByteBuffer copy = source.asReadOnlyBuffer();
        byte[] bytes = new byte[copy.remaining()];
        copy.get(bytes);
        return bytes;
    }
}
