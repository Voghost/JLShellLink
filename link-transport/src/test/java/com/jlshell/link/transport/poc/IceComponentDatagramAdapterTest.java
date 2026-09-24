package com.jlshell.link.transport.poc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class IceComponentDatagramAdapterTest {
    @Test
    void exchangesLinkPacketsThroughIceCompatibleDatagramSockets() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (DatagramSocket socketA = new DatagramSocket(new InetSocketAddress(loopback, 0));
                DatagramSocket socketC = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
            var addressA = new InetSocketAddress(socketA.getLocalAddress(), socketA.getLocalPort());
            var addressC = new InetSocketAddress(socketC.getLocalAddress(), socketC.getLocalPort());
            byte[] payload = new byte[] {0x4a, 0x4c, 0, (byte) 0xff};
            ArrayBlockingQueue<byte[]> received = new ArrayBlockingQueue<>(1);
            IceComponentDatagramAdapter adapterA = new IceComponentDatagramAdapter(socketA, addressC, ignored -> {});
            IceComponentDatagramAdapter adapterC = new IceComponentDatagramAdapter(socketC, addressA, received::offer);
            FutureTask<Void> receiver = new FutureTask<>(() -> {
                adapterC.receiveOne(1_200);
                return null;
            });
            Thread.ofVirtual().start(receiver);

            adapterA.send(payload);
            receiver.get(5, TimeUnit.SECONDS);

            assertArrayEquals(payload, received.poll());
            assertEquals(socketC.getLocalPort(), ((InetSocketAddress) adapterC.localAddress()).getPort());
            assertEquals(socketA.getLocalPort(), ((InetSocketAddress) adapterA.localAddress()).getPort());
        }
    }

    @Test
    void leavesIceOwnedSocketLifecycleToItsComponent() throws Exception {
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (DatagramSocket componentSocket = new DatagramSocket(new InetSocketAddress(loopback, 0));
                DatagramSocket peer = new DatagramSocket(new InetSocketAddress(loopback, 0))) {
            IceComponentDatagramAdapter adapter = new IceComponentDatagramAdapter(
                    componentSocket, peer.getLocalSocketAddress(), ignored -> {});

            assertTrue(componentSocket.isBound());
            assertTrue(adapter.localAddress() instanceof InetSocketAddress);
        }
    }
}
