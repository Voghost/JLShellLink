package com.jlshell.link.transport.poc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import kcp.IKcp;
import kcp.Kcp;
import org.ice4j.ice.Agent;
import org.ice4j.ice.CandidateType;
import org.ice4j.ice.Component;
import org.ice4j.ice.IceMediaStream;
import org.ice4j.ice.KeepAliveStrategy;
import org.ice4j.ice.RemoteCandidate;
import org.junit.jupiter.api.Test;

/** API/socket lifecycle smoke test for the pinned ice4j candidate. */
class Ice4jCandidateGatherTest {
    @Test
    void gathersCandidatesAndNominatesAReachableLanPair() throws Exception {
        String activeIpv4Interface = Collections.list(NetworkInterface.getNetworkInterfaces()).stream()
                .filter(networkInterface -> {
                    try {
                        return networkInterface.isUp() && !networkInterface.isPointToPoint();
                    } catch (SocketException e) {
                        return false;
                    }
                })
                .filter(networkInterface -> Collections.list(networkInterface.getInetAddresses()).stream()
                        .anyMatch(address -> address instanceof Inet4Address && !address.isLoopbackAddress()))
                .map(NetworkInterface::getName)
                .findFirst().orElse(null);
        assumeTrue(activeIpv4Interface != null, "No active non-loopback IPv4 interface for ICE test");
        System.setProperty("ice4j.harvest.mapping.aws.enabled", "false");
        System.setProperty("org.ice4j.ice.harvest.ALLOWED_INTERFACES", activeIpv4Interface);
        System.setProperty("ice4j.harvest.use-ipv6", "false");
        System.setProperty("ice4j.harvest.use-link-local-addresses", "false");
        Agent agentA = new Agent();
        Agent agentC = new Agent();
        try {
            agentA.setControlling(true);
            agentC.setControlling(false);
            IceMediaStream streamA = agentA.createMediaStream("link");
            IceMediaStream streamC = agentC.createMediaStream("link");
            Component componentA = agentA.createComponent(streamA, 0, 0, 0,
                    KeepAliveStrategy.SELECTED_ONLY, true);
            Component componentC = agentC.createComponent(streamC, 0, 0, 0,
                    KeepAliveStrategy.SELECTED_ONLY, true);

            assertFalse(componentA.getLocalCandidates().isEmpty(), "ICE A gathered no local candidates");
            assertTrue(componentA.getLocalCandidates().stream()
                    .allMatch(candidate -> candidate.getTransportAddress().getPort() > 0));
            assertNotNull(componentA.getSocket(), "ICE component application socket is unavailable");
            assertNotNull(componentC.getSocket(), "ICE component application socket is unavailable");

            var localA = componentA.getLocalCandidates().stream()
                    .filter(candidate -> candidate.getType() == CandidateType.HOST_CANDIDATE)
                    .findFirst().orElseThrow();
            var localC = componentC.getLocalCandidates().stream()
                    .filter(candidate -> candidate.getType() == CandidateType.HOST_CANDIDATE)
                    .findFirst().orElseThrow();
            streamA.setRemoteUfrag(agentC.getLocalUfrag());
            streamA.setRemotePassword(agentC.getLocalPassword());
            streamC.setRemoteUfrag(agentA.getLocalUfrag());
            streamC.setRemotePassword(agentA.getLocalPassword());
            componentA.addRemoteCandidate(new RemoteCandidate(
                    localC.getTransportAddress(), componentA, CandidateType.HOST_CANDIDATE,
                    "peer-c", 2_130_706_431L, null));
            componentC.addRemoteCandidate(new RemoteCandidate(
                    localA.getTransportAddress(), componentC, CandidateType.HOST_CANDIDATE,
                    "peer-a", 2_130_706_431L, null));
            agentA.startConnectivityEstablishment();
            agentC.startConnectivityEstablishment();

            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (System.nanoTime() < deadline
                    && (componentA.getSelectedPair() == null || componentC.getSelectedPair() == null)) {
                Thread.sleep(20);
            }
            assertNotNull(componentA.getSelectedPair(), "ICE A did not nominate the reachable pair");
            assertNotNull(componentC.getSelectedPair(), "ICE C did not nominate the reachable pair");

            try (IceKcpPeer peerA = new IceKcpPeer(
                            componentA.getSocket(),
                            componentA.getSelectedPair().getRemoteCandidate().getTransportAddress(), true);
                    IceKcpPeer peerC = new IceKcpPeer(
                            componentC.getSocket(),
                            componentC.getSelectedPair().getRemoteCandidate().getTransportAddress(), false)) {
                byte[] payload = new byte[4_096];
                for (int i = 0; i < payload.length; i++) {
                    payload[i] = (byte) (i * 31 + (i >>> 3));
                }
                peerA.send(payload);
                assertArrayEquals(payload, peerC.receiveExactly(payload.length),
                        "KCP did not recover dropped data over the ICE component sockets");
                assertTrue(peerA.droppedPackets.get() == 1, "KCP loss injection did not run");
                byte[] response = new byte[777];
                for (int i = 0; i < response.length; i++) {
                    response[i] = (byte) (255 - i * 13);
                }
                peerC.send(response);
                assertArrayEquals(response, peerA.receiveExactly(response.length),
                        "KCP reverse stream did not preserve binary data");
            }
        } finally {
            agentA.free();
            agentC.free();
        }
        assertTrue(agentA.isOver(), "ICE A did not release its sockets");
        assertTrue(agentC.isOver(), "ICE C did not release its sockets");
    }

    private static final class IceKcpPeer implements AutoCloseable {
        private final DatagramSocket iceSocket;
        private final IceComponentDatagramAdapter adapter;
        private final Kcp engine;
        private final ArrayBlockingQueue<byte[]> received = new ArrayBlockingQueue<>(4);
        private final boolean dropFirstPacket;
        private final AtomicInteger droppedPackets = new AtomicInteger();
        private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform().name("ice-kcp-poc-timer-", 0).factory());
        private final AtomicBoolean closed = new AtomicBoolean();
        private final Thread receiver;

        private IceKcpPeer(
                DatagramSocket iceSocket,
                SocketAddress remote,
                boolean dropFirstPacket) throws SocketException {
            this.iceSocket = iceSocket;
            this.dropFirstPacket = dropFirstPacket;
            this.iceSocket.setSoTimeout(100);
            this.adapter = new IceComponentDatagramAdapter(iceSocket, remote, this::receiveSegment);
            this.engine = new Kcp(0x4A4C5348, this::sendSegment);
            engine.nodelay(true, 10, 2, true);
            engine.setSndWnd(64);
            engine.setRcvWnd(64);
            engine.setMtu(1_200);
            engine.setStream(true);
            this.receiver = Thread.ofVirtual().start(this::receiveLoop);
            timer.scheduleAtFixedRate(this::update, 0, 10, TimeUnit.MILLISECONDS);
        }

        private void send(byte[] payload) {
            synchronized (engine) {
                ByteBuf data = Unpooled.wrappedBuffer(payload.clone());
                int result = engine.send(data);
                data.release();
                if (result < 0) {
                    throw new IllegalStateException("KCP rejected payload: " + result);
                }
                engine.update(System.currentTimeMillis());
            }
        }

        private byte[] receiveExactly(int length) throws InterruptedException {
            byte[] result = new byte[length];
            int offset = 0;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (offset < length && System.nanoTime() < deadline) {
                byte[] chunk = received.poll(100, TimeUnit.MILLISECONDS);
                if (chunk == null) {
                    continue;
                }
                int copyLength = Math.min(chunk.length, length - offset);
                System.arraycopy(chunk, 0, result, offset, copyLength);
                offset += copyLength;
            }
            return offset == length ? result : java.util.Arrays.copyOf(result, offset);
        }

        private void sendSegment(ByteBuf segment, IKcp ignored) {
            try {
                byte[] datagram = new byte[segment.readableBytes()];
                segment.getBytes(segment.readerIndex(), datagram);
                if (dropFirstPacket && droppedPackets.compareAndSet(0, 1)) {
                    return;
                }
                adapter.send(datagram);
            } catch (IOException e) {
                throw new IllegalStateException("Unable to send KCP datagram over ICE socket", e);
            } finally {
                segment.release();
            }
        }

        private void receiveSegment(byte[] datagram) {
            synchronized (engine) {
                engine.input(Unpooled.wrappedBuffer(datagram), true, System.currentTimeMillis());
                int readable;
                do {
                    List<ByteBuf> completeMessages = new ArrayList<>();
                    readable = engine.recv(completeMessages);
                    for (ByteBuf message : completeMessages) {
                        try {
                            byte[] payload = new byte[message.readableBytes()];
                            message.readBytes(payload);
                            received.offer(payload);
                        } finally {
                            message.release();
                        }
                    }
                } while (readable > 0);
                if (engine.checkFlush()) {
                    engine.flush(false, System.currentTimeMillis());
                }
            }
        }

        private void receiveLoop() {
            while (!closed.get()) {
                try {
                    adapter.receiveOne(1_200);
                } catch (SocketTimeoutException ignored) {
                    // Polling timeout lets the POC stop without closing ICE-owned sockets.
                } catch (IOException e) {
                    if (!closed.get()) {
                        received.offer(new byte[0]);
                    }
                }
            }
        }

        private void update() {
            synchronized (engine) {
                if (!closed.get()) {
                    engine.update(System.currentTimeMillis());
                }
            }
        }

        @Override
        public void close() throws Exception {
            closed.set(true);
            timer.shutdownNow();
            if (!timer.awaitTermination(1, TimeUnit.SECONDS)) {
                throw new IOException("KCP timer did not stop");
            }
            receiver.join(1_000);
            if (receiver.isAlive()) {
                throw new IOException("KCP receiver did not stop");
            }
            synchronized (engine) {
                engine.release();
            }
        }
    }
}
