package com.jlshell.link.transport.poc;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * POC-only adapter for application datagrams on ice4j's component socket.
 * The socket is owned by the ICE component and multiplexes STUN away from
 * application packets; this adapter deliberately does not close it.
 */
public final class IceComponentDatagramAdapter {
    private final DatagramSocket componentSocket;
    private final SocketAddress selectedRemote;
    private final Consumer<byte[]> kcpInput;

    public IceComponentDatagramAdapter(
            DatagramSocket componentSocket,
            SocketAddress selectedRemote,
            Consumer<byte[]> kcpInput) {
        this.componentSocket = Objects.requireNonNull(componentSocket, "componentSocket");
        this.selectedRemote = Objects.requireNonNull(selectedRemote, "selectedRemote");
        this.kcpInput = Objects.requireNonNull(kcpInput, "kcpInput");
    }

    public void send(byte[] datagram) throws IOException {
        Objects.requireNonNull(datagram, "datagram");
        componentSocket.send(new DatagramPacket(datagram, datagram.length, selectedRemote));
    }

    /** Blocks for one application packet and ignores packets from other peers. */
    public void receiveOne(int maxDatagramBytes) throws IOException {
        if (maxDatagramBytes < 1 || maxDatagramBytes > 65_507) {
            throw new IllegalArgumentException("maxDatagramBytes must be between 1 and 65507");
        }
        byte[] bytes = new byte[maxDatagramBytes];
        DatagramPacket packet = new DatagramPacket(bytes, bytes.length);
        componentSocket.receive(packet);
        if (selectedRemote.equals(packet.getSocketAddress())) {
            byte[] datagram = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), packet.getOffset(), datagram, 0, packet.getLength());
            kcpInput.accept(datagram);
        }
    }

    public SocketAddress localAddress() {
        return new InetSocketAddress(componentSocket.getLocalAddress(), componentSocket.getLocalPort());
    }
}
