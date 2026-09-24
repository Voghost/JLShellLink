package com.jlshell.link.transport.poc;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.Objects;
import java.util.function.Consumer;

/** POC-only bridge for a future KCP engine and the ICE-selected UDP socket. */
public final class KcpDatagramAdapter {
    private final DatagramChannel sharedChannel;
    private final SocketAddress remote;
    private final Consumer<ByteBuffer> kcpInput;

    public KcpDatagramAdapter(
            DatagramChannel sharedChannel,
            SocketAddress remote,
            Consumer<ByteBuffer> kcpInput) {
        this.sharedChannel = Objects.requireNonNull(sharedChannel, "sharedChannel");
        this.remote = Objects.requireNonNull(remote, "remote");
        this.kcpInput = Objects.requireNonNull(kcpInput, "kcpInput");
    }

    public int send(ByteBuffer kcpSegment) throws IOException {
        return sharedChannel.send(kcpSegment, remote);
    }

    public void receive(SocketAddress source, ByteBuffer datagram) {
        if (remote.equals(source)) {
            kcpInput.accept(datagram.asReadOnlyBuffer());
        }
    }

    public SocketAddress localAddress() throws IOException {
        return sharedChannel.getLocalAddress();
    }
}
