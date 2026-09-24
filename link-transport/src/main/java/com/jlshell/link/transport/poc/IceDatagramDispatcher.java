package com.jlshell.link.transport.poc;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.Objects;
import java.util.function.BiConsumer;

/**
 * POC-only receive dispatcher proving ICE/STUN and Link packets can share one
 * bound UDP socket. It does not implement ICE or the KCP wire protocol.
 */
public final class IceDatagramDispatcher implements AutoCloseable {
    private final DatagramChannel channel;
    private final BiConsumer<SocketAddress, ByteBuffer> stunReceiver;
    private final BiConsumer<SocketAddress, ByteBuffer> linkReceiver;
    private final ByteBuffer receiveBuffer;

    public IceDatagramDispatcher(
            DatagramChannel channel,
            BiConsumer<SocketAddress, ByteBuffer> stunReceiver,
            BiConsumer<SocketAddress, ByteBuffer> linkReceiver,
            int maxDatagramBytes) {
        this.channel = Objects.requireNonNull(channel, "channel");
        this.stunReceiver = Objects.requireNonNull(stunReceiver, "stunReceiver");
        this.linkReceiver = Objects.requireNonNull(linkReceiver, "linkReceiver");
        if (maxDatagramBytes < 20 || maxDatagramBytes > 65_507) {
            throw new IllegalArgumentException("maxDatagramBytes must be between 20 and 65507");
        }
        this.receiveBuffer = ByteBuffer.allocateDirect(maxDatagramBytes);
    }

    /** Blocks until one datagram arrives, dispatches it, and returns its source. */
    public SocketAddress dispatchOne() throws IOException {
        receiveBuffer.clear();
        SocketAddress source = channel.receive(receiveBuffer);
        if (source == null) {
            return null;
        }
        receiveBuffer.flip();
        ByteBuffer packet = ByteBuffer.allocate(receiveBuffer.remaining());
        packet.put(receiveBuffer).flip();
        if (isStun(packet)) {
            stunReceiver.accept(source, packet.asReadOnlyBuffer());
        } else {
            linkReceiver.accept(source, packet.asReadOnlyBuffer());
        }
        return source;
    }

    public SocketAddress localAddress() throws IOException {
        return channel.getLocalAddress();
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }

    static boolean isStun(ByteBuffer packet) {
        if (packet.remaining() < 20) {
            return false;
        }
        int start = packet.position();
        int first = Byte.toUnsignedInt(packet.get(start));
        int cookie = packet.getInt(start + 4);
        return (first & 0xC0) == 0 && cookie == 0x2112A442;
    }
}
