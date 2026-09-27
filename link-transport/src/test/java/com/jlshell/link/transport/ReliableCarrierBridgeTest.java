package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.jlshell.link.core.transport.TransportBudget;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.DefaultEventLoopGroup;
import io.netty.util.ReferenceCountUtil;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

class ReliableCarrierBridgeTest {
    private static final TransportBudget BUDGET = new TransportBudget(
            16_384, 8_192, 8, 131_072, 65_535, 262_144, 4, Duration.ofSeconds(5));

    @Test
    void bridgesNettyBytesInBothDirectionsOverReliableCarrier() throws Exception {
        MemoryDatagramPath[] paths = MemoryDatagramPath.pair();
        try (DefaultEventLoopGroup groupA = new DefaultEventLoopGroup(1);
                DefaultEventLoopGroup groupC = new DefaultEventLoopGroup(1);
                KcpReliableDuplexChannel kcpA = new KcpReliableDuplexChannel(0x4A4C5101, paths[0], BUDGET);
                KcpReliableDuplexChannel kcpC = new KcpReliableDuplexChannel(0x4A4C5101, paths[1], BUDGET);
                ReliableCarrierBridge bridgeA = ReliableCarrierBridge.open(groupA, kcpA, BUDGET)
                        .toCompletableFuture().get(5, TimeUnit.SECONDS);
                ReliableCarrierBridge bridgeC = ReliableCarrierBridge.open(groupC, kcpC, BUDGET)
                        .toCompletableFuture().get(5, TimeUnit.SECONDS)) {
            byte[] payload = new byte[48_321];
            for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i * 41 + (i >>> 4));
            CompletableFuture<byte[]> returned = new CompletableFuture<>();
            ByteArrayOutputStream receivedBytes = new ByteArrayOutputStream(payload.length);
            bridgeA.endpoint().pipeline().addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void channelRead(ChannelHandlerContext context, Object message) {
                    try {
                        ByteBuf bytes = (ByteBuf) message;
                        byte[] chunk = bytes(bytes);
                        receivedBytes.write(chunk, 0, chunk.length);
                        if (receivedBytes.size() >= payload.length) returned.complete(receivedBytes.toByteArray());
                    } finally {
                        ReferenceCountUtil.release(message);
                    }
                }
            });
            bridgeC.endpoint().pipeline().addLast(new ChannelInboundHandlerAdapter() {
                @Override
                public void channelRead(ChannelHandlerContext context, Object message) {
                    context.writeAndFlush(ReferenceCountUtil.retain(message));
                    ReferenceCountUtil.release(message);
                }
            });
            bridgeA.start().toCompletableFuture().get(5, TimeUnit.SECONDS);
            bridgeC.start().toCompletableFuture().get(5, TimeUnit.SECONDS);

            bridgeA.endpoint().writeAndFlush(Unpooled.wrappedBuffer(payload)).sync();

            assertArrayEquals(payload, returned.get(10, TimeUnit.SECONDS));
            bridgeA.close();
            bridgeC.close();
            bridgeA.closed().toCompletableFuture().get(5, TimeUnit.SECONDS);
            bridgeC.closed().toCompletableFuture().get(5, TimeUnit.SECONDS);
        } finally {
            paths[0].close();
            paths[1].close();
        }
    }

    private static byte[] bytes(ByteBuf value) {
        byte[] result = new byte[value.readableBytes()];
        value.getBytes(value.readerIndex(), result);
        return result;
    }

    private static final class MemoryDatagramPath implements DatagramPath {
        private final AtomicBoolean open = new AtomicBoolean(true);
        private MemoryDatagramPath peer;
        private volatile Consumer<ByteBuffer> receiver;
        private volatile Consumer<Throwable> failure;

        private static MemoryDatagramPath[] pair() {
            MemoryDatagramPath first = new MemoryDatagramPath();
            MemoryDatagramPath second = new MemoryDatagramPath();
            first.peer = second;
            second.peer = first;
            return new MemoryDatagramPath[] { first, second };
        }

        @Override
        public void setReceiver(Consumer<ByteBuffer> receiver, Consumer<Throwable> failure) {
            if (this.receiver != null) throw new IllegalStateException("receiver already installed");
            this.receiver = Objects.requireNonNull(receiver, "receiver");
            this.failure = Objects.requireNonNull(failure, "failure");
        }

        @Override
        public void send(ByteBuffer datagram) throws IOException {
            if (!open.get() || peer == null || !peer.open.get()) throw new IOException("datagram path is closed");
            byte[] copy = new byte[datagram.remaining()];
            datagram.asReadOnlyBuffer().get(copy);
            Consumer<ByteBuffer> target = peer.receiver;
            if (target == null) throw new IOException("peer datagram receiver is unavailable");
            try {
                target.accept(ByteBuffer.wrap(copy).asReadOnlyBuffer());
            } catch (RuntimeException error) {
                Consumer<Throwable> peerFailure = peer.failure;
                if (peerFailure != null) peerFailure.accept(error);
                throw error;
            }
        }

        @Override public boolean isOpen() { return open.get(); }

        @Override public void close() { open.set(false); }
    }
}
