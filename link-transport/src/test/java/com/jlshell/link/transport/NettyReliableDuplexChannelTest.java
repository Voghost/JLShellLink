package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.core.transport.TransportBufferBudget;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class NettyReliableDuplexChannelTest {
    @Test
    void readsBoundedChunksAndMapsCleanCloseToEof() {
        EmbeddedChannel carrier = new EmbeddedChannel();
        NettyReliableDuplexChannel channel = new NettyReliableDuplexChannel(carrier, budget(32, 32),
                () -> java.util.concurrent.CompletableFuture.completedFuture(null));
        byte[] payload = {1, 2, 3, 4, 5};
        var cancelled = channel.read(1).toCompletableFuture();
        cancelled.cancel(false);
        carrier.writeInbound(Unpooled.wrappedBuffer(payload));

        assertArrayEquals(new byte[] {1, 2}, bytes(channel.read(2).toCompletableFuture().join()));
        assertArrayEquals(new byte[] {3, 4}, bytes(channel.read(2).toCompletableFuture().join()));
        assertArrayEquals(new byte[] {5}, bytes(channel.read(2).toCompletableFuture().join()));

        var pending = channel.read(8);
        carrier.close();
        assertEquals(0, pending.toCompletableFuture().join().remaining());
        channel.closed().toCompletableFuture().join();
    }

    @Test
    void boundsInboundAndOutboundQueuesAndRunsHalfCloseAfterWrites() {
        EmbeddedChannel carrier = new EmbeddedChannel();
        AtomicInteger halfCloses = new AtomicInteger();
        NettyReliableDuplexChannel channel = new NettyReliableDuplexChannel(carrier, budget(4), () -> {
            halfCloses.incrementAndGet();
            return java.util.concurrent.CompletableFuture.completedFuture(null);
        });

        ByteBuffer outbound = ByteBuffer.wrap(new byte[] {8, 7, 6});
        channel.write(outbound).toCompletableFuture().join();
        io.netty.buffer.ByteBuf sent = carrier.readOutbound();
        byte[] sentBytes = new byte[sent.readableBytes()];
        sent.readBytes(sentBytes);
        sent.release();
        assertArrayEquals(new byte[] {8, 7, 6}, sentBytes);
        channel.shutdownOutput().toCompletableFuture().join();
        assertEquals(1, halfCloses.get());
        assertThrows(CompletionException.class, () -> channel.write(ByteBuffer.wrap(new byte[] {1}))
                .toCompletableFuture().join());

        carrier.writeInbound(Unpooled.wrappedBuffer(new byte[] {1, 2, 3, 4, 5}));
        assertThrows(CompletionException.class, () -> channel.closed().toCompletableFuture().join());
        carrier.finishAndReleaseAll();
    }

    @Test
    void sharesOneTotalBufferLimitAcrossChannelsAndReleasesReservations() {
        TransportBufferBudget shared = new TransportBufferBudget(4);
        EmbeddedChannel firstCarrier = new EmbeddedChannel();
        EmbeddedChannel secondCarrier = new EmbeddedChannel();
        NettyReliableDuplexChannel first = new NettyReliableDuplexChannel(firstCarrier,
                budget(4, 4), shared, () -> java.util.concurrent.CompletableFuture.completedFuture(null));
        NettyReliableDuplexChannel second = new NettyReliableDuplexChannel(secondCarrier,
                budget(4, 4), shared, () -> java.util.concurrent.CompletableFuture.completedFuture(null));

        firstCarrier.writeInbound(Unpooled.wrappedBuffer(new byte[] {1, 2, 3, 4}));
        assertEquals(4, shared.inUseBytes());
        secondCarrier.writeInbound(Unpooled.wrappedBuffer(new byte[] {5}));
        assertThrows(CompletionException.class, () -> second.closed().toCompletableFuture().join());

        assertArrayEquals(new byte[] {1, 2, 3, 4}, bytes(first.read(4).toCompletableFuture().join()));
        assertEquals(0, shared.inUseBytes());
        first.close();
        firstCarrier.finishAndReleaseAll();
        secondCarrier.finishAndReleaseAll();
    }

    private static TransportBudget budget(int queueBytes) {
        return budget(queueBytes, 4);
    }

    private static TransportBudget budget(int queueBytes, int perStreamBytes) {
        return new TransportBudget(1_024, 512, 8, queueBytes, perStreamBytes, 64, 2, Duration.ofSeconds(5));
    }

    private static byte[] bytes(ByteBuffer value) {
        byte[] result = new byte[value.remaining()];
        value.get(result);
        return result;
    }
}
