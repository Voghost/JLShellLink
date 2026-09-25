package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jlshell.link.core.transport.TransportBudget;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.ContinuationWebSocketFrame;
import java.time.Duration;
import org.junit.jupiter.api.Test;

class WebSocketByteStreamCodecTest {
    private static final TransportBudget BUDGET = new TransportBudget(16_384, 8_192, 8,
            4_096, 1_024, 8_192, 4, Duration.ofSeconds(5));

    @Test
    void convertsFragmentedBinaryInputAndSplitsOutputWithinFrameBudget() {
        EmbeddedChannel channel = new EmbeddedChannel(new WebSocketByteStreamCodec(BUDGET));
        try {
            byte[] first = new byte[] {1, 2, 3};
            byte[] second = new byte[] {4, 5};
            channel.writeInbound(new BinaryWebSocketFrame(false, 0, Unpooled.wrappedBuffer(first)));
            channel.writeInbound(new ContinuationWebSocketFrame(true, 0, Unpooled.wrappedBuffer(second)));
            ByteBuf inputFirst = channel.readInbound();
            ByteBuf inputSecond = channel.readInbound();
            try {
                byte[] actualFirst = new byte[inputFirst.readableBytes()];
                byte[] actualSecond = new byte[inputSecond.readableBytes()];
                inputFirst.readBytes(actualFirst);
                inputSecond.readBytes(actualSecond);
                assertArrayEquals(first, actualFirst);
                assertArrayEquals(second, actualSecond);
            } finally {
                inputFirst.release();
                inputSecond.release();
            }

            byte[] output = new byte[2_048];
            channel.writeOutbound(Unpooled.wrappedBuffer(output));
            BinaryWebSocketFrame one = channel.readOutbound();
            BinaryWebSocketFrame two = channel.readOutbound();
            try {
                assertEquals(1_024, one.content().readableBytes());
                assertEquals(1_024, two.content().readableBytes());
            } finally {
                one.release();
                two.release();
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void rejectsOversizedBinaryFrameAndClosesCarrier() {
        EmbeddedChannel channel = new EmbeddedChannel(new WebSocketByteStreamCodec(BUDGET));
        try {
            assertThrows(CorruptedFrameException.class, () -> channel.writeInbound(
                    new BinaryWebSocketFrame(Unpooled.wrappedBuffer(new byte[1_025]))));
            assertFalse(channel.isActive());
        } finally {
            channel.finishAndReleaseAll();
        }
    }
}
