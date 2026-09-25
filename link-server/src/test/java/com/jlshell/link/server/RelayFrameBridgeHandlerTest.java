package com.jlshell.link.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.TransportBufferBudget;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class RelayFrameBridgeHandlerTest {
    @Test
    void forwardsBoundedOpaqueBinaryBytesAndRecordsUsageWithoutPayload() {
        EmbeddedChannel client = new EmbeddedChannel();
        EmbeddedChannel agent = new EmbeddedChannel();
        AtomicLong recorded = new AtomicLong();
        LinkSessionId session = LinkSessionId.random();
        TunnelId tunnel = TunnelId.random();
        TransportBufferBudget pairBudget = new TransportBufferBudget(1024);
        TransportBufferBudget serverBudget = new TransportBufferBudget(4096);
        client.pipeline().addLast(new RelayFrameBridgeHandler(agent, session, tunnel,
                UsageRecorder.Direction.CLIENT_TO_AGENT, pairBudget, serverBudget,
                (s, t, direction, bytes) -> {
                    assertEquals(session, s);
                    assertEquals(tunnel, t);
                    assertEquals(UsageRecorder.Direction.CLIENT_TO_AGENT, direction);
                    recorded.addAndGet(bytes);
                }, 512));
        byte[] payload = new byte[] {0, 1, 2, (byte) 0xff, 4};
        try {
            client.writeInbound(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(payload)));
            BinaryWebSocketFrame forwarded = agent.readOutbound();
            assertArrayEquals(payload, io.netty.buffer.ByteBufUtil.getBytes(forwarded.content()));
            forwarded.release();
            assertEquals(payload.length, recorded.get());
            assertEquals(0, pairBudget.inUseBytes());
            assertEquals(0, serverBudget.inUseBytes());
        } finally {
            client.finishAndReleaseAll();
            agent.finishAndReleaseAll();
        }
    }
}
