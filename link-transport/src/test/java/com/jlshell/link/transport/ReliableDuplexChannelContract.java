package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.transport.ReliableDuplexChannel;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;

/** Shared byte-stream contract assertions run by both direct KCP and relayed CONNECT tests. */
public final class ReliableDuplexChannelContract {
    private ReliableDuplexChannelContract() { }

    public static void assertEchoAndHalfClose(ReliableDuplexChannel channel, byte[] payload) throws Exception {
        channel.write(ByteBuffer.wrap(payload)).toCompletableFuture().get(10, TimeUnit.SECONDS);
        byte[] echoed = new byte[payload.length];
        int offset = 0;
        while (offset < echoed.length) {
            ByteBuffer part = channel.read(Math.min(1_337, echoed.length - offset))
                    .toCompletableFuture().get(10, TimeUnit.SECONDS);
            int count = part.remaining();
            assertTrue(count > 0, "peer closed before returning the complete byte stream");
            part.get(echoed, offset, count);
            offset += count;
        }
        assertArrayEquals(payload, echoed);
        channel.shutdownOutput().toCompletableFuture().get(10, TimeUnit.SECONDS);
        ByteBuffer eof = channel.read(1).toCompletableFuture().get(10, TimeUnit.SECONDS);
        assertTrue(!eof.hasRemaining(), "peer did not map output half-close to input EOF");
    }
}
