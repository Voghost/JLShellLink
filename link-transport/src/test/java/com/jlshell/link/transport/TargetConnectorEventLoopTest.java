package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.*;

import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.transport.TransportBudget;
import io.netty.buffer.Unpooled;
import io.netty.channel.DefaultEventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class TargetConnectorEventLoopTest {
    @Test
    void localCarrierLoopConnectsRealTcpTargetUsingTheOwnedNioGroup() throws Exception {
        var carrierLoops = new DefaultEventLoopGroup(1);
        var targetLoops = new NioEventLoopGroup(1);
        var budget = new TransportBudget(65536, 8192, 32, 1048576, 131072,
                4194304, 8, Duration.ofSeconds(5));
        try (var listener = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            listener.setSoTimeout(5000);
            var connector = ConnectStreamMultiplexer.tcpConnector(budget, targetLoops);
            var connected = connector.connect(new TargetEndpoint("127.0.0.1", listener.getLocalPort()),
                    carrierLoops.next()).toCompletableFuture().get(5, TimeUnit.SECONDS);
            try (var target = listener.accept()) {
                assertTrue(connected.isActive());
                assertSame(targetLoops, connected.eventLoop().parent());
                assertNotSame(carrierLoops, connected.eventLoop().parent());
                target.setSoTimeout(5000);
                byte[] bytes = {0, 1, 2, (byte) 255};
                connected.writeAndFlush(Unpooled.wrappedBuffer(bytes)).syncUninterruptibly();
                assertArrayEquals(bytes, target.getInputStream().readNBytes(bytes.length));
            } finally {
                connected.close().syncUninterruptibly();
            }
            assertFalse(targetLoops.isShuttingDown());
            assertFalse(carrierLoops.isShuttingDown());
        } finally {
            carrierLoops.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
            targetLoops.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
        }
    }
}
