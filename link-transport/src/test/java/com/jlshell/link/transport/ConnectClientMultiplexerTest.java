package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ConnectClientMultiplexerTest {
    @Test
    void opensAuthorizedTunnelTransfersBinaryAndMapsHalfCloseAndEof() throws Exception {
        TransportBudget budget = budget();
        TransportBufferBudget clientBuffers = new TransportBufferBudget(budget.maxBufferedBytesTotal());
        TransportBufferBudget serverBuffers = new TransportBufferBudget(budget.maxBufferedBytesTotal());
        AtomicInteger authorizations = new AtomicInteger();
        AtomicReference<EmbeddedDuplexChannel> target = new AtomicReference<>();
        ConnectStreamMultiplexer serverMux = new ConnectStreamMultiplexer(budget, serverBuffers, request -> {
            authorizations.incrementAndGet();
            assertEquals("127.0.0.1", request.target().address());
            assertEquals(22, request.target().port());
            assertEquals("00000000-0000-0000-0000-000000000001", request.tunnelId().toString());
            assertEquals("opaque-test-ticket", request.accessTicket());
            return CompletableFuture.completedFuture(true);
        }, (endpoint, loop) -> {
            EmbeddedDuplexChannel connected = new EmbeddedDuplexChannel(new EchoOnWriteHandler());
            target.set(connected);
            return CompletableFuture.completedFuture(connected);
        });
        EmbeddedChannel clientParent = newClient();
        EmbeddedChannel serverParent = newServer(serverMux);
        ConnectClientMultiplexer clientMux = new ConnectClientMultiplexer(clientParent, budget, clientBuffers);
        ConnectClientMultiplexer.ConnectTunnel tunnel = null;

        try {
            CompletableFuture<ConnectClientMultiplexer.ConnectTunnel> opening = clientMux.open(
                    new TargetEndpoint("127.0.0.1", 22),
                    TunnelId.parse("00000000-0000-0000-0000-000000000001"), "opaque-test-ticket")
                    .toCompletableFuture();
            exchangeAll(clientParent, serverParent);
            tunnel = opening.get(2, TimeUnit.SECONDS);
            assertEquals(1, authorizations.get());
            assertEquals(1, clientMux.activeStreams());

            byte[] payload = new byte[budget.maxFrameBytes() + 731];
            for (int index = 0; index < payload.length; index++) {
                payload[index] = (byte) (index * 31);
            }
            CompletableFuture<ByteBuffer> reading = tunnel.read(payload.length).toCompletableFuture();
            CompletableFuture<Void> writing = tunnel.write(ByteBuffer.wrap(payload)).toCompletableFuture();
            exchangeAll(clientParent, serverParent);
            writing.get(2, TimeUnit.SECONDS);
            byte[] actual = new byte[payload.length];
            int offset = 0;
            while (offset < actual.length) {
                ByteBuffer received = offset == 0
                        ? reading.get(2, TimeUnit.SECONDS)
                        : tunnel.read(actual.length - offset).toCompletableFuture().get(2, TimeUnit.SECONDS);
                int count = received.remaining();
                received.get(actual, offset, count);
                offset += count;
            }
            assertArrayEquals(payload, actual);

            CompletableFuture<Void> halfClose = tunnel.shutdownOutput().toCompletableFuture();
            exchangeAll(clientParent, serverParent);
            halfClose.get(2, TimeUnit.SECONDS);
            assertTrue(target.get().outputShutdown());
            target.get().close();
            exchangeAll(clientParent, serverParent);
            assertEquals(0, tunnel.read(1024).toCompletableFuture().get(2, TimeUnit.SECONDS).remaining());
            assertEquals(0, clientBuffers.inUseBytes());
            assertEquals(0, serverBuffers.inUseBytes());
        } finally {
            if (tunnel != null) {
                tunnel.close();
            }
            clientParent.finishAndReleaseAll();
            serverParent.finishAndReleaseAll();
        }
    }

    @Test
    void authorizationDenialFailsOpenAndDoesNotConnectTarget() throws Exception {
        TransportBudget budget = budget();
        AtomicInteger connects = new AtomicInteger();
        ConnectStreamMultiplexer serverMux = new ConnectStreamMultiplexer(budget,
                new TransportBufferBudget(budget.maxBufferedBytesTotal()),
                request -> CompletableFuture.completedFuture(false), (endpoint, loop) -> {
                    connects.incrementAndGet();
                    return CompletableFuture.failedFuture(new AssertionError("denied target was connected"));
                });
        EmbeddedChannel clientParent = newClient();
        EmbeddedChannel serverParent = newServer(serverMux);
        ConnectClientMultiplexer clientMux = new ConnectClientMultiplexer(clientParent, budget,
                new TransportBufferBudget(budget.maxBufferedBytesTotal()));

        try {
            CompletableFuture<ConnectClientMultiplexer.ConnectTunnel> opening = clientMux.open(
                    new TargetEndpoint("127.0.0.1", 22), TunnelId.random(), "test-ticket")
                    .toCompletableFuture();
            exchangeAll(clientParent, serverParent);
            ExecutionException denied = assertThrows(ExecutionException.class,
                    () -> opening.get(2, TimeUnit.SECONDS));
            assertTrue(denied.getCause().getMessage().contains("403"));
            assertEquals(0, connects.get());
            assertEquals(0, clientMux.activeStreams());
        } finally {
            clientParent.finishAndReleaseAll();
            serverParent.finishAndReleaseAll();
        }
    }

    @Test
    void clientRejectsMissingOrOversizedTicketBeforeOpeningAStream() {
        TransportBudget budget = budget();
        EmbeddedChannel parent = newClient();
        ConnectClientMultiplexer mux = new ConnectClientMultiplexer(parent, budget,
                new TransportBufferBudget(budget.maxBufferedBytesTotal()));
        try {
            CompletableFuture<ConnectClientMultiplexer.ConnectTunnel> opening = mux.open(
                    new TargetEndpoint("127.0.0.1", 22), TunnelId.random(), " ").toCompletableFuture();
            assertThrows(ExecutionException.class, () -> opening.get(2, TimeUnit.SECONDS));
            CompletableFuture<ConnectClientMultiplexer.ConnectTunnel> oversized = mux.open(
                    new TargetEndpoint("127.0.0.1", 22), TunnelId.random(), "x".repeat(9_000))
                    .toCompletableFuture();
            assertThrows(ExecutionException.class, () -> oversized.get(2, TimeUnit.SECONDS));
            assertEquals(0, mux.activeStreams());
        } finally {
            parent.finishAndReleaseAll();
        }
    }

    private static EmbeddedChannel newClient() {
        return new EmbeddedChannel(Http2FrameCodecBuilder.forClient().build(),
                new Http2MultiplexHandler(new ChannelInboundHandlerAdapter()));
    }

    private static EmbeddedChannel newServer(ConnectStreamMultiplexer mux) {
        return new EmbeddedChannel(mux.newServerFrameCodec(), mux.newServerMultiplexHandler());
    }

    private static void exchangeAll(EmbeddedChannel first, EmbeddedChannel second) {
        for (int round = 0; round < 30; round++) {
            transferOutbound(first, second);
            transferOutbound(second, first);
            first.runPendingTasks();
            second.runPendingTasks();
        }
    }

    private static boolean transferOutbound(EmbeddedChannel from, EmbeddedChannel to) {
        boolean moved = false;
        Object outbound;
        List<Object> inbound = new ArrayList<>();
        while ((outbound = from.readOutbound()) != null) {
            moved = true;
            if (outbound instanceof ByteBuf bytes) {
                inbound.add(bytes.copy());
                bytes.release();
            } else {
                inbound.add(outbound);
            }
        }
        for (Object message : inbound) {
            to.writeInbound(message);
        }
        return moved;
    }

    private static TransportBudget budget() {
        return new TransportBudget(16_384, 8_192, 8, 1_048_576,
                65_535, 4_194_304, 8, Duration.ofSeconds(5));
    }

    private static final class EchoOnWriteHandler extends ChannelDuplexHandler {
        @Override
        public void write(ChannelHandlerContext context, Object message, ChannelPromise promise) {
            context.fireChannelRead(message);
            promise.setSuccess();
        }
    }

    private static final class EmbeddedDuplexChannel extends EmbeddedChannel implements io.netty.channel.socket.DuplexChannel {
        private boolean inputShutdown;
        private boolean outputShutdown;

        private EmbeddedDuplexChannel(ChannelInboundHandlerAdapter... handlers) {
            super(handlers);
        }

        @Override public boolean isInputShutdown() { return inputShutdown; }
        @Override public ChannelFuture shutdownInput() { inputShutdown = true; return newSucceededFuture(); }
        @Override public ChannelFuture shutdownInput(ChannelPromise promise) {
            inputShutdown = true;
            promise.setSuccess();
            return promise;
        }
        @Override public boolean isOutputShutdown() { return outputShutdown; }
        @Override public ChannelFuture shutdownOutput() { outputShutdown = true; return newSucceededFuture(); }
        @Override public ChannelFuture shutdownOutput(ChannelPromise promise) {
            outputShutdown = true;
            promise.setSuccess();
            return promise;
        }
        @Override public boolean isShutdown() { return inputShutdown && outputShutdown; }
        @Override public ChannelFuture shutdown() {
            inputShutdown = true;
            outputShutdown = true;
            return newSucceededFuture();
        }
        @Override public ChannelFuture shutdown(ChannelPromise promise) {
            inputShutdown = true;
            outputShutdown = true;
            promise.setSuccess();
            return promise;
        }
        private boolean outputShutdown() { return outputShutdown; }
    }
}
