package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import io.netty.channel.socket.DuplexChannel;
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.Http2DataFrame;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import io.netty.handler.codec.http2.Http2StreamChannel;
import io.netty.handler.codec.http2.Http2StreamChannelBootstrap;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ConnectStreamMultiplexerTest {
    @Test
    void authorizesNumericTargetAndProxiesConnectData() throws Exception {
        TransportBudget budget = budget();
        TransportBufferBudget shared = new TransportBufferBudget(budget.maxBufferedBytesTotal());
        AtomicInteger authorizations = new AtomicInteger();
        AtomicInteger connects = new AtomicInteger();
        AtomicReference<EmbeddedDuplexChannel> targetChannel = new AtomicReference<>();
        ConnectStreamMultiplexer mux = new ConnectStreamMultiplexer(budget, shared, request -> {
            authorizations.incrementAndGet();
            var target = request.target();
            assertEquals("127.0.0.1", target.address());
            assertEquals(22, target.port());
            assertEquals("00000000-0000-0000-0000-000000000001", request.tunnelId().toString());
            assertEquals("opaque-test-ticket", request.accessTicket());
            return CompletableFuture.completedFuture(true);
        }, (target, loop) -> {
            connects.incrementAndGet();
            EmbeddedDuplexChannel endpoint = new EmbeddedDuplexChannel(new EchoOnWriteHandler());
            targetChannel.set(endpoint);
            return CompletableFuture.completedFuture(endpoint);
        });
        EmbeddedChannel client = newClient();
        EmbeddedChannel server = newServer(mux);
        LinkedBlockingQueue<Integer> statuses = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> payloads = new LinkedBlockingQueue<>();
        AtomicBoolean responseEnded = new AtomicBoolean();

        try {
            Http2StreamChannel stream = new Http2StreamChannelBootstrap(client)
                    .handler(new ClientStreamHandler(statuses, payloads, responseEnded))
                    .open().syncUninterruptibly().getNow();
            stream.writeAndFlush(new io.netty.handler.codec.http2.DefaultHttp2HeadersFrame(
                    requestHeaders("127.0.0.1:22", true)));
            exchangeAll(client, server);
            assertEquals(200, statuses.poll(2, TimeUnit.SECONDS));
            assertEquals(1, authorizations.get());
            assertEquals(1, connects.get());

            byte[] bytes = new byte[] {0, 1, 2, (byte) 0xff, 10, 13};
            stream.writeAndFlush(new DefaultHttp2DataFrame(Unpooled.wrappedBuffer(bytes), true));
            exchangeAll(client, server);
            assertArrayEquals(bytes, payloads.poll(2, TimeUnit.SECONDS));
            assertNotNull(targetChannel.get());
            assertTrue(targetChannel.get().outputShutdown());
            assertEquals(0, shared.inUseBytes());
            targetChannel.get().close();
            exchangeAll(client, server);
            assertTrue(responseEnded.get());
        } finally {
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
        }
    }

    @Test
    void deniesBeforeConnectingAndRejectsHostnameAuthorities() throws Exception {
        TransportBudget budget = budget();
        AtomicInteger authorizations = new AtomicInteger();
        AtomicInteger connects = new AtomicInteger();
        ConnectStreamMultiplexer mux = new ConnectStreamMultiplexer(budget,
                new TransportBufferBudget(budget.maxBufferedBytesTotal()), request -> {
                    authorizations.incrementAndGet();
                    return CompletableFuture.completedFuture(false);
                }, (target, loop) -> {
                    connects.incrementAndGet();
                    return CompletableFuture.failedFuture(new AssertionError("denied target was connected"));
                });
        EmbeddedChannel client = newClient();
        EmbeddedChannel server = newServer(mux);
        LinkedBlockingQueue<Integer> statuses = new LinkedBlockingQueue<>();

        try {
            openRequest(client, server, "127.0.0.1:22", statuses, new LinkedBlockingQueue<>());
            assertEquals(403, statuses.poll(2, TimeUnit.SECONDS));
            assertEquals(1, authorizations.get());
            assertEquals(0, connects.get());

            openRequest(client, server, "target.example:22", statuses, new LinkedBlockingQueue<>());
            assertEquals(400, statuses.poll(2, TimeUnit.SECONDS));
            assertEquals(1, authorizations.get());
            assertEquals(0, connects.get());

            openRequest(client, server, "127.0.0.1:22", statuses, new LinkedBlockingQueue<>(), false);
            assertEquals(401, statuses.poll(2, TimeUnit.SECONDS));
            assertEquals(1, authorizations.get());
            assertEquals(0, connects.get());
        } finally {
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
        }
    }

    @Test
    void fragmentsLargeTargetReadWithinHttp2FrameLimit() throws Exception {
        TransportBudget budget = budget();
        TransportBufferBudget shared = new TransportBufferBudget(budget.maxBufferedBytesTotal());
        AtomicReference<EmbeddedDuplexChannel> targetChannel = new AtomicReference<>();
        ConnectStreamMultiplexer mux = new ConnectStreamMultiplexer(budget, shared,
                request -> CompletableFuture.completedFuture(true), (target, loop) -> {
                    EmbeddedDuplexChannel endpoint = new EmbeddedDuplexChannel(new EchoOnWriteHandler());
                    targetChannel.set(endpoint);
                    return CompletableFuture.completedFuture(endpoint);
                });
        EmbeddedChannel client = newClient();
        EmbeddedChannel server = newServer(mux);
        LinkedBlockingQueue<Integer> statuses = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> payloads = new LinkedBlockingQueue<>();

        try {
            openRequest(client, server, "127.0.0.1:22", statuses, payloads);
            assertEquals(200, statuses.poll(2, TimeUnit.SECONDS));

            byte[] expected = new byte[budget.maxFrameBytes() + 731];
            for (int index = 0; index < expected.length; index++) {
                expected[index] = (byte) (index * 31);
            }
            targetChannel.get().writeInbound(Unpooled.wrappedBuffer(expected));
            exchangeAll(client, server);

            List<byte[]> fragments = new ArrayList<>();
            byte[] fragment;
            while ((fragment = payloads.poll()) != null) {
                fragments.add(fragment);
            }
            assertEquals(2, fragments.size());
            byte[] actual = new byte[expected.length];
            int offset = 0;
            for (byte[] bytes : fragments) {
                System.arraycopy(bytes, 0, actual, offset, bytes.length);
                offset += bytes.length;
            }
            assertArrayEquals(expected, actual);
            assertEquals(0, shared.inUseBytes());
        } finally {
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
        }
    }

    @Test
    void timesOutAStalledAuthorizationAndDoesNotDialTarget() throws Exception {
        TransportBudget budget = new TransportBudget(16_384, 8_192, 8, 1_048_576,
                65_535, 4_194_304, 2, Duration.ofMillis(100));
        AtomicInteger connects = new AtomicInteger();
        ConnectStreamMultiplexer mux = new ConnectStreamMultiplexer(budget,
                new TransportBufferBudget(budget.maxBufferedBytesTotal()),
                request -> new CompletableFuture<>(),
                (target, loop) -> {
                    connects.incrementAndGet();
                    return CompletableFuture.failedFuture(new AssertionError("timed out request was connected"));
                });
        EmbeddedChannel client = newClient();
        EmbeddedChannel server = newServer(mux);
        LinkedBlockingQueue<Integer> statuses = new LinkedBlockingQueue<>();

        try {
            openRequest(client, server, "127.0.0.1:22", statuses, new LinkedBlockingQueue<>());
            Thread.sleep(150);
            server.runScheduledPendingTasks();
            exchangeAll(client, server);
            assertEquals(503, statuses.poll(2, TimeUnit.SECONDS));
            assertEquals(0, connects.get());
        } finally {
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
        }
    }

    private static void openRequest(EmbeddedChannel client, EmbeddedChannel server, String authority,
            LinkedBlockingQueue<Integer> statuses, LinkedBlockingQueue<byte[]> data) {
        openRequest(client, server, authority, statuses, data, true);
    }

    private static void openRequest(EmbeddedChannel client, EmbeddedChannel server, String authority,
            LinkedBlockingQueue<Integer> statuses, LinkedBlockingQueue<byte[]> data, boolean includeTicket) {
        Http2StreamChannel stream = new Http2StreamChannelBootstrap(client)
                    .handler(new ClientStreamHandler(statuses, data, new AtomicBoolean()))
                .open().syncUninterruptibly().getNow();
        stream.writeAndFlush(new io.netty.handler.codec.http2.DefaultHttp2HeadersFrame(
                requestHeaders(authority, includeTicket)));
        exchangeAll(client, server);
    }

    private static Http2Headers requestHeaders(String authority, boolean includeTicket) {
        var headers = new DefaultHttp2Headers()
                .method("CONNECT")
                .authority(authority)
                .set("x-jlshell-target-ip", "127.0.0.1")
                .set("x-jlshell-target-port", "22")
                .set("x-jlshell-tunnel-id", "00000000-0000-0000-0000-000000000001");
        if (includeTicket) {
            headers.set("x-jlshell-access-ticket", "opaque-test-ticket");
        }
        return headers;
    }

    private static EmbeddedChannel newClient() {
        return new EmbeddedChannel(Http2FrameCodecBuilder.forClient().build(),
                new Http2MultiplexHandler(new ChannelInboundHandlerAdapter()));
    }

    private static EmbeddedChannel newServer(ConnectStreamMultiplexer mux) {
        return new EmbeddedChannel(mux.newServerFrameCodec(), mux.newServerMultiplexHandler());
    }

    private static void exchangeAll(EmbeddedChannel first, EmbeddedChannel second) {
        for (int round = 0; round < 12; round++) {
            boolean moved = transferOutbound(first, second);
            moved |= transferOutbound(second, first);
            first.runPendingTasks();
            second.runPendingTasks();
            if (!moved) break;
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
        for (Object message : inbound) to.writeInbound(message);
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

    private static final class EmbeddedDuplexChannel extends EmbeddedChannel implements DuplexChannel {
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

    private static final class ClientStreamHandler extends ChannelInboundHandlerAdapter {
        private final LinkedBlockingQueue<Integer> statuses;
        private final LinkedBlockingQueue<byte[]> data;
        private final AtomicBoolean ended;

        private ClientStreamHandler(LinkedBlockingQueue<Integer> statuses, LinkedBlockingQueue<byte[]> data,
                AtomicBoolean ended) {
            this.statuses = statuses;
            this.data = data;
            this.ended = ended;
        }

        @Override
        public void channelRead(ChannelHandlerContext context, Object message) {
            try {
                if (message instanceof Http2HeadersFrame headers) {
                    statuses.offer(Integer.parseInt(headers.headers().status().toString()));
                } else if (message instanceof Http2DataFrame frame) {
                    byte[] bytes = new byte[frame.content().readableBytes()];
                    frame.content().getBytes(frame.content().readerIndex(), bytes);
                    data.offer(bytes);
                    if (frame.isEndStream()) ended.set(true);
                }
            } finally {
                io.netty.util.ReferenceCountUtil.release(message);
            }
        }
    }
}
