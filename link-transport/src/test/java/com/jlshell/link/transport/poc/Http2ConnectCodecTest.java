package com.jlshell.link.transport.poc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame;
import io.netty.handler.codec.http2.Http2DataFrame;
import io.netty.handler.codec.http2.Http2Frame;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import io.netty.handler.codec.http2.Http2StreamChannel;
import io.netty.handler.codec.http2.Http2StreamChannelBootstrap;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class Http2ConnectCodecTest {
    @Test
    void opensConnectStreamAndCarriesBidirectionalDataFrames() throws Exception {
        AtomicReference<Http2Headers> connectRequest = new AtomicReference<>();
        LinkedBlockingQueue<Integer> responseStatuses = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> echoedData = new LinkedBlockingQueue<>();

        EmbeddedChannel client = new EmbeddedChannel(
                Http2FrameCodecBuilder.forClient().build(),
                new Http2MultiplexHandler(new SimpleChannelInboundHandler<Http2Frame>() {
                    @Override
                    protected void channelRead0(ChannelHandlerContext ctx, Http2Frame frame) {
                        // Outbound client streams are opened explicitly below.
                    }
                }));
        EmbeddedChannel server = new EmbeddedChannel(
                Http2FrameCodecBuilder.forServer().build(),
                new Http2MultiplexHandler(new ChannelInitializer<Http2StreamChannel>() {
                    @Override
                    protected void initChannel(Http2StreamChannel stream) {
                        stream.pipeline().addLast(new SimpleChannelInboundHandler<Http2Frame>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, Http2Frame frame) {
                                if (frame instanceof Http2HeadersFrame headersFrame) {
                                    Http2Headers headers = headersFrame.headers();
                                    if ("CONNECT".contentEquals(headers.method())) {
                                        connectRequest.set(new DefaultHttp2Headers().add(headers));
                                        ctx.writeAndFlush(new DefaultHttp2HeadersFrame(
                                                new DefaultHttp2Headers().status("200")));
                                    }
                                } else if (frame instanceof Http2DataFrame dataFrame) {
                                    byte[] data = new byte[dataFrame.content().readableBytes()];
                                    dataFrame.content().getBytes(dataFrame.content().readerIndex(), data);
                                    ctx.writeAndFlush(new DefaultHttp2DataFrame(
                                            dataFrame.content().retainedDuplicate(), dataFrame.isEndStream()));
                                }
                            }
                        });
                    }
                }));

        try {
            exchangeAll(client, server);
            Http2StreamChannel clientStream = new Http2StreamChannelBootstrap(client)
                    .handler(new SimpleChannelInboundHandler<Http2Frame>() {
                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx, Http2Frame frame) {
                            if (frame instanceof Http2HeadersFrame headersFrame) {
                                responseStatuses.offer(Integer.parseInt(headersFrame.headers().status().toString()));
                            } else if (frame instanceof Http2DataFrame dataFrame) {
                                byte[] bytes = new byte[dataFrame.content().readableBytes()];
                                dataFrame.content().getBytes(dataFrame.content().readerIndex(), bytes);
                                echoedData.offer(bytes);
                            }
                        }
                    })
                    .open()
                    .syncUninterruptibly()
                    .getNow();

            clientStream.writeAndFlush(new DefaultHttp2HeadersFrame(
                    new DefaultHttp2Headers().method("CONNECT").authority("target.example:22")));
            exchangeAll(client, server);
            assertEquals("CONNECT", connectRequest.get().method().toString());
            assertEquals("target.example:22", connectRequest.get().authority().toString());
            assertEquals(200, responseStatuses.poll(2, TimeUnit.SECONDS));

            byte[] payload = "SSH payload over CONNECT".getBytes(StandardCharsets.UTF_8);
            clientStream.writeAndFlush(new DefaultHttp2DataFrame(Unpooled.wrappedBuffer(payload), false));
            exchangeAll(client, server);
            assertArrayEquals(payload, echoedData.poll(2, TimeUnit.SECONDS));
        } finally {
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
        }
    }

    private static void exchangeAll(EmbeddedChannel first, EmbeddedChannel second) {
        for (int round = 0; round < 8; round++) {
            boolean moved = transferOutbound(first, second);
            moved |= transferOutbound(second, first);
            first.runPendingTasks();
            second.runPendingTasks();
            if (!moved) {
                break;
            }
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
}
