package com.jlshell.link.server;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/** Minimal RFC 5389 Binding-only UDP responder. It never allocates or forwards relay traffic. */
public final class StunBindingServer implements AutoCloseable {
    private static final int MAGIC_COOKIE = 0x2112A442;
    private final InetSocketAddress bindAddress;
    private final EventLoopGroup eventLoop = new NioEventLoopGroup(1);
    private final Clock clock;
    private final int maxRequestsPerSecond;
    private volatile Channel channel;

    public StunBindingServer(InetSocketAddress bindAddress, Clock clock, int maxRequestsPerSecond) {
        this.bindAddress = Objects.requireNonNull(bindAddress, "bindAddress");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (maxRequestsPerSecond < 1 || maxRequestsPerSecond > 10_000) {
            throw new IllegalArgumentException("maxRequestsPerSecond must be between 1 and 10000");
        }
        this.maxRequestsPerSecond = maxRequestsPerSecond;
    }

    public CompletionStage<InetSocketAddress> start() {
        if (channel != null) throw new IllegalStateException("STUN endpoint already started");
        CompletableFuture<InetSocketAddress> started = new CompletableFuture<>();
        ChannelFuture bind = new Bootstrap()
                .group(eventLoop)
                .channel(NioDatagramChannel.class)
                .option(ChannelOption.SO_BROADCAST, false)
                .handler(new BindingHandler())
                .bind(bindAddress);
        bind.addListener(result -> {
            if (result.isSuccess()) {
                channel = bind.channel();
                started.complete((InetSocketAddress) bind.channel().localAddress());
            } else {
                started.completeExceptionally(result.cause());
            }
        });
        return started;
    }

    @Override
    public void close() {
        Channel current = channel;
        channel = null;
        if (current != null) current.close().syncUninterruptibly();
        eventLoop.shutdownGracefully().syncUninterruptibly();
    }

    private final class BindingHandler extends ChannelInboundHandlerAdapter {
        private final LinkedHashMap<String, Bucket> buckets = new LinkedHashMap<>(128, 0.75f, true);

        @Override
        public void channelRead(ChannelHandlerContext context, Object message) {
            if (!(message instanceof DatagramPacket packet)) return;
            try {
                ByteBuf input = packet.content();
                InetSocketAddress remote = packet.sender();
                if (remote == null || input.readableBytes() < 20 || input.readableBytes() > 576
                        || !allow(remote.getAddress())) return;
                ByteBuf response = bindingResponse(input, remote);
                if (response != null) context.writeAndFlush(new DatagramPacket(response, remote));
            } finally {
                packet.release();
            }
        }

        private boolean allow(InetAddress address) {
            long now = clock.millis();
            String key = address.getHostAddress();
            Bucket bucket = buckets.get(key);
            if (bucket == null) {
                if (buckets.size() >= 8192) {
                    buckets.entrySet().removeIf(entry -> now - entry.getValue().windowStart > 60_000);
                    if (buckets.size() >= 8192) buckets.remove(buckets.keySet().iterator().next());
                }
                bucket = new Bucket(now, 0);
                buckets.put(key, bucket);
            }
            if (now - bucket.windowStart >= 1000) {
                bucket.windowStart = now;
                bucket.requests = 0;
            }
            return ++bucket.requests <= maxRequestsPerSecond;
        }

        private ByteBuf bindingResponse(ByteBuf request, InetSocketAddress remote) {
            int start = request.readerIndex();
            int messageType = request.getUnsignedShort(start);
            int messageLength = request.getUnsignedShort(start + 2);
            int cookie = request.getInt(start + 4);
            if (messageType != 0x0001 || cookie != MAGIC_COOKIE || messageLength % 4 != 0
                    || messageLength > 512 || request.readableBytes() != 20 + messageLength) return null;
            ByteBuf response = Unpooled.buffer(48);
            InetAddress address = remote.getAddress();
            byte[] ip = address.getAddress();
            boolean ipv4 = address instanceof Inet4Address;
            int valueLength = ipv4 ? 8 : 20;
            response.writeShort(0x0101).writeShort(4 + valueLength).writeInt(MAGIC_COOKIE);
            response.writeBytes(request, start + 8, 12);
            response.writeShort(0x0020).writeShort(valueLength);
            response.writeByte(0);
            response.writeByte(ipv4 ? 0x01 : 0x02);
            response.writeShort(remote.getPort() ^ (MAGIC_COOKIE >>> 16));
            if (ipv4) {
                int addressBits = java.nio.ByteBuffer.wrap(ip).getInt() ^ MAGIC_COOKIE;
                response.writeInt(addressBits);
            } else {
                byte[] mask = new byte[16];
                java.nio.ByteBuffer.wrap(mask).putInt(MAGIC_COOKIE);
                request.getBytes(start + 8, mask, 4, 12);
                byte[] encoded = Arrays.copyOf(ip, ip.length);
                for (int index = 0; index < encoded.length; index++) encoded[index] ^= mask[index];
                response.writeBytes(encoded);
            }
            return response;
        }
    }

    private static final class Bucket {
        private long windowStart;
        private int requests;

        private Bucket(long windowStart, int requests) {
            this.windowStart = windowStart;
            this.requests = requests;
        }
    }
}
