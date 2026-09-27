package com.jlshell.link.transport;

import com.jlshell.link.core.transport.ReliableDuplexChannel;
import com.jlshell.link.core.transport.TransportBudget;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.local.LocalAddress;
import io.netty.channel.local.LocalChannel;
import io.netty.channel.local.LocalServerChannel;
import io.netty.util.ReferenceCountUtil;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bridges a reliable carrier byte stream into an active Netty LocalChannel.
 * Install the TLS/HTTP2 pipeline on {@link #endpoint()} before calling
 * {@link #start()}; no network socket is opened by this adapter. The event loop
 * group must support Netty LocalChannel registration (for example,
 * {@code DefaultEventLoopGroup}); NIO selector groups do not support it.
 */
public final class ReliableCarrierBridge implements AutoCloseable {
    private static final int MAX_CHUNK_BYTES = 64 * 1024;

    private final ReliableDuplexChannel carrier;
    private final Channel listener;
    private final Channel endpoint;
    private final Channel pump;
    private final int readChunkBytes;
    private final CompletableFuture<Void> closed = new CompletableFuture<>();
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean open = new AtomicBoolean(true);

    private ReliableCarrierBridge(ReliableDuplexChannel carrier, Channel listener,
            Channel endpoint, Channel pump, int readChunkBytes) {
        this.carrier = carrier;
        this.listener = listener;
        this.endpoint = endpoint;
        this.pump = pump;
        this.readChunkBytes = readChunkBytes;
        endpoint.closeFuture().addListener(ignored -> close());
        pump.closeFuture().addListener(ignored -> close());
        listener.closeFuture().addListener(ignored -> close());
        carrier.closed().whenComplete((ignored, error) -> {
            if (error != null) fail(unwrap(error));
            else close();
        });
    }

    /** Creates an active, private in-process Netty channel pair over {@code carrier}. */
    public static CompletionStage<ReliableCarrierBridge> open(
            EventLoopGroup group, ReliableDuplexChannel carrier, TransportBudget budget) {
        Objects.requireNonNull(group, "group");
        Objects.requireNonNull(carrier, "carrier");
        Objects.requireNonNull(budget, "budget");
        int readChunkBytes = Math.min(MAX_CHUNK_BYTES,
                Math.min(budget.maxFrameBytes(), budget.maxBufferedBytesPerStream()));
        int maxBridgeMessageBytes = Math.min(budget.maxBufferedBytesPerStream(), budget.maxBufferedBytesTotal());
        if (readChunkBytes < 256 || readChunkBytes > MAX_CHUNK_BYTES) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("readChunkBytes must be between 256 and 65536"));
        }
        CompletableFuture<ReliableCarrierBridge> result = new CompletableFuture<>();
        CompletableFuture<Channel> pumpReady = new CompletableFuture<>();
        LocalAddress address = new LocalAddress("jlshell-link-" + UUID.randomUUID());
        ServerBootstrap server = new ServerBootstrap().group(group, group)
                .channel(LocalServerChannel.class)
                .childOption(ChannelOption.AUTO_READ, false)
                .childHandler(new ChannelInitializer<LocalChannel>() {
                    @Override
                    protected void initChannel(LocalChannel channel) {
                        channel.pipeline().addLast("jlshell-link-carrier-pump",
                                new PumpHandler(carrier, readChunkBytes, maxBridgeMessageBytes));
                        if (!pumpReady.complete(channel)) channel.close();
                    }
                });
        server.bind(address).addListener(bind -> {
            if (!bind.isSuccess()) {
                carrier.close();
                result.completeExceptionally(bind.cause());
                return;
            }
            Channel listener = ((ChannelFuture) bind).channel();
            Bootstrap client = new Bootstrap().group(group).channel(LocalChannel.class)
                    .option(ChannelOption.AUTO_READ, true)
                    .handler(new ChannelInboundHandlerAdapter());
            client.connect(address).addListener(connect -> {
                if (!connect.isSuccess()) {
                    listener.close();
                    carrier.close();
                    result.completeExceptionally(connect.cause());
                    return;
                }
                Channel endpoint = ((ChannelFuture) connect).channel();
                pumpReady.whenComplete((pump, acceptError) -> {
                    if (acceptError != null) {
                        endpoint.close();
                        listener.close();
                        carrier.close();
                        result.completeExceptionally(unwrap(acceptError));
                    } else {
                        ReliableCarrierBridge bridge = new ReliableCarrierBridge(
                                carrier, listener, endpoint, pump, readChunkBytes);
                        if (!result.complete(bridge)) bridge.close();
                    }
                });
            });
        });
        result.whenComplete((bridge, error) -> {
            if (result.isCancelled()) {
                pumpReady.thenAccept(Channel::close);
                carrier.close();
            }
        });
        return result;
    }

    /** The active local endpoint on which the caller installs its secure protocol pipeline. */
    public Channel endpoint() {
        if (!open.get()) throw new IllegalStateException("carrier bridge is closed");
        return endpoint;
    }

    /** Starts bounded bidirectional reads after the secure pipeline is installed. */
    public CompletionStage<Void> start() {
        if (!open.get()) return CompletableFuture.failedFuture(new IOException("carrier bridge is closed"));
        if (!started.compareAndSet(false, true)) {
            return CompletableFuture.failedFuture(new IllegalStateException("carrier bridge already started"));
        }
        CompletableFuture<Void> result = new CompletableFuture<>();
        pump.eventLoop().execute(() -> {
            if (!open.get() || !pump.isActive() || !endpoint.isActive()) {
                result.completeExceptionally(new IOException("local carrier endpoints are unavailable"));
                fail(new IOException("local carrier endpoints are unavailable"));
                return;
            }
            pump.read();
            readCarrier();
            result.complete(null);
        });
        return result;
    }

    public CompletionStage<Void> closed() { return closed; }

    private void readCarrier() {
        if (!open.get()) return;
        carrier.read(readChunkBytes).whenComplete((bytes, error) -> {
            if (error != null) {
                fail(unwrap(error));
                return;
            }
            if (bytes == null || !bytes.hasRemaining()) {
                fail(new IOException("carrier reached EOF"));
                return;
            }
            ByteBuffer source = bytes.asReadOnlyBuffer();
            byte[] copy = new byte[source.remaining()];
            source.get(copy);
            pump.eventLoop().execute(() -> {
                if (!open.get() || !pump.isActive()) return;
                pump.writeAndFlush(Unpooled.wrappedBuffer(copy)).addListener(write -> {
                    if (!write.isSuccess()) fail(write.cause());
                    else readCarrier();
                });
            });
        });
    }

    private void fail(Throwable failure) {
        if (!open.compareAndSet(true, false)) return;
        carrier.abort(failure);
        closeChannels(failure);
    }

    @Override
    public void close() {
        if (!open.compareAndSet(true, false)) return;
        carrier.close();
        closeChannels(null);
    }

    private void closeChannels(Throwable failure) {
        AtomicInteger remaining = new AtomicInteger(3);
        Runnable completeWhenClosed = () -> {
            if (remaining.decrementAndGet() != 0) return;
            if (failure == null) closed.complete(null);
            else closed.completeExceptionally(failure);
        };
        endpoint.close().addListener(ignored -> completeWhenClosed.run());
        pump.close().addListener(ignored -> completeWhenClosed.run());
        listener.close().addListener(ignored -> completeWhenClosed.run());
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while ((current instanceof java.util.concurrent.CompletionException
                || current instanceof java.util.concurrent.ExecutionException) && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static final class PumpHandler extends ChannelInboundHandlerAdapter {
        private final ReliableDuplexChannel carrier;
        private final int readChunkBytes;
        private final int maxBridgeMessageBytes;

        private PumpHandler(ReliableDuplexChannel carrier, int readChunkBytes, int maxBridgeMessageBytes) {
            this.carrier = carrier;
            this.readChunkBytes = readChunkBytes;
            this.maxBridgeMessageBytes = maxBridgeMessageBytes;
        }

        @Override
        public void channelRead(ChannelHandlerContext context, Object message) {
            if (!(message instanceof ByteBuf bytes)) {
                ReferenceCountUtil.release(message);
                context.close();
                carrier.abort(new IOException("local secure pipeline produced a non-byte message"));
                return;
            }
            if (bytes.readableBytes() > maxBridgeMessageBytes) {
                ReferenceCountUtil.release(bytes);
                context.close();
                carrier.abort(new IOException("local secure pipeline exceeded the bridge message budget"));
                return;
            }
            ByteBuf retained = bytes.retainedDuplicate();
            ReferenceCountUtil.release(bytes);
            writeNext(context, retained);
        }

        private void writeNext(ChannelHandlerContext context, ByteBuf bytes) {
            if (!context.channel().isActive()) {
                ReferenceCountUtil.release(bytes);
                return;
            }
            if (!bytes.isReadable()) {
                ReferenceCountUtil.release(bytes);
                context.read();
                return;
            }
            int count = Math.min(readChunkBytes, bytes.readableBytes());
            byte[] copy = new byte[count];
            bytes.readBytes(copy);
            carrier.write(ByteBuffer.wrap(copy).asReadOnlyBuffer()).whenComplete((ignored, error) -> {
                if (error != null) {
                    context.executor().execute(() -> {
                        ReferenceCountUtil.release(bytes);
                        context.close();
                        carrier.abort(unwrap(error));
                    });
                } else {
                    context.executor().execute(() -> writeNext(context, bytes));
                }
            });
        }

        @Override
        public void channelActive(ChannelHandlerContext context) {
            context.fireChannelActive();
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) {
            carrier.close();
            context.fireChannelInactive();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
            carrier.abort(cause);
            context.close();
        }
    }
}
