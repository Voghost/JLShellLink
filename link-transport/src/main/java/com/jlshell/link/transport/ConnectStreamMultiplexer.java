package com.jlshell.link.transport;

import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoop;
import io.netty.channel.socket.DuplexChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame;
import io.netty.handler.codec.http2.DefaultHttp2ResetFrame;
import io.netty.handler.codec.http2.Http2DataFrame;
import io.netty.handler.codec.http2.Http2Error;
import io.netty.handler.codec.http2.Http2FrameCodec;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import io.netty.handler.codec.http2.Http2ResetFrame;
import io.netty.handler.codec.http2.Http2Settings;
import io.netty.handler.codec.http2.Http2StreamChannel;
import io.netty.util.ReferenceCountUtil;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Server-side HTTP/2 CONNECT multiplexer with a fail-closed authorization hook. */
public final class ConnectStreamMultiplexer {
    public record AuthorizationRequest(TargetEndpoint target, TunnelId tunnelId, String accessTicket) {
        public AuthorizationRequest {
            Objects.requireNonNull(target, "target");
            Objects.requireNonNull(tunnelId, "tunnelId");
            if (accessTicket == null || accessTicket.isBlank()) {
                throw new IllegalArgumentException("accessTicket is required");
            }
        }
    }

    @FunctionalInterface
    public interface AccessAuthorizer {
        CompletionStage<Boolean> authorize(AuthorizationRequest request);
    }

    @FunctionalInterface
    public interface TargetConnector {
        CompletionStage<Channel> connect(TargetEndpoint target, EventLoop eventLoop);
    }

    private enum State { WAITING_FOR_REQUEST, AUTHORIZING, CONNECTING, OPEN, CLOSED }

    private final TransportBudget budget;
    private final TransportBufferBudget sharedBuffers;
    private final AccessAuthorizer authorizer;
    private final TargetConnector connector;
    private final AtomicInteger activeStreams = new AtomicInteger();
    private final Semaphore setupSlots;

    /**
     * One instance represents one authenticated A—C HTTP/2 connection. The
     * authorizer must validate the current tunnel grant and lease; denial,
     * error, or timeout must never be converted into an allow decision.
     */
    public ConnectStreamMultiplexer(TransportBudget budget, TransportBufferBudget sharedBuffers,
            AccessAuthorizer authorizer, TargetConnector connector) {
        this.budget = Objects.requireNonNull(budget, "budget");
        this.sharedBuffers = Objects.requireNonNull(sharedBuffers, "sharedBuffers");
        if (sharedBuffers.limitBytes() > budget.maxBufferedBytesTotal()) {
            throw new IllegalArgumentException("shared buffer ledger cannot exceed total transport budget");
        }
        this.authorizer = Objects.requireNonNull(authorizer, "authorizer");
        this.connector = Objects.requireNonNull(connector, "connector");
        this.setupSlots = new Semaphore(budget.maxConcurrentHandshakes());
    }

    public static TargetConnector tcpConnector(TransportBudget budget) {
        Objects.requireNonNull(budget, "budget");
        long timeout = Math.max(1, Math.min(Integer.MAX_VALUE, budget.handshakeTimeout().toMillis()));
        return (target, eventLoop) -> {
            CompletableFuture<Channel> result = new CompletableFuture<>();
            Bootstrap bootstrap = new Bootstrap()
                    .group(eventLoop)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInboundHandlerAdapter())
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) timeout);
            bootstrap.connect(target.socketAddress()).addListener(future -> {
                if (future.isSuccess()) {
                    result.complete(((ChannelFuture) future).channel());
                } else {
                    result.completeExceptionally(future.cause());
                }
            });
            return result;
        };
    }

    /** Build an HTTP/2 server codec with finite peer-advertised limits. */
    public Http2FrameCodec newServerFrameCodec() {
        if (budget.maxFrameBytes() < 16_384 || budget.maxFrameBytes() > 16_777_215) {
            throw new IllegalArgumentException("HTTP/2 frame budget must be between 16384 and 16777215 bytes");
        }
        Http2Settings settings = new Http2Settings()
                .maxConcurrentStreams(budget.maxConcurrentStreams())
                .maxFrameSize(budget.maxFrameBytes())
                .initialWindowSize(budget.maxBufferedBytesPerStream())
                .maxHeaderListSize(budget.maxHeaderBytes());
        return Http2FrameCodecBuilder.forServer().initialSettings(settings).build();
    }

    /** Add the codec and per-stream CONNECT handler to a server pipeline. */
    public void installServerPipeline(ChannelPipeline pipeline) {
        Objects.requireNonNull(pipeline, "pipeline");
        pipeline.addLast("jlshell-link-h2", newServerFrameCodec());
        pipeline.addLast("jlshell-link-h2-streams", newServerMultiplexHandler());
    }

    public Http2MultiplexHandler newServerMultiplexHandler() {
        return new Http2MultiplexHandler(new ChannelInitializer<Http2StreamChannel>() {
            @Override
            protected void initChannel(Http2StreamChannel stream) {
                if (activeStreams.incrementAndGet() > budget.maxConcurrentStreams()) {
                    activeStreams.decrementAndGet();
                    stream.writeAndFlush(new DefaultHttp2ResetFrame(Http2Error.REFUSED_STREAM))
                            .addListener(ignored -> stream.close());
                    return;
                }
                AtomicBoolean released = new AtomicBoolean();
                stream.closeFuture().addListener(ignored -> {
                    if (released.compareAndSet(false, true)) {
                        activeStreams.decrementAndGet();
                    }
                });
                stream.pipeline().addLast(new ConnectHandler(stream));
            }
        });
    }

    private final class ConnectHandler extends ChannelInboundHandlerAdapter {
        private final Http2StreamChannel stream;
        private final AtomicLong toTargetBytes = new AtomicLong();
        private final AtomicLong toPeerBytes = new AtomicLong();
        private State state = State.WAITING_FOR_REQUEST;
        private TargetEndpoint target;
        private Channel targetChannel;
        private boolean requestEnded;
        private boolean responseEnded;
        private boolean setupSlotHeld;
        private ScheduledFuture<?> setupTimeout;

        private ConnectHandler(Http2StreamChannel stream) {
            this.stream = stream;
        }

        @Override
        public void channelRead(ChannelHandlerContext context, Object message) {
            boolean release = true;
            try {
                if (message instanceof Http2HeadersFrame headers) {
                    onHeaders(context, headers);
                } else if (message instanceof Http2DataFrame data) {
                    release = !onData(context, data);
                } else if (message instanceof Http2ResetFrame) {
                    cancelSetupTimeout();
                    releaseSetupSlot();
                    closeTarget();
                    state = State.CLOSED;
                    stream.close();
                } else {
                    reset(context, Http2Error.PROTOCOL_ERROR);
                }
            } catch (Throwable error) {
                reset(context, Http2Error.INTERNAL_ERROR);
            } finally {
                if (release) {
                    ReferenceCountUtil.release(message);
                }
            }
        }

        private void onHeaders(ChannelHandlerContext context, Http2HeadersFrame frame) {
            if (state != State.WAITING_FOR_REQUEST) {
                reset(context, Http2Error.PROTOCOL_ERROR);
                return;
            }
            if (!"CONNECT".contentEquals(frame.headers().method())) {
                respond(context, 405, true);
                return;
            }
            AuthorizationRequest request;
            try {
                target = parseAuthority(frame.headers().authority().toString());
                request = parseAuthorization(frame.headers(), target);
            } catch (MissingAccessTicketException missingTicket) {
                respond(context, 401, true);
                return;
            } catch (RuntimeException invalid) {
                respond(context, 400, true);
                return;
            }
            requestEnded = frame.isEndStream();
            if (!setupSlots.tryAcquire()) {
                respond(context, 503, true);
                return;
            }
            setupSlotHeld = true;
            state = State.AUTHORIZING;
            scheduleSetupTimeout(context);
            CompletionStage<Boolean> decision;
            try {
                decision = Objects.requireNonNull(authorizer.authorize(request), "authorization stage");
            } catch (Throwable error) {
                respond(context, 503, true);
                return;
            }
            decision.whenComplete((allowed, error) -> executeOnStream(() -> {
                if (state != State.AUTHORIZING) {
                    return;
                }
                if (error != null || allowed == null) {
                    respond(context, 503, true);
                } else if (!allowed) {
                    respond(context, 403, true);
                } else {
                    connectTarget(context);
                }
            }));
        }

        private void connectTarget(ChannelHandlerContext context) {
            state = State.CONNECTING;
            CompletionStage<Channel> pending;
            try {
                pending = Objects.requireNonNull(connector.connect(target, stream.eventLoop()), "target connect stage");
            } catch (Throwable error) {
                respond(context, 502, true);
                return;
            }
            pending.whenComplete((connected, error) -> executeOnStream(() -> {
                if (state != State.CONNECTING) {
                    if (connected != null) connected.close();
                    return;
                }
                if (error != null || connected == null || !connected.isActive()) {
                    if (connected != null) connected.close();
                    respond(context, 502, true);
                    return;
                }
                targetChannel = connected;
                connected.pipeline().addLast(new TargetHandler());
                state = State.OPEN;
                cancelSetupTimeout();
                releaseSetupSlot();
                context.writeAndFlush(new DefaultHttp2HeadersFrame(new DefaultHttp2Headers().status("200")));
                if (requestEnded) {
                    shutdownTargetOutput();
                }
            }));
        }

        private boolean onData(ChannelHandlerContext context, Http2DataFrame frame) {
            if (state != State.OPEN || targetChannel == null) {
                reset(context, Http2Error.PROTOCOL_ERROR);
                return false;
            }
            int length = frame.content().readableBytes();
            if (length > 0) {
                if (!reserve(toTargetBytes, length)) {
                    reset(context, Http2Error.ENHANCE_YOUR_CALM);
                    return false;
                }
                try {
                    ChannelFuture write = targetChannel.writeAndFlush(frame.content().retainedDuplicate());
                    write.addListener(result -> {
                        release(toTargetBytes, length);
                        ReferenceCountUtil.release(frame);
                        executeOnStream(() -> {
                            if (stream.isWritable()
                                    && toTargetBytes.get() < Math.max(1, budget.maxQueuedWriteBytes() / 2)) {
                                stream.config().setAutoRead(true);
                            }
                            if (!result.isSuccess()) {
                                reset(context, Http2Error.CONNECT_ERROR);
                            }
                        });
                    });
                    if (frame.isEndStream()) {
                        write.addListener(result -> {
                            if (result.isSuccess()) {
                                executeOnStream(this::shutdownTargetOutput);
                            }
                        });
                    }
                    if (toTargetBytes.get() >= Math.max(1, budget.maxQueuedWriteBytes() / 2)) {
                        stream.config().setAutoRead(false);
                    }
                } catch (Throwable error) {
                    release(toTargetBytes, length);
                    throw error;
                }
                return true;
            }
            if (frame.isEndStream()) {
                shutdownTargetOutput();
            }
            return false;
        }

        private boolean reserve(AtomicLong directionalQueue, int bytes) {
            while (true) {
                long current = directionalQueue.get();
                if (bytes > budget.maxQueuedWriteBytes() - current) {
                    return false;
                }
                if (directionalQueue.compareAndSet(current, current + bytes)) {
                    if (sharedBuffers.tryReserve(bytes)) {
                        return true;
                    }
                    directionalQueue.addAndGet(-bytes);
                    return false;
                }
            }
        }

        private void release(AtomicLong directionalQueue, int bytes) {
            directionalQueue.addAndGet(-bytes);
            sharedBuffers.release(bytes);
            if (directionalQueue == toPeerBytes && targetChannel != null
                    && directionalQueue.get() < Math.max(1, budget.maxQueuedWriteBytes() / 2)) {
                Channel target = targetChannel;
                target.eventLoop().execute(() -> target.config().setAutoRead(true));
            }
        }

        private void shutdownTargetOutput() {
            if (!(targetChannel instanceof DuplexChannel duplex)) {
                reset(stream.pipeline().context(this), Http2Error.CONNECT_ERROR);
                return;
            }
            duplex.shutdownOutput().addListener(result -> {
                if (!result.isSuccess()) {
                    executeOnStream(() -> reset(stream.pipeline().context(this), Http2Error.CONNECT_ERROR));
                }
            });
        }

        private void respond(ChannelHandlerContext context, int status, boolean endStream) {
            if (state == State.CLOSED) {
                return;
            }
            state = State.CLOSED;
            cancelSetupTimeout();
            releaseSetupSlot();
            closeTarget();
            context.writeAndFlush(new DefaultHttp2HeadersFrame(
                    new DefaultHttp2Headers().status(Integer.toString(status)), endStream))
                    .addListener(ignored -> stream.close());
        }

        private void reset(ChannelHandlerContext context, Http2Error error) {
            if (context == null || state == State.CLOSED) {
                return;
            }
            state = State.CLOSED;
            cancelSetupTimeout();
            releaseSetupSlot();
            closeTarget();
            context.writeAndFlush(new DefaultHttp2ResetFrame(error)).addListener(ignored -> stream.close());
        }

        private void executeOnStream(Runnable operation) {
            if (stream.eventLoop().inEventLoop()) {
                operation.run();
            } else {
                try {
                    stream.eventLoop().execute(operation);
                } catch (RejectedExecutionException ignored) {
                    closeTarget();
                    stream.close();
                }
            }
        }

        private void closeTarget() {
            Channel connected = targetChannel;
            targetChannel = null;
            if (connected != null) {
                connected.close();
            }
        }

        private void scheduleSetupTimeout(ChannelHandlerContext context) {
            long timeoutMillis = Math.max(1, budget.handshakeTimeout().toMillis());
            setupTimeout = stream.eventLoop().schedule(() -> {
                if (state == State.AUTHORIZING || state == State.CONNECTING) {
                    respond(context, 503, true);
                }
            }, timeoutMillis, TimeUnit.MILLISECONDS);
        }

        private void cancelSetupTimeout() {
            ScheduledFuture<?> timeout = setupTimeout;
            setupTimeout = null;
            if (timeout != null) {
                timeout.cancel(false);
            }
        }

        private void releaseSetupSlot() {
            if (setupSlotHeld) {
                setupSlotHeld = false;
                setupSlots.release();
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) {
            state = State.CLOSED;
            cancelSetupTimeout();
            releaseSetupSlot();
            closeTarget();
            context.fireChannelInactive();
        }

        @Override
        public void channelWritabilityChanged(ChannelHandlerContext context) {
            Channel target = targetChannel;
            if (target != null) {
                boolean shouldRead = stream.isWritable()
                        && toPeerBytes.get() < Math.max(1, budget.maxQueuedWriteBytes() / 2);
                target.eventLoop().execute(() -> target.config().setAutoRead(shouldRead));
            }
            context.fireChannelWritabilityChanged();
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
            reset(context, Http2Error.INTERNAL_ERROR);
        }

        private final class TargetHandler extends ChannelInboundHandlerAdapter {
            @Override
            public void channelRead(ChannelHandlerContext targetContext, Object message) {
                try {
                    if (!(message instanceof ByteBuf bytes)) {
                        targetContext.fireChannelRead(message);
                        return;
                    }
                    int length = bytes.readableBytes();
                    if (length == 0) {
                        return;
                    }
                    if (state != State.OPEN || responseEnded || !reserve(toPeerBytes, length)) {
                        executeOnStream(() -> reset(stream.pipeline().context(ConnectHandler.this),
                                Http2Error.ENHANCE_YOUR_CALM));
                        return;
                    }
                    int offset = bytes.readerIndex();
                    int remaining = length;
                    int submittedBytes = 0;
                    while (remaining > 0) {
                        int chunkLength = Math.min(remaining, budget.maxFrameBytes());
                        ByteBuf chunk = bytes.retainedSlice(offset, chunkLength);
                        Http2DataFrame frame = new DefaultHttp2DataFrame(chunk, false);
                        try {
                            stream.writeAndFlush(frame).addListener(result -> {
                                release(toPeerBytes, chunkLength);
                                if (!result.isSuccess()) {
                                    executeOnStream(() -> reset(stream.pipeline().context(ConnectHandler.this),
                                            Http2Error.CONNECT_ERROR));
                                }
                            });
                            submittedBytes += chunkLength;
                        } catch (Throwable error) {
                            ReferenceCountUtil.release(frame);
                            release(toPeerBytes, length - submittedBytes);
                            throw error;
                        }
                        offset += chunkLength;
                        remaining -= chunkLength;
                        if (toPeerBytes.get() >= Math.max(1, budget.maxQueuedWriteBytes() / 2)) {
                            targetContext.channel().config().setAutoRead(false);
                        }
                    }
                } finally {
                    ReferenceCountUtil.release(message);
                }
            }

            @Override
            public void channelInactive(ChannelHandlerContext targetContext) {
                executeOnStream(() -> {
                    if (state == State.OPEN && !responseEnded && stream.isActive()) {
                        responseEnded = true;
                        stream.writeAndFlush(new DefaultHttp2DataFrame(Unpooled.buffer(0), true));
                    }
                });
            }

            @Override
            public void exceptionCaught(ChannelHandlerContext targetContext, Throwable cause) {
                executeOnStream(() -> reset(stream.pipeline().context(ConnectHandler.this),
                        Http2Error.CONNECT_ERROR));
            }
        }
    }

    private static TargetEndpoint parseAuthority(String authority) {
        if (authority == null || authority.isBlank()) {
            throw new IllegalArgumentException("CONNECT authority is required");
        }
        String address;
        String portText;
        if (authority.startsWith("[")) {
            int end = authority.indexOf(']');
            if (end < 0 || end + 1 >= authority.length() || authority.charAt(end + 1) != ':') {
                throw new IllegalArgumentException("Invalid IPv6 CONNECT authority");
            }
            address = authority.substring(1, end);
            portText = authority.substring(end + 2);
        } else {
            int colon = authority.lastIndexOf(':');
            if (colon <= 0 || authority.indexOf(':') != colon) {
                throw new IllegalArgumentException("CONNECT authority must be numeric IP:port");
            }
            address = authority.substring(0, colon);
            portText = authority.substring(colon + 1);
        }
        if (portText.isEmpty() || !portText.chars().allMatch(Character::isDigit)) {
            throw new IllegalArgumentException("CONNECT port must be decimal");
        }
        int port;
        try {
            port = Integer.parseInt(portText);
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("CONNECT port is out of range", invalid);
        }
        return new TargetEndpoint(address, port);
    }

    private static AuthorizationRequest parseAuthorization(io.netty.handler.codec.http2.Http2Headers headers,
            TargetEndpoint authorityTarget) {
        String ip = singleHeader(headers, "x-jlshell-target-ip");
        String port = singleHeader(headers, "x-jlshell-target-port");
        String tunnel = singleHeader(headers, "x-jlshell-tunnel-id");
        String ticket = singleHeader(headers, "x-jlshell-access-ticket");
        if (ip == null || port == null || tunnel == null) {
            throw new IllegalArgumentException("CONNECT authorization headers are incomplete");
        }
        if (ticket == null || ticket.isBlank()) {
            throw new MissingAccessTicketException();
        }
        int targetPort;
        try {
            targetPort = Integer.parseInt(port);
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("CONNECT target port is invalid", invalid);
        }
        TargetEndpoint declaredTarget = new TargetEndpoint(ip, targetPort);
        if (!declaredTarget.equals(authorityTarget)) {
            throw new IllegalArgumentException("CONNECT authority does not match the authorized target");
        }
        try {
            return new AuthorizationRequest(authorityTarget, TunnelId.parse(tunnel), ticket);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("CONNECT tunnel id is invalid", invalid);
        }
    }

    private static String singleHeader(io.netty.handler.codec.http2.Http2Headers headers, String name) {
        java.util.List<CharSequence> values = headers.getAll(name);
        if (values.size() > 1) {
            throw new IllegalArgumentException("CONNECT header must occur once: " + name);
        }
        return values.isEmpty() ? null : values.get(0).toString();
    }

    private static final class MissingAccessTicketException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
    }
}
