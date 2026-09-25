package com.jlshell.link.transport.poc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.ConnectClientMultiplexer;
import com.jlshell.link.transport.ConnectStreamMultiplexer;
import com.jlshell.link.transport.TlsHandshakeGate;
import com.jlshell.link.transport.WssSecureConnector;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpHeaders;
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
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.PortUnreachableException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;

/** Local WSS pairing proof only; production relay authentication remains a Website contract. */
class WssRelayPairingTest {
    private static final String RELAY_CREDENTIAL = "poc-relay-credential";

    @Test
    void productionWssConnectorCarriesInnerTlsHttp2Connect() throws Exception {
        TransportBudget budget = new TransportBudget(16_384, 8_192, 8, 1_048_576,
                65_535, 4_194_304, 8, Duration.ofSeconds(8));
        try (TestIdentity identity = TestIdentity.create();
                WssRelayServer relay = new WssRelayServer(identity.serverContext(), RELAY_CREDENTIAL);
                TcpEchoTarget target = new TcpEchoTarget()) {
            NioEventLoopGroup group = new NioEventLoopGroup(2);
            Channel client = null;
            Channel gateway = null;
            ConnectClientMultiplexer.ConnectTunnel tunnel = null;
            try {
                URI endpoint = URI.create("wss://localhost:" + relay.port() + "/link/v2/relay");
                TlsHandshakeGate gate = new TlsHandshakeGate(budget.maxConcurrentHandshakes());
                AtomicReference<Throwable> targetFailure = new AtomicReference<>();
                AtomicReference<Boolean> targetActive = new AtomicReference<>();
                ConnectStreamMultiplexer.TargetConnector tcp = ConnectStreamMultiplexer.tcpConnector(budget);
                ConnectStreamMultiplexer gatewayMux = new ConnectStreamMultiplexer(budget,
                        new TransportBufferBudget(budget.maxBufferedBytesTotal()),
                        request -> CompletableFuture.completedFuture(
                                request.target().equals(new TargetEndpoint("127.0.0.1", target.port()))
                                        && "test-ticket".equals(request.accessTicket())),
                        (endpointToConnect, eventLoop) -> {
                            try {
                                return tcp.connect(endpointToConnect, eventLoop).whenComplete((connected, error) -> {
                                    targetFailure.set(error);
                                    targetActive.set(connected != null && connected.isActive());
                                });
                            } catch (RuntimeException error) {
                                targetFailure.set(error);
                                throw error;
                            }
                        });
                CompletableFuture<Channel> gatewayReady = WssSecureConnector.connectGateway(group, endpoint,
                        identity.clientContext(), relayHeaders("C"), identity.serverContext(),
                        "client", 443, budget, gate, gatewayMux).toCompletableFuture();
                CompletableFuture<Channel> clientReady = WssSecureConnector.connectClient(group, endpoint,
                        identity.clientContext(), relayHeaders("A"), identity.clientContext(),
                        "localhost", 443, budget, gate).toCompletableFuture();
                gateway = gatewayReady.get(12, TimeUnit.SECONDS);
                client = clientReady.get(12, TimeUnit.SECONDS);
                assertEquals(0, gate.inFlightHandshakes());

                ConnectClientMultiplexer clientMux = new ConnectClientMultiplexer(client, budget,
                        new TransportBufferBudget(budget.maxBufferedBytesTotal()));
                try {
                    tunnel = clientMux.open(new TargetEndpoint("127.0.0.1", target.port()),
                            TunnelId.random(), "test-ticket").toCompletableFuture().get(5, TimeUnit.SECONDS);
                } catch (ExecutionException error) {
                    throw new AssertionError("target connect failure: " + targetFailure.get()
                            + ", active=" + targetActive.get(), error);
                }
                byte[] payload = payload(4_096, 41);
                tunnel.write(ByteBuffer.wrap(payload)).toCompletableFuture().get(5, TimeUnit.SECONDS);
                byte[] received = new byte[payload.length];
                int count = 0;
                while (count < received.length) {
                    ByteBuffer part = tunnel.read(received.length - count)
                            .toCompletableFuture().get(5, TimeUnit.SECONDS);
                    int size = part.remaining();
                    assertTrue(size > 0, "WSS CONNECT target closed before echo completed");
                    part.get(received, count, size);
                    count += size;
                }
                assertArrayEquals(payload, received);
                tunnel.shutdownOutput().toCompletableFuture().get(5, TimeUnit.SECONDS);
                assertEquals(0, tunnel.read(1).toCompletableFuture().get(5, TimeUnit.SECONDS).remaining());
                assertTrue(!relay.forwardedContains("production-connector", payload),
                        "B observed inner CONNECT plaintext");
            } finally {
                if (tunnel != null) {
                    tunnel.close();
                }
                if (client != null) {
                    client.close().syncUninterruptibly();
                }
                if (gateway != null) {
                    gateway.close().syncUninterruptibly();
                }
                group.shutdownGracefully().syncUninterruptibly();
            }
            assertTrue(relay.awaitActiveSessions(0, Duration.ofSeconds(3)));
        }
    }

    private static HttpHeaders relayHeaders(String role) {
        return new DefaultHttpHeaders()
                .add("Authorization", "Bearer " + RELAY_CREDENTIAL)
                .add("X-Link-Session", "production-connector")
                .add("X-Link-Role", role);
    }

    @Test
    void productionConnectorRejectsPlaintextRelayAndMissingAuthorization() throws Exception {
        TransportBudget budget = new TransportBudget(16_384, 8_192, 8, 1_048_576,
                65_535, 4_194_304, 8, Duration.ofSeconds(5));
        NioEventLoopGroup group = new NioEventLoopGroup(1);
        try {
            SSLContext context = SSLContext.getDefault();
            TlsHandshakeGate gate = new TlsHandshakeGate(8);
            assertThrows(IllegalArgumentException.class, () -> WssSecureConnector.connectClient(
                    group, URI.create("ws://localhost:443/link/v2/relay"), context,
                    relayHeaders("A"), context, "localhost", 443, budget, gate));
            assertThrows(IllegalArgumentException.class, () -> WssSecureConnector.connectClient(
                    group, URI.create("wss://localhost:443/link/v2/relay"), context,
                    new DefaultHttpHeaders(), context, "localhost", 443, budget, gate));
        } finally {
            group.shutdownGracefully().syncUninterruptibly();
        }
    }

    @Test
    void fallsBackOnceAfterDirectTimeoutButNeverAfterAuthorizationFailure() throws Exception {
        try (TestIdentity identity = TestIdentity.create();
                WssRelayServer relay = new WssRelayServer(identity.serverContext(), RELAY_CREDENTIAL)) {
            HttpClient client = HttpClient.newBuilder()
                    .sslContext(identity.clientContext())
                    .connectTimeout(Duration.ofSeconds(3))
                    .build();
            URI endpoint = URI.create("wss://localhost:" + relay.port() + "/link/v2/relay");
            AtomicInteger directAttempts = new AtomicInteger();
            AtomicInteger relayAttempts = new AtomicInteger();
            CompletableFuture<String> direct = new CompletableFuture<>();
            CompletableFuture<byte[]> receivedAtC = new CompletableFuture<>();
            BinaryListener listenerC = new BinaryListener(receivedAtC);
            byte[] payload = payload(2_048, 29);
            String selected = connectWithRelayFallback(
                            () -> {
                                directAttempts.incrementAndGet();
                                return direct;
                            },
                            () -> {
                                relayAttempts.incrementAndGet();
                                return CompletableFuture.supplyAsync(() -> {
                                    try {
                                        WebSocket peerA = connect(client, endpoint, "fallback-session", "A",
                                                RELAY_CREDENTIAL, new BinaryListener());
                                        WebSocket peerC = connect(client, endpoint, "fallback-session", "C",
                                                RELAY_CREDENTIAL, listenerC);
                                        if (!relay.awaitPaired("fallback-session", Duration.ofSeconds(2))) {
                                            throw new IOException("WSS peers failed to pair after direct timeout");
                                        }
                                        peerA.sendBinary(ByteBuffer.wrap(payload), true)
                                                .get(2, TimeUnit.SECONDS);
                                        if (!java.util.Arrays.equals(payload, receivedAtC.get(3, TimeUnit.SECONDS))) {
                                            throw new IOException("WSS fallback corrupted tunnel data");
                                        }
                                        peerA.sendClose(WebSocket.NORMAL_CLOSURE, "done")
                                                .get(2, TimeUnit.SECONDS);
                                        peerC.abort();
                                        return "relay";
                                    } catch (Exception e) {
                                        throw new java.util.concurrent.CompletionException(e);
                                    }
                                });
                            },
                            Duration.ofMillis(50))
                    .get(5, TimeUnit.SECONDS);
            assertEquals("relay", selected);
            assertEquals(1, directAttempts.get());
            assertEquals(1, relayAttempts.get());
            assertArrayEquals(payload, receivedAtC.get(1, TimeUnit.SECONDS));
        }

        AtomicInteger deniedRelayAttempts = new AtomicInteger();
        CompletableFuture<String> denied = connectWithRelayFallback(
                () -> CompletableFuture.failedFuture(new SecurityException("access denied")),
                () -> {
                    deniedRelayAttempts.incrementAndGet();
                    return CompletableFuture.completedFuture("relay");
                },
                Duration.ofMillis(50));
        assertThrows(ExecutionException.class, () -> denied.get(1, TimeUnit.SECONDS));
        assertEquals(0, deniedRelayAttempts.get(), "authorization failure must not trigger relay fallback");

        CompletableFuture<String> invalidCertificate = connectWithRelayFallback(
                () -> CompletableFuture.failedFuture(new SSLHandshakeException("invalid peer identity")),
                () -> {
                    deniedRelayAttempts.incrementAndGet();
                    return CompletableFuture.completedFuture("relay");
                },
                Duration.ofMillis(50));
        assertThrows(ExecutionException.class, () -> invalidCertificate.get(1, TimeUnit.SECONDS));
        assertEquals(0, deniedRelayAttempts.get(), "TLS identity failure must not trigger relay fallback");
    }

    private static <T> CompletableFuture<T> connectWithRelayFallback(
            Supplier<CompletableFuture<T>> directAttempt,
            Supplier<CompletableFuture<T>> relayAttempt,
            Duration directBudget) {
        CompletableFuture<T> direct;
        try {
            direct = directAttempt.get();
        } catch (RuntimeException error) {
            direct = CompletableFuture.failedFuture(error);
        }
        return direct.orTimeout(directBudget.toMillis(), TimeUnit.MILLISECONDS)
                .handle((value, failure) -> {
                    if (failure == null) {
                        return CompletableFuture.completedFuture(value);
                    }
                    Throwable cause = failure;
                    while (cause instanceof java.util.concurrent.CompletionException
                            || cause instanceof ExecutionException) {
                        cause = cause.getCause();
                    }
                    if (cause instanceof TimeoutException
                            || cause instanceof ConnectException
                            || cause instanceof NoRouteToHostException
                            || cause instanceof PortUnreachableException
                            || cause instanceof SocketTimeoutException
                            || cause instanceof UnknownHostException) {
                        try {
                            return relayAttempt.get();
                        } catch (RuntimeException error) {
                            return CompletableFuture.<T>failedFuture(error);
                        }
                    }
                    return CompletableFuture.<T>failedFuture(cause);
                })
                .thenCompose(stage -> stage);
    }

    @Test
    void pairsOutboundClientsRelaysBinaryFramesAndCleansHalfOpenSessions() throws Exception {
        try (TestIdentity identity = TestIdentity.create();
                WssRelayServer relay = new WssRelayServer(identity.serverContext(), RELAY_CREDENTIAL)) {
            HttpClient client = HttpClient.newBuilder()
                    .sslContext(identity.clientContext())
                    .connectTimeout(Duration.ofSeconds(3))
                    .build();
            URI endpoint = URI.create("wss://localhost:" + relay.port() + "/link/v2/relay");

            WebSocket halfOpen = connect(client, endpoint, "half-open", "A", RELAY_CREDENTIAL,
                    new BinaryListener());
            assertTrue(relay.awaitActiveSessions(1, Duration.ofSeconds(2)));
            halfOpen.sendClose(WebSocket.NORMAL_CLOSURE, "cleanup").get(2, TimeUnit.SECONDS);
            assertTrue(relay.awaitActiveSessions(0, Duration.ofSeconds(2)),
                    "relay retained a half-open pairing after its only peer disconnected");

            CompletableFuture<byte[]> receivedAtC = new CompletableFuture<>();
            CompletableFuture<byte[]> receivedAtA = new CompletableFuture<>();
            BinaryListener listenerA = new BinaryListener(receivedAtA);
            BinaryListener listenerC = new BinaryListener(receivedAtC);
            WebSocket peerA = connect(client, endpoint, "paired-session", "A", RELAY_CREDENTIAL,
                    listenerA);
            WebSocket peerC = connect(client, endpoint, "paired-session", "C", RELAY_CREDENTIAL,
                    listenerC);
            assertTrue(relay.awaitPaired("paired-session", Duration.ofSeconds(2)),
                    "A and C were not paired by the relay");

            byte[] aToC = payload(8_192, 17);
            peerA.sendBinary(ByteBuffer.wrap(aToC), true).get(2, TimeUnit.SECONDS);
            assertArrayEquals(aToC, receivedAtC.get(3, TimeUnit.SECONDS));
            byte[] cToA = payload(4_097, 91);
            peerC.sendBinary(ByteBuffer.wrap(cToA), true).get(2, TimeUnit.SECONDS);
            assertArrayEquals(cToA, receivedAtA.get(3, TimeUnit.SECONDS));

            CompletableFuture<byte[]> slowFirstMessage = new CompletableFuture<>();
            BinaryListener slowListener = new BinaryListener(slowFirstMessage);
            WebSocket slowPeerA = connect(client, endpoint, "slow-session", "A", RELAY_CREDENTIAL,
                    new BinaryListener());
            WebSocket slowPeerC = connect(client, endpoint, "slow-session", "C", RELAY_CREDENTIAL,
                    slowListener);
            assertTrue(relay.awaitPaired("slow-session", Duration.ofSeconds(2)));
            byte[][] slowPayloads = new byte[8][];
            for (int i = 0; i < slowPayloads.length; i++) {
                slowPayloads[i] = payload(4_096, 120 + i);
                slowPeerA.sendBinary(ByteBuffer.wrap(slowPayloads[i]), true).get(2, TimeUnit.SECONDS);
            }
            assertTrue(slowListener.awaitQueued(4, Duration.ofSeconds(2)),
                    "slow WSS consumer did not fill its bounded receive queue");
            assertEquals(4, slowListener.maxQueuedMessages.get());
            for (byte[] expected : slowPayloads) {
                assertArrayEquals(expected, slowListener.takeMessage(Duration.ofSeconds(2)));
            }
            assertTrue(slowListener.maxQueuedMessages.get() <= 4,
                    "slow WSS consumer exceeded its bounded receive queue");
            slowPeerA.sendClose(WebSocket.NORMAL_CLOSURE, "done").get(2, TimeUnit.SECONDS);
            assertTrue(relay.awaitActiveSessions(1, Duration.ofSeconds(2)));

            peerA.sendClose(WebSocket.NORMAL_CLOSURE, "done").get(2, TimeUnit.SECONDS);
            assertTrue(relay.awaitActiveSessions(0, Duration.ofSeconds(2)),
                    "relay retained a pairing after a peer closed");

            CompletableFuture<byte[]> secureMessageAtA = new CompletableFuture<>();
            CompletableFuture<byte[]> secureMessageAtC = new CompletableFuture<>();
            BinaryListener secureListenerA = new BinaryListener(secureMessageAtA);
            BinaryListener secureListenerC = new BinaryListener(secureMessageAtC);
            WebSocket securePeerA = connect(client, endpoint, "secure-session", "A", RELAY_CREDENTIAL,
                    secureListenerA);
            WebSocket securePeerC = connect(client, endpoint, "secure-session", "C", RELAY_CREDENTIAL,
                    secureListenerC);
            assertTrue(relay.awaitPaired("secure-session", Duration.ofSeconds(2)));
            try (SSLSocket innerClient = layeredTls(identity.clientContext(),
                            new WebSocketStreamSocket(securePeerA, secureListenerA), true);
                    SSLSocket innerServer = layeredTls(identity.serverContext(),
                            new WebSocketStreamSocket(securePeerC, secureListenerC), false)) {
                innerServer.setNeedClientAuth(true);
                CompletableFuture<Void> serverHandshake = CompletableFuture.runAsync(() -> {
                    try {
                        innerServer.startHandshake();
                    } catch (IOException e) {
                        throw new java.util.concurrent.CompletionException(e);
                    }
                });
                innerClient.startHandshake();
                serverHandshake.get(5, TimeUnit.SECONDS);
                assertEquals("TLSv1.3", innerClient.getSession().getProtocol());
                assertEquals("TLSv1.3", innerServer.getSession().getProtocol());
                byte[] connectPayload = runHttp2Connect(innerClient, innerServer);
                assertTrue(!relay.forwardedContains("secure-session", connectPayload),
                        "relay observed the HTTP/2 CONNECT plaintext payload");
            }
            assertTrue(relay.awaitActiveSessions(0, Duration.ofSeconds(2)),
                    "relay retained the secure pairing after TLS sockets closed");

            WebSocket.Builder badCredential = client.newWebSocketBuilder()
                    .connectTimeout(Duration.ofSeconds(3))
                    .header("Authorization", "Bearer invalid")
                    .header("X-Link-Session", "denied-session")
                    .header("X-Link-Role", "A");
            assertThrows(ExecutionException.class, () -> badCredential
                    .buildAsync(endpoint, new BinaryListener())
                    .get(3, TimeUnit.SECONDS), "relay accepted an invalid credential");
            assertEquals(0, relay.activeSessions());
            peerC.abort();
        }
    }

    private static WebSocket connect(
            HttpClient client,
            URI endpoint,
            String session,
            String role,
            String credential,
            WebSocket.Listener listener) throws Exception {
        return client.newWebSocketBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .header("Authorization", "Bearer " + credential)
                .header("X-Link-Session", session)
                .header("X-Link-Role", role)
                .buildAsync(endpoint, listener)
                .get(3, TimeUnit.SECONDS);
    }

    private static byte[] payload(int length, int seed) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (seed + i * 31 + (i >>> 3));
        }
        return bytes;
    }

    private static byte[] runHttp2Connect(SSLSocket tlsClient, SSLSocket tlsServer) throws Exception {
        LinkedBlockingQueue<Integer> statuses = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> echoed = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<Boolean> responseEndStreams = new LinkedBlockingQueue<>();
        try (TcpEchoTarget target = new TcpEchoTarget()) {
        AtomicReference<Socket> targetSocket = new AtomicReference<>();
        EmbeddedChannel client = new EmbeddedChannel(
                Http2FrameCodecBuilder.forClient().build(),
                new Http2MultiplexHandler(new SimpleChannelInboundHandler<Http2Frame>() {
                    @Override
                    protected void channelRead0(ChannelHandlerContext ctx, Http2Frame frame) {
                        // Client streams are opened explicitly.
                    }
                }));
        EmbeddedChannel server = new EmbeddedChannel(
                Http2FrameCodecBuilder.forServer().build(),
                new Http2MultiplexHandler(new ChannelInitializer<Http2StreamChannel>() {
                    @Override
                    protected void initChannel(Http2StreamChannel stream) {
                        stream.pipeline().addLast(new SimpleChannelInboundHandler<Http2Frame>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, Http2Frame frame)
                                    throws Exception {
                                if (frame instanceof Http2HeadersFrame headers
                                        && "CONNECT".contentEquals(headers.headers().method())) {
                                    targetSocket.set(new Socket(InetAddress.getLoopbackAddress(), target.port()));
                                    ctx.writeAndFlush(new DefaultHttp2HeadersFrame(
                                            new DefaultHttp2Headers().status("200")));
                                } else if (frame instanceof Http2DataFrame data) {
                                    Socket socket = targetSocket.get();
                                    if (socket == null) {
                                        throw new IOException("CONNECT target was not opened");
                                    }
                                    byte[] request = new byte[data.content().readableBytes()];
                                    data.content().getBytes(data.content().readerIndex(), request);
                                    socket.getOutputStream().write(request);
                                    socket.getOutputStream().flush();
                                    if (data.isEndStream()) {
                                        socket.shutdownOutput();
                                    }
                                    byte[] response = socket.getInputStream().readNBytes(request.length);
                                    if (response.length != request.length) {
                                        throw new IOException("TCP echo target returned truncated data");
                                    }
                                    ctx.writeAndFlush(new DefaultHttp2DataFrame(
                                            Unpooled.wrappedBuffer(response), data.isEndStream()));
                                }
                            }
                        });
                    }
                }));
        try {
            exchangeHttp2(client, server, tlsClient, tlsServer);
            Http2StreamChannel stream = new Http2StreamChannelBootstrap(client)
                    .handler(new SimpleChannelInboundHandler<Http2Frame>() {
                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx, Http2Frame frame) {
                            if (frame instanceof Http2HeadersFrame headers) {
                                statuses.offer(Integer.parseInt(headers.headers().status().toString()));
                            } else if (frame instanceof Http2DataFrame data) {
                                byte[] bytes = new byte[data.content().readableBytes()];
                                data.content().getBytes(data.content().readerIndex(), bytes);
                                echoed.offer(bytes);
                                responseEndStreams.offer(data.isEndStream());
                            }
                        }
                    })
                    .open().syncUninterruptibly().getNow();
            stream.writeAndFlush(new DefaultHttp2HeadersFrame(new DefaultHttp2Headers()
                    .method("CONNECT").authority("127.0.0.1:" + target.port())));
            exchangeHttp2(client, server, tlsClient, tlsServer);
            assertEquals(200, statuses.poll(2, TimeUnit.SECONDS));
            byte[] data = payload(1_024, 43);
            stream.writeAndFlush(new DefaultHttp2DataFrame(Unpooled.wrappedBuffer(data), true));
            exchangeHttp2(client, server, tlsClient, tlsServer);
            assertArrayEquals(data, echoed.poll(2, TimeUnit.SECONDS));
            assertEquals(Boolean.TRUE, responseEndStreams.poll(2, TimeUnit.SECONDS));
            return data;
        } finally {
            Socket socket = targetSocket.get();
            if (socket != null) {
                socket.close();
            }
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
        }
        }
    }

    private static void exchangeHttp2(
            EmbeddedChannel client,
            EmbeddedChannel server,
            SSLSocket clientTls,
            SSLSocket serverTls) throws IOException {
        for (int round = 0; round < 16; round++) {
            boolean moved = transferHttp2(client, server, clientTls, serverTls);
            moved |= transferHttp2(server, client, serverTls, clientTls);
            client.runPendingTasks();
            server.runPendingTasks();
            if (!moved) {
                return;
            }
        }
        throw new IOException("HTTP/2 exchange did not quiesce");
    }

    private static boolean transferHttp2(
            EmbeddedChannel source, EmbeddedChannel target, SSLSocket sourceTls, SSLSocket targetTls)
            throws IOException {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        Object outbound;
        while ((outbound = source.readOutbound()) != null) {
            if (!(outbound instanceof ByteBuf buffer)) {
                throw new IOException("Unexpected HTTP/2 outbound type: " + outbound.getClass());
            }
            byte[] bytes = new byte[buffer.readableBytes()];
            buffer.readBytes(bytes);
            wire.writeBytes(bytes);
            buffer.release();
        }
        byte[] bytes = wire.toByteArray();
        if (bytes.length == 0) {
            return false;
        }
        sourceTls.getOutputStream().write(bytes);
        sourceTls.getOutputStream().flush();
        byte[] encryptedTunnelData = targetTls.getInputStream().readNBytes(bytes.length);
        if (encryptedTunnelData.length != bytes.length) {
            throw new IOException("Truncated TLS-protected HTTP/2 bytes");
        }
        target.writeInbound(Unpooled.wrappedBuffer(encryptedTunnelData));
        return true;
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int start = 0; start <= haystack.length - needle.length; start++) {
            for (int i = 0; i < needle.length; i++) {
                if (haystack[start + i] != needle[i]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    private static final class TcpEchoTarget implements AutoCloseable {
        private final ServerSocket listener;
        private final AtomicReference<Socket> accepted = new AtomicReference<>();
        private final Thread worker;

        private TcpEchoTarget() throws IOException {
            listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            worker = Thread.ofVirtual().start(() -> {
                try (Socket socket = listener.accept()) {
                    accepted.set(socket);
                    byte[] buffer = new byte[2_048];
                    int count;
                    while ((count = socket.getInputStream().read(buffer)) >= 0) {
                        socket.getOutputStream().write(buffer, 0, count);
                        socket.getOutputStream().flush();
                    }
                } catch (IOException ignored) {
                    // Closing the POC target ends its echo loop.
                }
            });
        }

        private int port() {
            return listener.getLocalPort();
        }

        @Override
        public void close() throws Exception {
            listener.close();
            Socket socket = accepted.get();
            if (socket != null) {
                socket.close();
            }
            worker.join(1_000);
            if (worker.isAlive()) {
                throw new IOException("TCP echo target did not stop");
            }
        }
    }

    private static final class BinaryListener implements WebSocket.Listener {
        private final ByteArrayOutputStream message = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> received;
        private final ArrayBlockingQueue<byte[]> messages = new ArrayBlockingQueue<>(4);
        private final AtomicBoolean requestOutstanding = new AtomicBoolean();
        private final AtomicInteger maxQueuedMessages = new AtomicInteger();
        private volatile WebSocket webSocket;
        private volatile boolean ended;

        private BinaryListener() {
            this(new CompletableFuture<>());
        }

        private BinaryListener(CompletableFuture<byte[]> received) {
            this.received = received;
        }

        @Override
        public void onOpen(WebSocket webSocket) {
            this.webSocket = webSocket;
            requestNextIfCapacity();
        }

        @Override
        public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
            byte[] part = new byte[data.remaining()];
            data.get(part);
            message.writeBytes(part);
            if (last) {
                byte[] completeMessage = message.toByteArray();
                message.reset();
                if (!messages.offer(completeMessage)) {
                    received.completeExceptionally(new IOException("WSS receive queue exceeded its bound"));
                    webSocket.abort();
                    return CompletableFuture.completedFuture(null);
                }
                maxQueuedMessages.accumulateAndGet(messages.size(), Math::max);
                received.complete(completeMessage);
            }
            requestOutstanding.set(false);
            requestNextIfCapacity();
            return null;
        }

        private byte[] takeMessage(Duration timeout) throws InterruptedException {
            byte[] next = messages.poll(timeout.toMillis(), TimeUnit.MILLISECONDS);
            if (next != null) {
                requestNextIfCapacity();
            }
            return next;
        }

        private boolean awaitQueued(int size, Duration timeout) throws InterruptedException {
            long deadline = System.nanoTime() + timeout.toNanos();
            while (System.nanoTime() < deadline && messages.size() < size) {
                Thread.sleep(5);
            }
            return messages.size() >= size;
        }

        private void requestNextIfCapacity() {
            WebSocket current = webSocket;
            if (current != null && !ended && messages.remainingCapacity() > 0
                    && requestOutstanding.compareAndSet(false, true)) {
                current.request(1);
            }
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            received.completeExceptionally(error);
            ended = true;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            ended = true;
            return CompletableFuture.completedFuture(null);
        }
    }

    private static SSLSocket layeredTls(SSLContext context, WebSocketStreamSocket transport, boolean client)
            throws IOException {
        SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(transport, "localhost", 443, true);
        socket.setUseClientMode(client);
        socket.setEnabledProtocols(new String[] {"TLSv1.3"});
        if (client) {
            var parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
        }
        return socket;
    }

    /** Presents WSS binary messages as a blocking byte stream for an inner TLS session. */
    private static final class WebSocketStreamSocket extends Socket {
        private final WebSocket webSocket;
        private final BinaryListener listener;
        private final InputStream input = new InputStream() {
            private byte[] current = new byte[0];
            private int offset;

            @Override
            public int read() throws IOException {
                byte[] one = new byte[1];
                int count = read(one, 0, 1);
                return count < 0 ? -1 : one[0] & 0xff;
            }

            @Override
            public int read(byte[] target, int start, int length) throws IOException {
                if (length == 0) {
                    return 0;
                }
                while (offset >= current.length) {
                    if (listener.ended && listener.messages.isEmpty()) {
                        return -1;
                    }
                    try {
                        byte[] next = listener.takeMessage(Duration.ofMillis(100));
                        if (next != null) {
                            current = next;
                            offset = 0;
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted while reading WSS tunnel", e);
                    }
                }
                int count = Math.min(length, current.length - offset);
                System.arraycopy(current, offset, target, start, count);
                offset += count;
                return count;
            }
        };
        private final OutputStream output = new OutputStream() {
            @Override
            public void write(int value) throws IOException {
                write(new byte[] {(byte) value});
            }

            @Override
            public void write(byte[] bytes, int start, int length) throws IOException {
                if (isClosed()) {
                    throw new SocketException("WSS tunnel is closed");
                }
                if (length == 0) {
                    return;
                }
                byte[] frame = java.util.Arrays.copyOfRange(bytes, start, start + length);
                try {
                    webSocket.sendBinary(ByteBuffer.wrap(frame), true).get(5, TimeUnit.SECONDS);
                } catch (Exception e) {
                    throw new IOException("Unable to write WSS tunnel frame", e);
                }
            }
        };
        private volatile boolean closed;

        private WebSocketStreamSocket(WebSocket webSocket, BinaryListener listener) {
            this.webSocket = webSocket;
            this.listener = listener;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            if (closed) {
                throw new SocketException("WSS tunnel is closed");
            }
            return input;
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            if (closed) {
                throw new SocketException("WSS tunnel is closed");
            }
            return output;
        }

        @Override
        public InetAddress getInetAddress() {
            return InetAddress.getLoopbackAddress();
        }

        @Override
        public int getPort() {
            return 443;
        }

        @Override
        public SocketAddress getRemoteSocketAddress() {
            return new InetSocketAddress(getInetAddress(), getPort());
        }

        @Override
        public boolean isConnected() {
            return true;
        }

        @Override
        public boolean isBound() {
            return true;
        }

        @Override
        public boolean isClosed() {
            return closed;
        }

        @Override
        public void close() {
            if (!closed) {
                closed = true;
                webSocket.abort();
            }
        }
    }

    /** Small RFC 6455 test server over TLS. It is deliberately isolated from production sources. */
    private static final class WssRelayServer implements AutoCloseable {
        private static final String WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        private static final int MAX_FRAME_BYTES = 1_048_576;
        private final SSLServerSocket listener;
        private final String credential;
        private final Map<String, Pair> pairs = new ConcurrentHashMap<>();
        private final Map<String, ConcurrentLinkedQueue<byte[]>> forwarded = new ConcurrentHashMap<>();
        private final Thread acceptThread;
        private volatile boolean closed;

        private WssRelayServer(SSLContext context, String credential) throws IOException {
            this.credential = credential;
            SSLServerSocketFactory factory = context.getServerSocketFactory();
            listener = (SSLServerSocket) factory.createServerSocket();
            listener.setEnabledProtocols(new String[] {"TLSv1.3"});
            listener.setNeedClientAuth(false);
            listener.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
            acceptThread = Thread.ofVirtual().name("wss-relay-poc-accept").start(this::acceptLoop);
        }

        private int port() {
            return listener.getLocalPort();
        }

        private int activeSessions() {
            return pairs.size();
        }

        private boolean forwardedContains(String session, byte[] payload) {
            for (String role : List.of("A", "C")) {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                for (byte[] frame : forwarded.getOrDefault(session + ":" + role,
                        new ConcurrentLinkedQueue<>())) {
                    stream.writeBytes(frame);
                }
                if (contains(stream.toByteArray(), payload)) {
                    return true;
                }
            }
            return false;
        }

        private boolean awaitActiveSessions(int expected, Duration timeout) throws InterruptedException {
            long deadline = System.nanoTime() + timeout.toNanos();
            while (System.nanoTime() < deadline) {
                if (activeSessions() == expected) {
                    return true;
                }
                Thread.sleep(10);
            }
            return activeSessions() == expected;
        }

        private boolean awaitPaired(String session, Duration timeout) throws InterruptedException {
            long deadline = System.nanoTime() + timeout.toNanos();
            while (System.nanoTime() < deadline) {
                Pair pair = pairs.get(session);
                if (pair != null && pair.isPaired()) {
                    return true;
                }
                Thread.sleep(10);
            }
            Pair pair = pairs.get(session);
            return pair != null && pair.isPaired();
        }

        private void acceptLoop() {
            while (!closed) {
                try {
                    SSLSocket socket = (SSLSocket) listener.accept();
                    socket.setEnabledProtocols(new String[] {"TLSv1.3"});
                    Thread.ofVirtual().start(() -> serve(socket));
                } catch (IOException e) {
                    if (!closed) {
                        close();
                    }
                }
            }
        }

        private void serve(SSLSocket socket) {
            Connection connection = null;
            Pair pair = null;
            try {
                socket.startHandshake();
                BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
                OutputStream output = socket.getOutputStream();
                Map<String, String> headers = readHandshake(input);
                if (!MessageDigest.isEqual(
                        ("Bearer " + credential).getBytes(StandardCharsets.UTF_8),
                        headers.getOrDefault("authorization", "").getBytes(StandardCharsets.UTF_8))) {
                    writeHttpError(output, 401, "Unauthorized");
                    return;
                }
                String session = headers.get("x-link-session");
                String role = headers.get("x-link-role");
                String key = headers.get("sec-websocket-key");
                if (session == null || session.isBlank() || session.length() > 128
                        || !("A".equals(role) || "C".equals(role)) || key == null) {
                    writeHttpError(output, 400, "Bad Request");
                    return;
                }
                writeHandshakeSuccess(output, key);
                connection = new Connection(session, role, socket, input, output);
                pair = pairs.computeIfAbsent(session, Pair::new);
                if (!pair.attach(connection)) {
                    writeCloseFrame(output, new byte[0]);
                    return;
                }
                connection.readFrames(pair);
            } catch (IOException ignored) {
                // A disconnected WSS peer releases its pairing in finally.
            } finally {
                if (pair != null) {
                    pair.detach(connection);
                }
                closeQuietly(socket);
            }
        }

        private Map<String, String> readHandshake(InputStream input) throws IOException {
            String request = readLine(input);
            if (!request.startsWith("GET /link/v2/relay HTTP/1.1")) {
                throw new IOException("Unexpected WSS relay request path");
            }
            Map<String, String> headers = new ConcurrentHashMap<>();
            String line;
            while (!(line = readLine(input)).isEmpty()) {
                int colon = line.indexOf(':');
                if (colon > 0) {
                    headers.put(line.substring(0, colon).trim().toLowerCase(),
                            line.substring(colon + 1).trim());
                }
            }
            return headers;
        }

        private String readLine(InputStream input) throws IOException {
            ByteArrayOutputStream line = new ByteArrayOutputStream();
            int previous = -1;
            int current;
            while ((current = input.read()) >= 0) {
                if (previous == '\r' && current == '\n') {
                    byte[] bytes = line.toByteArray();
                    return new String(bytes, 0, Math.max(0, bytes.length - 1), StandardCharsets.US_ASCII);
                }
                line.write(current);
                previous = current;
                if (line.size() > 8_192) {
                    throw new IOException("WSS handshake line is too large");
                }
            }
            throw new IOException("WSS peer closed during handshake");
        }

        private void writeHandshakeSuccess(OutputStream output, String key) throws IOException {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-1")
                        .digest((key + WEBSOCKET_GUID).getBytes(StandardCharsets.US_ASCII));
                String accept = Base64.getEncoder().encodeToString(digest);
                output.write(("HTTP/1.1 101 Switching Protocols\r\n"
                        + "Upgrade: websocket\r\n"
                        + "Connection: Upgrade\r\n"
                        + "Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                output.flush();
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new IOException("SHA-1 is unavailable for WebSocket handshake", e);
            }
        }

        private void writeHttpError(OutputStream output, int status, String message) throws IOException {
            byte[] body = message.getBytes(StandardCharsets.US_ASCII);
            output.write(("HTTP/1.1 " + status + " " + message + "\r\n"
                    + "Connection: close\r\nContent-Length: " + body.length + "\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            output.write(body);
            output.flush();
        }

        private static int readByte(InputStream input) throws IOException {
            int value = input.read();
            if (value < 0) {
                throw new IOException("WSS peer closed");
            }
            return value;
        }

        private static ClientFrame readClientFrame(InputStream input) throws IOException {
            int first = readByte(input);
            int second = readByte(input);
            boolean finalFrame = (first & 0x80) != 0;
            int opcode = first & 0x0f;
            boolean masked = (second & 0x80) != 0;
            long length = second & 0x7f;
            if (length == 126) {
                length = ((long) readByte(input) << 8) | readByte(input);
            } else if (length == 127) {
                length = 0;
                for (int i = 0; i < 8; i++) {
                    length = (length << 8) | readByte(input);
                }
            }
            if (!masked || length > MAX_FRAME_BYTES || (opcode >= 8 && (!finalFrame || length > 125))) {
                throw new IOException("Invalid or oversized client WebSocket frame");
            }
            byte[] mask = input.readNBytes(4);
            byte[] payload = input.readNBytes((int) length);
            if (mask.length != 4 || payload.length != length) {
                throw new IOException("Truncated client WebSocket frame");
            }
            for (int i = 0; i < payload.length; i++) {
                payload[i] ^= mask[i & 3];
            }
            return new ClientFrame(finalFrame, opcode, payload);
        }

        private static void writeServerFrame(OutputStream output, int opcode, byte[] payload) throws IOException {
            if (payload.length > MAX_FRAME_BYTES) {
                throw new IOException("Relay frame exceeded its test limit");
            }
            output.write(0x80 | opcode);
            if (payload.length < 126) {
                output.write(payload.length);
            } else if (payload.length <= 0xffff) {
                output.write(126);
                output.write((payload.length >>> 8) & 0xff);
                output.write(payload.length & 0xff);
            } else {
                output.write(127);
                for (int shift = 56; shift >= 0; shift -= 8) {
                    output.write((payload.length >>> shift) & 0xff);
                }
            }
            output.write(payload);
            output.flush();
        }

        private static void writeCloseFrame(OutputStream output, byte[] payload) throws IOException {
            writeServerFrame(output, 8, payload);
        }

        private static void closeQuietly(Socket socket) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Closing is best-effort during peer cleanup.
            }
        }

        @Override
        public void close() {
            closed = true;
            try {
                listener.close();
            } catch (IOException ignored) {
                // Server is shutting down.
            }
            pairs.values().forEach(Pair::close);
            try {
                acceptThread.join(1_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        private final class Pair {
            private final String session;
            private Connection peerA;
            private Connection peerC;
            private boolean closedPair;

            private Pair(String session) {
                this.session = session;
            }

            private synchronized boolean attach(Connection connection) {
                if (closedPair) {
                    return false;
                }
                if ("A".equals(connection.role)) {
                    if (peerA != null) {
                        return false;
                    }
                    peerA = connection;
                } else {
                    if (peerC != null) {
                        return false;
                    }
                    peerC = connection;
                }
                return true;
            }

            private synchronized boolean isPaired() {
                return !closedPair && peerA != null && peerC != null;
            }

            private synchronized void forward(Connection connection, byte[] payload) throws IOException {
                if (closedPair || peerA == null || peerC == null) {
                    throw new IOException("Relay session is not paired");
                }
                Connection peer = connection == peerA ? peerC : peerA;
                forwarded.computeIfAbsent(session + ":" + connection.role,
                        ignored -> new ConcurrentLinkedQueue<>()).offer(payload.clone());
                synchronized (peer.output) {
                    writeServerFrame(peer.output, 2, payload);
                }
            }

            private synchronized void detach(Connection connection) {
                if (connection == null) {
                    return;
                }
                if (peerA == connection) {
                    peerA = null;
                }
                if (peerC == connection) {
                    peerC = null;
                }
                if (peerA == null || peerC == null) {
                    close();
                }
            }

            private synchronized void close() {
                if (closedPair) {
                    return;
                }
                closedPair = true;
                pairs.remove(session, this);
                if (peerA != null) {
                    peerA.close();
                    peerA = null;
                }
                if (peerC != null) {
                    peerC.close();
                    peerC = null;
                }
            }
        }

        private final class Connection {
            private final String session;
            private final String role;
            private final SSLSocket socket;
            private final InputStream input;
            private final OutputStream output;

            private Connection(String session, String role, SSLSocket socket,
                    InputStream input, OutputStream output) {
                this.session = session;
                this.role = role;
                this.socket = socket;
                this.input = input;
                this.output = output;
            }

            private void readFrames(Pair pair) throws IOException {
                while (!closed) {
                    ClientFrame frame = readClientFrame(input);
                    boolean finalFrame = frame.finalFrame();
                    int opcode = frame.opcode();
                    byte[] payload = frame.payload();
                    if (opcode == 8) {
                        writeCloseFrame(output, payload);
                        return;
                    }
                    if (opcode == 9) {
                        synchronized (output) {
                            writeServerFrame(output, 10, payload);
                        }
                        continue;
                    }
                    if (opcode != 2 || !finalFrame) {
                        throw new IOException("POC relay only accepts complete binary messages");
                    }
                    pair.forward(this, payload);
                }
            }

            private void close() {
                closeQuietly(socket);
            }
        }

        private record ClientFrame(boolean finalFrame, int opcode, byte[] payload) {}
    }

    private static final class TestIdentity implements AutoCloseable {
        private static final char[] PASSWORD = "wss-relay-poc".toCharArray();
        private final Path directory;
        private final SSLContext clientContext;
        private final SSLContext serverContext;

        private TestIdentity(Path directory, SSLContext clientContext, SSLContext serverContext) {
            this.directory = directory;
            this.clientContext = clientContext;
            this.serverContext = serverContext;
        }

        private static TestIdentity create() throws Exception {
            Path directory = Files.createTempDirectory("jlshell-wss-relay-poc-");
            Path serverIdentity = directory.resolve("server.p12");
            Path clientIdentity = directory.resolve("client.p12");
            Path serverCertificate = directory.resolve("server.cer");
            Path clientCertificate = directory.resolve("client.cer");
            Path clientTrust = directory.resolve("client-trust.p12");
            Path serverTrust = directory.resolve("server-trust.p12");
            runKeytool(List.of("-genkeypair", "-noprompt", "-alias", "server", "-keyalg", "RSA",
                    "-keysize", "2048", "-validity", "2", "-storetype", "PKCS12", "-keystore",
                    serverIdentity.toString(), "-storepass", new String(PASSWORD), "-keypass", new String(PASSWORD),
                    "-dname", "CN=localhost", "-ext", "SAN=dns:localhost"));
            runKeytool(List.of("-genkeypair", "-noprompt", "-alias", "client", "-keyalg", "RSA",
                    "-keysize", "2048", "-validity", "2", "-storetype", "PKCS12", "-keystore",
                    clientIdentity.toString(), "-storepass", new String(PASSWORD), "-keypass", new String(PASSWORD),
                    "-dname", "CN=jlshell-wss-test-client"));
            exportCertificate(serverIdentity, "server", serverCertificate);
            exportCertificate(clientIdentity, "client", clientCertificate);
            importCertificate(clientTrust, "server", serverCertificate);
            importCertificate(serverTrust, "client", clientCertificate);
            return new TestIdentity(directory, context(clientIdentity, clientTrust),
                    context(serverIdentity, serverTrust));
        }

        private static void exportCertificate(Path identity, String alias, Path certificate) throws Exception {
            runKeytool(List.of("-exportcert", "-rfc", "-alias", alias, "-keystore", identity.toString(),
                    "-storetype", "PKCS12", "-storepass", new String(PASSWORD), "-file", certificate.toString()));
        }

        private static void importCertificate(Path trust, String alias, Path certificate) throws Exception {
            runKeytool(List.of("-importcert", "-noprompt", "-alias", alias, "-file", certificate.toString(),
                    "-keystore", trust.toString(), "-storetype", "PKCS12", "-storepass", new String(PASSWORD)));
        }

        private static SSLContext context(Path identity, Path trust) throws Exception {
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            if (identity != null) {
                KeyStore keys = KeyStore.getInstance("PKCS12");
                try (var input = Files.newInputStream(identity)) {
                    keys.load(input, PASSWORD);
                }
                keyManagers.init(keys, PASSWORD);
            }
            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            if (trust != null) {
                KeyStore trustStore = KeyStore.getInstance("PKCS12");
                try (var input = Files.newInputStream(trust)) {
                    trustStore.load(input, PASSWORD);
                }
                trustManagers.init(trustStore);
            } else {
                trustManagers.init((KeyStore) null);
            }
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(identity == null ? null : keyManagers.getKeyManagers(),
                    trustManagers.getTrustManagers(), null);
            return context;
        }

        private static void runKeytool(List<String> args) throws Exception {
            String executable = System.getProperty("os.name").toLowerCase().contains("win")
                    ? "keytool.exe" : "keytool";
            List<String> command = new ArrayList<>();
            command.add(Path.of(System.getProperty("java.home"), "bin", executable).toString());
            command.addAll(args);
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            byte[] output = process.getInputStream().readAllBytes();
            if (!process.waitFor(30, TimeUnit.SECONDS) || process.exitValue() != 0) {
                process.destroyForcibly();
                throw new IOException("keytool failed: " + new String(output, StandardCharsets.UTF_8));
            }
        }

        private SSLContext clientContext() {
            return clientContext;
        }

        private SSLContext serverContext() {
            return serverContext;
        }

        @Override
        public void close() throws IOException {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }
}
