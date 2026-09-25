package com.jlshell.link.transport.poc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

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
import com.jlshell.link.core.transport.TlsPeerContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.NetworkInterface;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import kcp.IKcp;
import kcp.Kcp;
import org.ice4j.ice.Agent;
import org.ice4j.ice.CandidateType;
import org.ice4j.ice.Component;
import org.ice4j.ice.IceMediaStream;
import org.ice4j.ice.KeepAliveStrategy;
import org.ice4j.ice.RemoteCandidate;
import org.junit.jupiter.api.Test;

/** API/socket lifecycle smoke test for the pinned ice4j candidate. */
class IceKcpTls13IntegrationTest {
    @Test
    void gathersCandidatesAndNominatesAReachableLanPair() throws Exception {
        assumeTrue(Boolean.parseBoolean(System.getenv().getOrDefault("JLSHELL_LINK_ICE_TEST_ENABLED", "true")),
                "ICE integration disabled because this runner does not expose a usable host candidate");
        String activeIpv4Interface = Collections.list(NetworkInterface.getNetworkInterfaces()).stream()
                .filter(networkInterface -> {
                    try {
                        return networkInterface.isUp() && !networkInterface.isPointToPoint();
                    } catch (SocketException e) {
                        return false;
                    }
                })
                .filter(networkInterface -> Collections.list(networkInterface.getInetAddresses()).stream()
                        .anyMatch(address -> address instanceof Inet4Address && !address.isLoopbackAddress()))
                .map(NetworkInterface::getName)
                .findFirst().orElse(null);
        assumeTrue(activeIpv4Interface != null, "No active non-loopback IPv4 interface for ICE test");
        System.setProperty("ice4j.harvest.mapping.aws.enabled", "false");
        System.setProperty("org.ice4j.ice.harvest.ALLOWED_INTERFACES", activeIpv4Interface);
        System.setProperty("ice4j.harvest.use-ipv6", "false");
        System.setProperty("ice4j.harvest.use-link-local-addresses", "false");
        Agent agentA = new Agent();
        Agent agentC = new Agent();
        try {
            agentA.setControlling(true);
            agentC.setControlling(false);
            IceMediaStream streamA = agentA.createMediaStream("link");
            IceMediaStream streamC = agentC.createMediaStream("link");
            Component componentA = agentA.createComponent(streamA, 0, 0, 0,
                    KeepAliveStrategy.SELECTED_ONLY, true);
            Component componentC = agentC.createComponent(streamC, 0, 0, 0,
                    KeepAliveStrategy.SELECTED_ONLY, true);

            assertFalse(componentA.getLocalCandidates().isEmpty(), "ICE A gathered no local candidates");
            assertTrue(componentA.getLocalCandidates().stream()
                    .allMatch(candidate -> candidate.getTransportAddress().getPort() > 0));
            assertNotNull(componentA.getSocket(), "ICE component application socket is unavailable");
            assertNotNull(componentC.getSocket(), "ICE component application socket is unavailable");

            var localA = componentA.getLocalCandidates().stream()
                    .filter(candidate -> candidate.getType() == CandidateType.HOST_CANDIDATE)
                    .findFirst().orElseThrow();
            var localC = componentC.getLocalCandidates().stream()
                    .filter(candidate -> candidate.getType() == CandidateType.HOST_CANDIDATE)
                    .findFirst().orElseThrow();
            streamA.setRemoteUfrag(agentC.getLocalUfrag());
            streamA.setRemotePassword(agentC.getLocalPassword());
            streamC.setRemoteUfrag(agentA.getLocalUfrag());
            streamC.setRemotePassword(agentA.getLocalPassword());
            componentA.addRemoteCandidate(new RemoteCandidate(
                    localC.getTransportAddress(), componentA, CandidateType.HOST_CANDIDATE,
                    "peer-c", 2_130_706_431L, null));
            componentC.addRemoteCandidate(new RemoteCandidate(
                    localA.getTransportAddress(), componentC, CandidateType.HOST_CANDIDATE,
                    "peer-a", 2_130_706_431L, null));
            agentA.startConnectivityEstablishment();
            agentC.startConnectivityEstablishment();

            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (System.nanoTime() < deadline
                    && (componentA.getSelectedPair() == null || componentC.getSelectedPair() == null)) {
                Thread.sleep(20);
            }
            assertNotNull(componentA.getSelectedPair(), "ICE A did not nominate the reachable pair");
            assertNotNull(componentC.getSelectedPair(), "ICE C did not nominate the reachable pair");
            assertEquals(localA.getTransportAddress(), componentA.getSocket().getLocalSocketAddress(),
                    "ICE A host candidate and application socket do not share a local address");
            assertEquals(localC.getTransportAddress(), componentC.getSocket().getLocalSocketAddress(),
                    "ICE C host candidate and application socket do not share a local address");
            assertEquals(localA.getTransportAddress(),
                    componentA.getSelectedPair().getLocalCandidate().getTransportAddress());
            assertEquals(localC.getTransportAddress(),
                    componentC.getSelectedPair().getLocalCandidate().getTransportAddress());

            try (IceKcpPeer peerA = new IceKcpPeer(
                            componentA.getSocket(),
                            componentA.getSelectedPair().getRemoteCandidate().getTransportAddress(), 2, true);
                    IceKcpPeer peerC = new IceKcpPeer(
                            componentC.getSocket(),
                            componentC.getSelectedPair().getRemoteCandidate().getTransportAddress(), 0, false)) {
                byte[] payload = new byte[4_096];
                for (int i = 0; i < payload.length; i++) {
                    payload[i] = (byte) (i * 31 + (i >>> 3));
                }
                peerA.send(payload);
                assertArrayEquals(payload, peerC.receiveExactly(payload.length),
                        "KCP did not recover dropped data over the ICE component sockets");
                assertEquals(2, peerA.droppedPackets.get(), "KCP loss injection did not drop both initial datagrams");
                assertTrue(peerA.reorderedPackets.get(), "KCP datagram reorder injection did not run");
                byte[] response = new byte[777];
                for (int i = 0; i < response.length; i++) {
                    response[i] = (byte) (255 - i * 13);
                }
                peerC.send(response);
                assertArrayEquals(response, peerA.receiveExactly(response.length),
                        "KCP reverse stream did not preserve binary data");

                byte[] slowPayload = new byte[256 * 1_024];
                for (int i = 0; i < slowPayload.length; i++) {
                    slowPayload[i] = (byte) (i * 23 + (i >>> 4));
                }
                peerA.send(slowPayload);
                assertArrayEquals(slowPayload, peerC.receiveExactly(slowPayload.length, true),
                        "KCP stream failed while the application consumed slowly");
                assertTrue(peerC.maxQueuedChunks.get() <= 4,
                        "application queue exceeded the configured four-chunk bound");
                assertTrue(peerC.deferredReads.get() > 0,
                        "slow application consumer did not defer reads from KCP");

                try (TlsTestIdentities identities = TlsTestIdentities.create()) {
                    SSLEngine tlsClient = identities.clientContext().createSSLEngine("localhost", 443);
                    configureTls13(tlsClient, true);
                    SSLEngine tlsServer = identities.serverContext().createSSLEngine();
                    configureTls13(tlsServer, false);
                    TlsEndpoint clientTls = new TlsEndpoint(tlsClient, peerA);
                    TlsEndpoint serverTls = new TlsEndpoint(tlsServer, peerC);
                    completeHandshake(clientTls, serverTls);
                    assertTrue("TLSv1.3".equals(tlsClient.getSession().getProtocol()));
                    assertTrue("TLSv1.3".equals(tlsServer.getSession().getProtocol()));

                    byte[] securePayload = "mutual TLS 1.3 over ICE/KCP".getBytes(StandardCharsets.UTF_8);
                    sendTlsApplicationData(tlsClient, peerA, securePayload);
                    assertArrayEquals(securePayload, receiveTlsApplicationData(serverTls, securePayload.length));

                    try (TcpEchoTarget target = new TcpEchoTarget();
                            Http2ConnectSession h2 = new Http2ConnectSession(target.port())) {
                        transferClientH2ToServer(clientTls, serverTls, h2);
                        transferServerH2ToClient(clientTls, serverTls, h2);
                        transferClientH2ToServer(clientTls, serverTls, h2);

                        h2.openConnect();
                        transferClientH2ToServer(clientTls, serverTls, h2);
                        transferServerH2ToClient(clientTls, serverTls, h2);
                        assertTrue(h2.connectAccepted(), "HTTP/2 CONNECT was not accepted");
                        assertEquals(200, h2.responseStatus.poll(2, TimeUnit.SECONDS));

                        byte[] connectData = new byte[1_024];
                        for (int i = 0; i < connectData.length; i++) {
                            connectData[i] = (byte) (i * 7 + 3);
                        }
                        h2.sendData(connectData, true);
                        transferClientH2ToServer(clientTls, serverTls, h2);
                        transferServerH2ToClient(clientTls, serverTls, h2);
                        assertArrayEquals(connectData, h2.echoedData.poll(2, TimeUnit.SECONDS),
                                "HTTP/2 CONNECT data did not reach the TCP target and return");
                        assertTrue(h2.responseEnded.get(),
                                "HTTP/2 END_STREAM was not returned after the TCP half-close");
                    }

                    SSLEngine untrustedClient = identities.untrustedClientContext().createSSLEngine("localhost", 443);
                    configureTls13(untrustedClient, true);
                    SSLEngine secondServer = identities.serverContext().createSSLEngine();
                    configureTls13(secondServer, false);
                    assertThrows(SSLException.class, () -> completeHandshake(
                            new TlsEndpoint(untrustedClient, peerA), new TlsEndpoint(secondServer, peerC)),
                            "server accepted a client certificate outside its test trust store");

                    SSLEngine wrongPinClient = identities.wrongPinClientContext().createSSLEngine("localhost", 443);
                    configureTls13(wrongPinClient, true);
                    SSLEngine thirdServer = identities.serverContext().createSSLEngine();
                    configureTls13(thirdServer, false);
                    assertThrows(SSLException.class, () -> completeHandshake(
                            new TlsEndpoint(wrongPinClient, peerA), new TlsEndpoint(thirdServer, peerC)),
                            "client accepted a trusted certificate with the wrong public key pin");
                }

                CompletableFuture<byte[]> blockedRead = CompletableFuture.supplyAsync(() -> {
                    try {
                        return peerC.receiveExactly(1, false);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new java.util.concurrent.CompletionException(e);
                    }
                });
                Thread.sleep(50);
                peerC.close();
                ExecutionException cancelled = assertThrows(ExecutionException.class,
                        () -> blockedRead.get(2, TimeUnit.SECONDS));
                assertTrue(cancelled.getCause() instanceof CancellationException,
                        "closed ICE/KCP receive did not surface cancellation");
                assertFalse(componentC.getSocket().isClosed(),
                        "KCP adapter closed the ICE-owned application socket");
            }
        } finally {
            agentA.free();
            agentC.free();
        }
        assertTrue(agentA.isOver(), "ICE A did not release its sockets");
        assertTrue(agentC.isOver(), "ICE C did not release its sockets");
    }

    private static void transferClientH2ToServer(
            TlsEndpoint clientTls, TlsEndpoint serverTls, Http2ConnectSession h2) throws Exception {
        byte[] encodedFrames = h2.drainClientOutbound();
        assertTrue(encodedFrames.length > 0, "HTTP/2 client produced no wire bytes");
        sendTlsApplicationData(clientTls.engine, clientTls.peer, encodedFrames);
        h2.receiveAtServer(receiveTlsApplicationData(serverTls, encodedFrames.length));
    }

    private static void transferServerH2ToClient(
            TlsEndpoint clientTls, TlsEndpoint serverTls, Http2ConnectSession h2) throws Exception {
        byte[] encodedFrames = h2.drainServerOutbound();
        assertTrue(encodedFrames.length > 0, "HTTP/2 server produced no wire bytes");
        sendTlsApplicationData(serverTls.engine, serverTls.peer, encodedFrames);
        h2.receiveAtClient(receiveTlsApplicationData(clientTls, encodedFrames.length));
    }

    private static final class TcpEchoTarget implements AutoCloseable {
        private final ServerSocket listener;
        private final AtomicReference<Socket> acceptedSocket = new AtomicReference<>();
        private final Thread serverThread;

        private TcpEchoTarget() throws IOException {
            listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            serverThread = Thread.ofVirtual().start(() -> {
                try (Socket socket = listener.accept()) {
                    acceptedSocket.set(socket);
                    byte[] buffer = new byte[2_048];
                    int count;
                    while ((count = socket.getInputStream().read(buffer)) >= 0) {
                        socket.getOutputStream().write(buffer, 0, count);
                        socket.getOutputStream().flush();
                    }
                } catch (IOException ignored) {
                    // Closing the POC target ends the echo loop.
                }
            });
        }

        private int port() {
            return listener.getLocalPort();
        }

        @Override
        public void close() throws Exception {
            listener.close();
            Socket socket = acceptedSocket.get();
            if (socket != null) {
                socket.close();
            }
            serverThread.join(1_000);
            if (serverThread.isAlive()) {
                throw new IOException("TCP echo target did not stop");
            }
        }
    }

    private static final class Http2ConnectSession implements AutoCloseable {
        private final AtomicReference<Http2Headers> connectRequest = new AtomicReference<>();
        private final AtomicReference<Socket> targetSocket = new AtomicReference<>();
        private final AtomicBoolean responseEnded = new AtomicBoolean();
        private final LinkedBlockingQueue<Integer> responseStatus = new LinkedBlockingQueue<>();
        private final LinkedBlockingQueue<byte[]> echoedData = new LinkedBlockingQueue<>();
        private final EmbeddedChannel client;
        private final EmbeddedChannel server;
        private final int targetPort;
        private Http2StreamChannel clientStream;

        private Http2ConnectSession(int targetPort) {
            this.targetPort = targetPort;
            client = new EmbeddedChannel(
                    Http2FrameCodecBuilder.forClient().build(),
                    new Http2MultiplexHandler(new SimpleChannelInboundHandler<Http2Frame>() {
                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx, Http2Frame frame) {
                            // Client-initiated streams are opened through Http2StreamChannelBootstrap.
                        }
                    }));
            server = new EmbeddedChannel(
                    Http2FrameCodecBuilder.forServer().build(),
                    new Http2MultiplexHandler(new ChannelInitializer<Http2StreamChannel>() {
                        @Override
                        protected void initChannel(Http2StreamChannel stream) {
                            stream.pipeline().addLast(new SimpleChannelInboundHandler<Http2Frame>() {
                                @Override
                                protected void channelRead0(ChannelHandlerContext ctx, Http2Frame frame)
                                        throws Exception {
                                    if (frame instanceof Http2HeadersFrame headersFrame) {
                                        Http2Headers headers = headersFrame.headers();
                                        if ("CONNECT".contentEquals(headers.method())) {
                                            connectRequest.set(new DefaultHttp2Headers().add(headers));
                                            Socket socket = new Socket(InetAddress.getLoopbackAddress(), targetPort);
                                            targetSocket.set(socket);
                                            ctx.writeAndFlush(new DefaultHttp2HeadersFrame(
                                                    new DefaultHttp2Headers().status("200")));
                                        }
                                    } else if (frame instanceof Http2DataFrame dataFrame) {
                                        Socket socket = targetSocket.get();
                                        if (socket == null) {
                                            throw new IOException("CONNECT target socket is not open");
                                        }
                                        byte[] request = new byte[dataFrame.content().readableBytes()];
                                        dataFrame.content().getBytes(dataFrame.content().readerIndex(), request);
                                        socket.getOutputStream().write(request);
                                        socket.getOutputStream().flush();
                                        if (dataFrame.isEndStream()) {
                                            socket.shutdownOutput();
                                        }
                                        byte[] response = socket.getInputStream().readNBytes(request.length);
                                        if (response.length != request.length) {
                                            throw new IOException("TCP target returned a truncated response");
                                        }
                                        ctx.writeAndFlush(new DefaultHttp2DataFrame(
                                                Unpooled.wrappedBuffer(response), dataFrame.isEndStream()));
                                    }
                                }
                            });
                        }
                    }));
        }

        private void openConnect() throws Exception {
            clientStream = new Http2StreamChannelBootstrap(client)
                    .handler(new SimpleChannelInboundHandler<Http2Frame>() {
                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx, Http2Frame frame) {
                            if (frame instanceof Http2HeadersFrame headersFrame) {
                                responseStatus.offer(Integer.parseInt(headersFrame.headers().status().toString()));
                            } else if (frame instanceof Http2DataFrame dataFrame) {
                                byte[] bytes = new byte[dataFrame.content().readableBytes()];
                                dataFrame.content().getBytes(dataFrame.content().readerIndex(), bytes);
                                echoedData.offer(bytes);
                                responseEnded.set(dataFrame.isEndStream());
                            }
                        }
                    })
                    .open()
                    .syncUninterruptibly()
                    .getNow();
            clientStream.writeAndFlush(new DefaultHttp2HeadersFrame(
                    new DefaultHttp2Headers().method("CONNECT").authority("127.0.0.1:" + targetPort)));
            client.runPendingTasks();
        }

        private boolean connectAccepted() {
            Http2Headers headers = connectRequest.get();
            return headers != null
                    && "CONNECT".contentEquals(headers.method())
                    && ("127.0.0.1:" + targetPort).contentEquals(headers.authority());
        }

        private void sendData(byte[] payload, boolean endStream) {
            clientStream.writeAndFlush(new DefaultHttp2DataFrame(
                    Unpooled.wrappedBuffer(payload.clone()), endStream));
            client.runPendingTasks();
        }

        private byte[] drainClientOutbound() {
            return drainOutbound(client);
        }

        private byte[] drainServerOutbound() {
            return drainOutbound(server);
        }

        private void receiveAtServer(byte[] bytes) {
            server.writeInbound(Unpooled.wrappedBuffer(bytes));
            server.runPendingTasks();
        }

        private void receiveAtClient(byte[] bytes) {
            client.writeInbound(Unpooled.wrappedBuffer(bytes));
            client.runPendingTasks();
        }

        private static byte[] drainOutbound(EmbeddedChannel channel) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            Object message;
            while ((message = channel.readOutbound()) != null) {
                if (!(message instanceof ByteBuf bytes)) {
                    throw new IllegalStateException("Unexpected HTTP/2 outbound message: " + message.getClass());
                }
                byte[] chunk = new byte[bytes.readableBytes()];
                bytes.readBytes(chunk);
                output.writeBytes(chunk);
                bytes.release();
            }
            return output.toByteArray();
        }

        @Override
        public void close() throws Exception {
            Socket socket = targetSocket.get();
            if (socket != null) {
                socket.close();
            }
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
        }
    }

    private static void configureTls13(SSLEngine engine, boolean client) {
        engine.setUseClientMode(client);
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.3"});
        if (client) {
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
        } else {
            parameters.setNeedClientAuth(true);
        }
        engine.setSSLParameters(parameters);
    }

    private static void completeHandshake(TlsEndpoint client, TlsEndpoint server) throws Exception {
        SSLEngine clientEngine = client.engine;
        SSLEngine serverEngine = server.engine;
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (System.nanoTime() < deadline) {
            driveHandshake(client);
            driveHandshake(server);
            if (clientEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                    && serverEngine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                return;
            }
            Thread.sleep(1);
        }
        throw new SSLException("TLS 1.3 handshake over ICE/KCP timed out: client="
                + clientEngine.getHandshakeStatus() + ", server=" + serverEngine.getHandshakeStatus());
    }

    private static void driveHandshake(TlsEndpoint endpoint) throws IOException, InterruptedException {
        SSLEngine engine = endpoint.engine;
        SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
        while (status == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
            status = engine.getHandshakeStatus();
        }

        byte[] incoming = endpoint.peer.pollReceived(0, TimeUnit.MILLISECONDS);
        if (incoming != null) {
            endpoint.networkInput.compact();
            if (incoming.length > endpoint.networkInput.remaining()) {
                throw new SSLException("TLS record exceeded the POC network buffer");
            }
            endpoint.networkInput.put(incoming);
            endpoint.networkInput.flip();
        }

        status = engine.getHandshakeStatus();
        if (status == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
            endpoint.networkOutput.clear();
            SSLEngineResult result = engine.wrap(ByteBuffer.allocate(0), endpoint.networkOutput);
            if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                throw new SSLException("TLS network output buffer overflow");
            }
            sendNetworkBytes(endpoint.peer, endpoint.networkOutput);
        } else if (status == SSLEngineResult.HandshakeStatus.NEED_UNWRAP
                || status == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
            if (endpoint.networkInput.hasRemaining()
                    || status == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                endpoint.applicationInput.clear();
                SSLEngineResult result = engine.unwrap(endpoint.networkInput, endpoint.applicationInput);
                if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                    throw new SSLException("TLS peer closed during handshake");
                }
            }
        }
    }

    private static void sendNetworkBytes(IceKcpPeer peer, ByteBuffer bytes) {
        bytes.flip();
        if (!bytes.hasRemaining()) {
            return;
        }
        byte[] packet = new byte[bytes.remaining()];
        bytes.get(packet);
        peer.send(packet);
    }

    private static void sendTlsApplicationData(SSLEngine engine, IceKcpPeer peer, byte[] plaintext)
            throws IOException {
        ByteBuffer source = ByteBuffer.wrap(plaintext);
        TlsEndpoint endpoint = new TlsEndpoint(engine, peer);
        while (source.hasRemaining()) {
            endpoint.networkOutput.clear();
            SSLEngineResult result = engine.wrap(source, endpoint.networkOutput);
            if (result.getStatus() != SSLEngineResult.Status.OK) {
                throw new SSLException("TLS application wrap failed: " + result.getStatus());
            }
            sendNetworkBytes(peer, endpoint.networkOutput);
        }
    }

    private static byte[] receiveTlsApplicationData(TlsEndpoint endpoint, int expectedBytes) throws Exception {
        SSLEngine engine = endpoint.engine;
        IceKcpPeer peer = endpoint.peer;
        int applicationBufferSize = engine.getSession().getApplicationBufferSize();
        ByteBuffer plaintext = ByteBuffer.allocate(Math.max(expectedBytes + 1_024, applicationBufferSize));
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (plaintext.position() < expectedBytes && System.nanoTime() < deadline) {
            byte[] incoming = peer.pollReceived(100, TimeUnit.MILLISECONDS);
            if (incoming == null) {
                continue;
            }
            endpoint.networkInput.compact();
            if (incoming.length > endpoint.networkInput.remaining()) {
                throw new SSLException("TLS record exceeded the POC network buffer");
            }
            endpoint.networkInput.put(incoming);
            endpoint.networkInput.flip();
            SSLEngineResult result = engine.unwrap(endpoint.networkInput, plaintext);
            if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                throw new SSLException("TLS peer closed during application data");
            }
        }
        if (plaintext.position() != expectedBytes) {
            throw new SSLException("TLS application data timed out: received " + plaintext.position()
                    + " of " + expectedBytes + " bytes");
        }
        return java.util.Arrays.copyOf(plaintext.array(), plaintext.position());
    }

    private static final class TlsEndpoint {
        private final SSLEngine engine;
        private final IceKcpPeer peer;
        private final ByteBuffer networkInput = ByteBuffer.allocate(65_536);
        private final ByteBuffer networkOutput = ByteBuffer.allocate(65_536);
        private final ByteBuffer applicationInput = ByteBuffer.allocate(65_536);

        private TlsEndpoint(SSLEngine engine, IceKcpPeer peer) {
            this.engine = engine;
            this.peer = peer;
            networkInput.limit(0);
        }
    }

    private static final class TlsTestIdentities implements AutoCloseable {
        private static final char[] PASSWORD = "link-poc-test".toCharArray();
        private final Path directory;
        private final SSLContext clientContext;
        private final SSLContext serverContext;
        private final SSLContext untrustedClientContext;
        private final SSLContext wrongPinClientContext;

        private TlsTestIdentities(
                Path directory,
                SSLContext clientContext,
                SSLContext serverContext,
                SSLContext untrustedClientContext,
                SSLContext wrongPinClientContext) {
            this.directory = directory;
            this.clientContext = clientContext;
            this.serverContext = serverContext;
            this.untrustedClientContext = untrustedClientContext;
            this.wrongPinClientContext = wrongPinClientContext;
        }

        private static TlsTestIdentities create() throws Exception {
            Path directory = Files.createTempDirectory("jlshell-link-tls-poc-");
            Path serverIdentity = directory.resolve("server.p12");
            Path clientIdentity = directory.resolve("client.p12");
            Path untrustedClientIdentity = directory.resolve("untrusted-client.p12");
            Path serverCertificate = directory.resolve("server.cer");
            Path clientCertificate = directory.resolve("client.cer");
            Path clientTrust = directory.resolve("client-trust.p12");
            Path serverTrust = directory.resolve("server-trust.p12");
            generateIdentity(serverIdentity, "server", "CN=localhost", "serverAuth", true);
            generateIdentity(clientIdentity, "client", "CN=jlshell-test-client", "clientAuth", false);
            generateIdentity(untrustedClientIdentity, "untrusted", "CN=untrusted-test-client", "clientAuth", false);
            exportCertificate(serverIdentity, "server", serverCertificate);
            exportCertificate(clientIdentity, "client", clientCertificate);
            importCertificate(clientTrust, "server", serverCertificate);
            importCertificate(serverTrust, "client", clientCertificate);
            return new TlsTestIdentities(
                    directory,
                    pinnedSslContext(clientIdentity, clientTrust, serverCertificate, false),
                    pinnedSslContext(serverIdentity, serverTrust, clientCertificate, false),
                    pinnedSslContext(untrustedClientIdentity, clientTrust, serverCertificate, false),
                    pinnedSslContext(clientIdentity, clientTrust, serverCertificate, true));
        }

        private static void generateIdentity(
                Path store, String alias, String subject, String extendedKeyUsage, boolean server)
                throws Exception {
            List<String> args = new ArrayList<>(List.of(
                    "-genkeypair", "-noprompt", "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
                    "-validity", "2", "-storetype", "PKCS12", "-keystore", store.toString(),
                    "-storepass", new String(PASSWORD), "-keypass", new String(PASSWORD), "-dname", subject,
                    "-ext", "EKU=" + extendedKeyUsage));
            if (server) {
                args.addAll(List.of("-ext", "SAN=dns:localhost"));
            }
            runKeytool(args);
        }

        private static void exportCertificate(Path store, String alias, Path output) throws Exception {
            runKeytool(List.of(
                    "-exportcert", "-rfc", "-alias", alias, "-keystore", store.toString(),
                    "-storetype", "PKCS12", "-storepass", new String(PASSWORD), "-file", output.toString()));
        }

        private static void importCertificate(Path store, String alias, Path certificate) throws Exception {
            runKeytool(List.of(
                    "-importcert", "-noprompt", "-alias", alias, "-file", certificate.toString(),
                    "-keystore", store.toString(), "-storetype", "PKCS12", "-storepass", new String(PASSWORD)));
        }

        private static void runKeytool(List<String> args) throws Exception {
            String executable = System.getProperty("os.name").toLowerCase().contains("win") ? "keytool.exe" : "keytool";
            Path keytool = Path.of(System.getProperty("java.home"), "bin", executable);
            List<String> command = new ArrayList<>();
            command.add(keytool.toString());
            command.addAll(args);
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            byte[] output = process.getInputStream().readAllBytes();
            if (!process.waitFor(30, TimeUnit.SECONDS) || process.exitValue() != 0) {
                process.destroyForcibly();
                throw new IOException("keytool failed: " + new String(output, StandardCharsets.UTF_8));
            }
        }

        private static SSLContext pinnedSslContext(Path identity, Path trust, Path peerCertificate,
                boolean corruptPin) throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(identity)) {
                keyStore.load(input, PASSWORD);
            }
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keyStore, PASSWORD);

            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(trust)) {
                trustStore.load(input, PASSWORD);
            }
            java.security.cert.X509Certificate peer;
            try (var input = Files.newInputStream(peerCertificate)) {
                peer = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory
                        .getInstance("X.509").generateCertificate(input);
            }
            byte[] pin = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(peer.getPublicKey().getEncoded());
            if (corruptPin) {
                pin[0] ^= 1;
            }
            return TlsPeerContext.create(keyManagers.getKeyManagers(), trustStore, pin);
        }

        private SSLContext clientContext() {
            return clientContext;
        }

        private SSLContext serverContext() {
            return serverContext;
        }

        private SSLContext untrustedClientContext() {
            return untrustedClientContext;
        }

        private SSLContext wrongPinClientContext() {
            return wrongPinClientContext;
        }

        @Override
        public void close() throws IOException {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(Collections.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }

    private static final class IceKcpPeer implements AutoCloseable {
        private final DatagramSocket iceSocket;
        private final IceComponentDatagramAdapter adapter;
        private final Kcp engine;
        private final ArrayBlockingQueue<byte[]> received = new ArrayBlockingQueue<>(4);
        private final AtomicInteger maxQueuedChunks = new AtomicInteger();
        private final AtomicInteger deferredReads = new AtomicInteger();
        private final int dropFirstPackets;
        private final boolean reorderFirstPair;
        private final AtomicInteger outboundPackets = new AtomicInteger();
        private final AtomicInteger droppedPackets = new AtomicInteger();
        private final AtomicReference<byte[]> delayedDatagram = new AtomicReference<>();
        private final AtomicBoolean reorderedPackets = new AtomicBoolean();
        private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform().name("ice-kcp-poc-timer-", 0).factory());
        private final AtomicBoolean closed = new AtomicBoolean();
        private final Thread receiver;

        private IceKcpPeer(
                DatagramSocket iceSocket,
                SocketAddress remote,
                int dropFirstPackets,
                boolean reorderFirstPair) throws SocketException {
            this.iceSocket = iceSocket;
            this.dropFirstPackets = dropFirstPackets;
            this.reorderFirstPair = reorderFirstPair;
            this.iceSocket.setSoTimeout(100);
            this.adapter = new IceComponentDatagramAdapter(iceSocket, remote, this::receiveSegment);
            this.engine = new Kcp(0x4A4C5348, this::sendSegment);
            engine.nodelay(true, 10, 2, true);
            engine.setSndWnd(64);
            engine.setRcvWnd(64);
            engine.setMtu(1_200);
            engine.setStream(true);
            this.receiver = Thread.ofVirtual().start(this::receiveLoop);
            timer.scheduleAtFixedRate(this::update, 0, 10, TimeUnit.MILLISECONDS);
        }

        private void send(byte[] payload) {
            synchronized (engine) {
                ByteBuf data = Unpooled.wrappedBuffer(payload.clone());
                int result = engine.send(data);
                data.release();
                if (result < 0) {
                    throw new IllegalStateException("KCP rejected payload: " + result);
                }
                engine.update(System.currentTimeMillis());
            }
        }

        private byte[] receiveExactly(int length) throws InterruptedException {
            return receiveExactly(length, false);
        }

        private byte[] receiveExactly(int length, boolean slowConsumer) throws InterruptedException {
            byte[] result = new byte[length];
            int offset = 0;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (offset < length && System.nanoTime() < deadline) {
                if (closed.get()) {
                    throw new CancellationException("ICE/KCP receive cancelled because the peer closed");
                }
                byte[] chunk = pollReceived(100, TimeUnit.MILLISECONDS);
                if (chunk == null) {
                    continue;
                }
                int copyLength = Math.min(chunk.length, length - offset);
                System.arraycopy(chunk, 0, result, offset, copyLength);
                offset += copyLength;
                if (slowConsumer) {
                    Thread.sleep(1);
                }
            }
            return offset == length ? result : java.util.Arrays.copyOf(result, offset);
        }

        private byte[] pollReceived(long timeout, TimeUnit unit) throws InterruptedException {
            byte[] chunk = received.poll(timeout, unit);
            if (chunk != null && !closed.get()) {
                synchronized (engine) {
                    drainKcpToApplicationQueue();
                    if (engine.checkFlush()) {
                        engine.flush(false, System.currentTimeMillis());
                    }
                }
            }
            return chunk;
        }

        private void sendSegment(ByteBuf segment, IKcp ignored) {
            try {
                byte[] datagram = new byte[segment.readableBytes()];
                segment.getBytes(segment.readerIndex(), datagram);
                if (outboundPackets.getAndIncrement() < dropFirstPackets) {
                    droppedPackets.incrementAndGet();
                    return;
                }
                byte[] delayed = delayedDatagram.getAndSet(null);
                if (reorderFirstPair && !reorderedPackets.get()) {
                    if (delayed == null) {
                        delayedDatagram.set(datagram);
                        return;
                    }
                    adapter.send(datagram);
                    adapter.send(delayed);
                    reorderedPackets.set(true);
                    return;
                }
                adapter.send(datagram);
            } catch (IOException e) {
                throw new IllegalStateException("Unable to send KCP datagram over ICE socket", e);
            } finally {
                segment.release();
            }
        }

        private void receiveSegment(byte[] datagram) {
            synchronized (engine) {
                engine.input(Unpooled.wrappedBuffer(datagram), true, System.currentTimeMillis());
                drainKcpToApplicationQueue();
                if (engine.checkFlush()) {
                    engine.flush(false, System.currentTimeMillis());
                }
            }
        }

        private void drainKcpToApplicationQueue() {
            while (received.remainingCapacity() > 0) {
                List<ByteBuf> completeMessages = new ArrayList<>(1);
                int readable = engine.recv(completeMessages);
                if (readable <= 0) {
                    break;
                }
                for (ByteBuf message : completeMessages) {
                    try {
                        byte[] payload = new byte[message.readableBytes()];
                        message.readBytes(payload);
                        if (!received.offer(payload)) {
                            throw new IllegalStateException("bounded application queue rejected a KCP chunk");
                        }
                        maxQueuedChunks.accumulateAndGet(received.size(), Math::max);
                    } finally {
                        message.release();
                    }
                }
            }
            if (received.remainingCapacity() == 0 && engine.canRecv()) {
                deferredReads.incrementAndGet();
            }
        }

        private void receiveLoop() {
            while (!closed.get()) {
                try {
                    adapter.receiveOne(1_200);
                } catch (SocketTimeoutException ignored) {
                    // Polling timeout lets the POC stop without closing ICE-owned sockets.
                } catch (IOException e) {
                    if (!closed.get()) {
                        received.offer(new byte[0]);
                    }
                }
            }
        }

        private void update() {
            synchronized (engine) {
                if (!closed.get()) {
                    engine.update(System.currentTimeMillis());
                }
            }
        }

        @Override
        public void close() throws Exception {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            timer.shutdownNow();
            if (!timer.awaitTermination(1, TimeUnit.SECONDS)) {
                throw new IOException("KCP timer did not stop");
            }
            receiver.join(1_000);
            if (receiver.isAlive()) {
                throw new IOException("KCP receiver did not stop");
            }
            synchronized (engine) {
                engine.release();
            }
        }
    }
}
