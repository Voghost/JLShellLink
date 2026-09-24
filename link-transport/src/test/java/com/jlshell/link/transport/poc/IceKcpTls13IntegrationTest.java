package com.jlshell.link.transport.poc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
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

            try (IceKcpPeer peerA = new IceKcpPeer(
                            componentA.getSocket(),
                            componentA.getSelectedPair().getRemoteCandidate().getTransportAddress(), true);
                    IceKcpPeer peerC = new IceKcpPeer(
                            componentC.getSocket(),
                            componentC.getSelectedPair().getRemoteCandidate().getTransportAddress(), false)) {
                byte[] payload = new byte[4_096];
                for (int i = 0; i < payload.length; i++) {
                    payload[i] = (byte) (i * 31 + (i >>> 3));
                }
                peerA.send(payload);
                assertArrayEquals(payload, peerC.receiveExactly(payload.length),
                        "KCP did not recover dropped data over the ICE component sockets");
                assertTrue(peerA.droppedPackets.get() == 1, "KCP loss injection did not run");
                byte[] response = new byte[777];
                for (int i = 0; i < response.length; i++) {
                    response[i] = (byte) (255 - i * 13);
                }
                peerC.send(response);
                assertArrayEquals(response, peerA.receiveExactly(response.length),
                        "KCP reverse stream did not preserve binary data");

                try (TlsTestIdentities identities = TlsTestIdentities.create()) {
                    SSLEngine tlsClient = identities.clientContext().createSSLEngine("localhost", 443);
                    configureTls13(tlsClient, true);
                    SSLEngine tlsServer = identities.serverContext().createSSLEngine();
                    configureTls13(tlsServer, false);
                    completeHandshake(tlsClient, tlsServer, peerA, peerC);
                    assertTrue("TLSv1.3".equals(tlsClient.getSession().getProtocol()));
                    assertTrue("TLSv1.3".equals(tlsServer.getSession().getProtocol()));

                    byte[] securePayload = "mutual TLS 1.3 over ICE/KCP".getBytes(StandardCharsets.UTF_8);
                    sendTlsApplicationData(tlsClient, peerA, securePayload);
                    assertArrayEquals(securePayload, receiveTlsApplicationData(tlsServer, peerC, securePayload.length));

                    SSLEngine untrustedClient = identities.untrustedClientContext().createSSLEngine("localhost", 443);
                    configureTls13(untrustedClient, true);
                    SSLEngine secondServer = identities.serverContext().createSSLEngine();
                    configureTls13(secondServer, false);
                    assertThrows(SSLException.class, () -> completeHandshake(
                            untrustedClient, secondServer, peerA, peerC),
                            "server accepted a client certificate outside its test trust store");
                }
            }
        } finally {
            agentA.free();
            agentC.free();
        }
        assertTrue(agentA.isOver(), "ICE A did not release its sockets");
        assertTrue(agentC.isOver(), "ICE C did not release its sockets");
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

    private static void completeHandshake(
            SSLEngine clientEngine, SSLEngine serverEngine, IceKcpPeer clientPeer, IceKcpPeer serverPeer)
            throws Exception {
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();
        TlsEndpoint client = new TlsEndpoint(clientEngine, clientPeer);
        TlsEndpoint server = new TlsEndpoint(serverEngine, serverPeer);
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

    private static void driveHandshake(TlsEndpoint endpoint) throws IOException {
        SSLEngine engine = endpoint.engine;
        SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
        while (status == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
            status = engine.getHandshakeStatus();
        }

        byte[] incoming = endpoint.peer.received.poll();
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

    private static byte[] receiveTlsApplicationData(SSLEngine engine, IceKcpPeer peer, int expectedBytes)
            throws Exception {
        TlsEndpoint endpoint = new TlsEndpoint(engine, peer);
        ByteBuffer plaintext = ByteBuffer.allocate(expectedBytes + 1_024);
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (plaintext.position() < expectedBytes && System.nanoTime() < deadline) {
            byte[] incoming = peer.received.poll(100, TimeUnit.MILLISECONDS);
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

        private TlsTestIdentities(
                Path directory,
                SSLContext clientContext,
                SSLContext serverContext,
                SSLContext untrustedClientContext) {
            this.directory = directory;
            this.clientContext = clientContext;
            this.serverContext = serverContext;
            this.untrustedClientContext = untrustedClientContext;
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
                    sslContext(clientIdentity, clientTrust),
                    sslContext(serverIdentity, serverTrust),
                    sslContext(untrustedClientIdentity, clientTrust));
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

        private static SSLContext sslContext(Path identity, Path trust) throws Exception {
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
            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trustStore);

            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
            return context;
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
        private final boolean dropFirstPacket;
        private final AtomicInteger droppedPackets = new AtomicInteger();
        private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform().name("ice-kcp-poc-timer-", 0).factory());
        private final AtomicBoolean closed = new AtomicBoolean();
        private final Thread receiver;

        private IceKcpPeer(
                DatagramSocket iceSocket,
                SocketAddress remote,
                boolean dropFirstPacket) throws SocketException {
            this.iceSocket = iceSocket;
            this.dropFirstPacket = dropFirstPacket;
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
            byte[] result = new byte[length];
            int offset = 0;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (offset < length && System.nanoTime() < deadline) {
                byte[] chunk = received.poll(100, TimeUnit.MILLISECONDS);
                if (chunk == null) {
                    continue;
                }
                int copyLength = Math.min(chunk.length, length - offset);
                System.arraycopy(chunk, 0, result, offset, copyLength);
                offset += copyLength;
            }
            return offset == length ? result : java.util.Arrays.copyOf(result, offset);
        }

        private void sendSegment(ByteBuf segment, IKcp ignored) {
            try {
                byte[] datagram = new byte[segment.readableBytes()];
                segment.getBytes(segment.readerIndex(), datagram);
                if (dropFirstPacket && droppedPackets.compareAndSet(0, 1)) {
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
                int readable;
                do {
                    List<ByteBuf> completeMessages = new ArrayList<>();
                    readable = engine.recv(completeMessages);
                    for (ByteBuf message : completeMessages) {
                        try {
                            byte[] payload = new byte[message.readableBytes()];
                            message.readBytes(payload);
                            received.offer(payload);
                        } finally {
                            message.release();
                        }
                    }
                } while (readable > 0);
                if (engine.checkFlush()) {
                    engine.flush(false, System.currentTimeMillis());
                }
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
            closed.set(true);
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
