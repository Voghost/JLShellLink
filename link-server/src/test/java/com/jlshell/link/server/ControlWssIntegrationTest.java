package com.jlshell.link.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.signal.ControlSignal;
import com.jlshell.link.core.signal.ControlSignalJsonCodec;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ControlWssIntegrationTest {
    @TempDir Path temporary;

    @Test
    void proofBoundAAndCAcceptInviteRouteCandidateAndReceiveRevocation() throws Exception {
        SSLContext serverTls = serverTls();
        SSLContext clientTls = clientTls();
        var scheduler = Executors.newSingleThreadScheduledExecutor();
        var proofs = new NodeProofService();
        Clock clock = Clock.systemUTC();
        UUID account = UUID.randomUUID();
        UUID clientId = UUID.randomUUID();
        UUID agentId = UUID.randomUUID();
        Ed25519NodeKey clientKey = Ed25519NodeKey.generate();
        Ed25519NodeKey agentKey = Ed25519NodeKey.generate();
        var principals = Map.of(
                clientId, new ControlPeerAuthenticator.AuthenticatedPeer(NodeRole.CLIENT, account,
                        clientId, null, clientKey.fingerprint(), clientKey.publicKey()),
                agentId, new ControlPeerAuthenticator.AuthenticatedPeer(NodeRole.AGENT, account,
                        agentId, agentId, agentKey.fingerprint(), agentKey.publicKey()));
        var registry = new NodeConnectionRegistry(clock);
        var pairings = new RelayPairingService(registry, scheduler, clock, 16, 65_536);
        var router = new SignalRouter(clock, 16, 16, 16, 64);
        var server = new WssRelayServer(new InetSocketAddress("127.0.0.1", 0), serverTls,
                (handshake, credential) -> CompletableFuture.failedFuture(new SecurityException()),
                pairings, new RelayChallengeStore(new SecureRandom(), proofs, clock,
                        Duration.ofSeconds(30), 16), UsageRecorder.NOOP,
                new TransportBufferBudget(65_536), 65_536, Duration.ofSeconds(10), 2,
                (handshake, credential) -> {
                    var principal = principals.get(handshake.nodeId());
                    return "test-credential".equals(credential) && principal != null
                            && principal.matches(handshake)
                            ? CompletableFuture.completedFuture(principal)
                            : CompletableFuture.failedFuture(new SecurityException());
                }, new ControlChallengeStore(new SecureRandom(), proofs, clock,
                        Duration.ofSeconds(30), 16), router);
        HttpClient http = HttpClient.newBuilder().sslContext(clientTls).build();
        try {
            int port = server.start().toCompletableFuture().get(5, TimeUnit.SECONDS).getPort();
            try (ControlPeer client = connect(http, port, NodeRole.CLIENT, clientId, clientKey, proofs);
                    ControlPeer agent = connect(http, port, NodeRole.AGENT, agentId, agentKey, proofs)) {
                assertEquals("READY", client.nextType());
                assertEquals("READY", agent.nextType());
                LinkSessionId session = LinkSessionId.random();
                router.authorize(new SignalRouter.AuthorizedSession(account, session, clientId,
                        agentId, clientKey.fingerprint(), agentKey.fingerprint(), 1,
                        Instant.now().plusSeconds(60)));
                String inviteForClient = client.next();
                String inviteForAgent = agent.next();
                assertEquals("SESSION_INVITE", type(inviteForClient));
                assertEquals("SESSION_INVITE", type(inviteForAgent));
                long generation = ((ControlSignal.SessionInvite) new ControlSignalJsonCodec()
                        .decodeServerSignal(inviteForClient)).generation();
                ControlSignal.IceEnd end = new ControlSignal.IceEnd(UUID.randomUUID(), session, generation);
                client.socket.sendText(new ControlSignalJsonCodec().encode(end), true).join();
                assertEquals("ICE_END", agent.nextType());
                router.revoke(session);
                assertEquals("SESSION_REVOKED", client.nextType());
                assertEquals("SESSION_REVOKED", agent.nextType());
            }
        } finally {
            http.close();
            server.close();
            pairings.close();
            scheduler.shutdownNow();
        }
    }

    private ControlPeer connect(HttpClient http, int port, NodeRole role, UUID id,
                                Ed25519NodeKey key, NodeProofService proofs) throws Exception {
        String label = role == NodeRole.AGENT ? "agent" : "client";
        String base = "https://127.0.0.1:" + port;
        HttpRequest challengeRequest = HttpRequest.newBuilder(URI.create(base + "/link/v2/control-challenges"))
                .header("Authorization", "Bearer test-credential")
                .header("X-Link-Role", label)
                .header("X-Link-Node-Id", id.toString())
                .header("X-Link-Key-Fingerprint", key.fingerprint().value())
                .POST(HttpRequest.BodyPublishers.noBody()).build();
        HttpResponse<String> response = http.send(challengeRequest, HttpResponse.BodyHandlers.ofString());
        assertEquals(201, response.statusCode());
        Map<String, Object> body = JSONObjectUtils.parse(response.body());
        byte[] nonce = Base64.getUrlDecoder().decode(JSONObjectUtils.getString(body, "challenge"));
        String proof = Base64.getUrlEncoder().withoutPadding().encodeToString(proofs.sign(key,
                new NodeProofContext("control-channel", id, Optional.empty()), nonce));
        var received = new LinkedBlockingQueue<String>();
        WebSocket.Listener listener = new WebSocket.Listener() {
            @Override public void onOpen(WebSocket socket) {
                socket.request(1);
                socket.sendText(JSONObjectUtils.toJSONString(Map.of("type", "HELLO", "role", label,
                        "nodeId", id.toString(), "keyFingerprint", key.fingerprint().value(),
                        "minProtocol", "link-v2", "maxProtocol", "link-v2",
                        "capabilities", List.of("tcp-connect"), "sentAt", Instant.now().toString())), true);
            }
            @Override public java.util.concurrent.CompletionStage<?> onText(
                    WebSocket socket, CharSequence data, boolean last) {
                if (last) received.add(data.toString());
                socket.request(1);
                return CompletableFuture.completedFuture(null);
            }
        };
        WebSocket socket = http.newWebSocketBuilder()
                .header("Authorization", "Bearer test-credential")
                .header("X-Link-Role", label)
                .header("X-Link-Node-Id", id.toString())
                .header("X-Link-Key-Fingerprint", key.fingerprint().value())
                .header("X-Link-Challenge-Id", JSONObjectUtils.getString(body, "challengeId"))
                .header("X-Link-Proof", proof)
                .buildAsync(URI.create("wss://127.0.0.1:" + port + "/link/v2/control"), listener)
                .get(5, TimeUnit.SECONDS);
        return new ControlPeer(socket, received);
    }

    private SSLContext serverTls() throws Exception {
        Path p12 = temporary.resolve("server.p12");
        String executable = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool").toString();
        Process process = new ProcessBuilder(executable, "-genkeypair", "-noprompt", "-alias", "server",
                "-keyalg", "Ed25519", "-sigalg", "Ed25519", "-dname", "CN=localhost",
                "-ext", "SAN=IP:127.0.0.1", "-validity", "2", "-storetype", "PKCS12",
                "-keystore", p12.toString(), "-storepass", "testpass12").redirectErrorStream(true).start();
        assertTrue(process.waitFor(10, TimeUnit.SECONDS));
        assertEquals(0, process.exitValue(), new String(process.getInputStream().readAllBytes()));
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(p12)) { keys.load(input, "testpass12".toCharArray()); }
        identity = keys;
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(keys, "testpass12".toCharArray());
        SSLContext tls = SSLContext.getInstance("TLSv1.3");
        tls.init(managers.getKeyManagers(), null, new SecureRandom());
        return tls;
    }

    private KeyStore identity;

    private SSLContext clientTls() throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("server", identity.getCertificate("server"));
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        SSLContext tls = SSLContext.getInstance("TLSv1.3");
        tls.init(null, managers.getTrustManagers(), new SecureRandom());
        return tls;
    }

    private static String type(String json) throws Exception {
        return JSONObjectUtils.getString(JSONObjectUtils.parse(json), "type");
    }

    private record ControlPeer(WebSocket socket, LinkedBlockingQueue<String> received) implements AutoCloseable {
        String next() throws Exception {
            String value = received.poll(5, TimeUnit.SECONDS);
            if (value == null) throw new AssertionError("control WSS message was not delivered");
            return value;
        }
        String nextType() throws Exception { return type(next()); }
        @Override public void close() { socket.sendClose(WebSocket.NORMAL_CLOSURE, ""); }
    }
}
