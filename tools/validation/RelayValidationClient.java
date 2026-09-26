package com.jlshell.link.validation;

import com.jlshell.link.agent.RelayProofClient;
import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.TlsPeerContext;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.ConnectClientMultiplexer;
import com.jlshell.link.transport.TlsHandshakeGate;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.netty.channel.nio.NioEventLoopGroup;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/** Manual, isolated A-side acceptance harness; never packages account credentials. */
public final class RelayValidationClient {
    private static final URI WEBSITE = URI.create("https://ooml.net:13577");
    private static final URI RELAY = URI.create("wss://ooml.net:13575/link/v2/relay");
    private static final List<TargetEndpoint> TARGETS = List.of(
            new TargetEndpoint("192.168.31.1", 80),
            new TargetEndpoint("192.168.31.151", 22),
            new TargetEndpoint("192.168.31.202", 22));
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final NodeProofService proofs = new NodeProofService();
    private final Path directory;
    private final String jwt;
    private final UUID deviceId;
    private final UUID agentId;
    private final Ed25519NodeKey key;
    private final KeyManagerFactory keyManagers;
    private final KeyStore agentTrust;
    private final NodeKeyFingerprint agentFingerprint;

    private RelayValidationClient(Path directory) throws Exception {
        this.directory = directory;
        jwt = read("client-jwt");
        deviceId = UUID.fromString(read("device-id"));
        agentId = UUID.fromString(read("agent-id"));
        char[] password = read("tls.password").toCharArray();
        KeyStore local = KeyStore.getInstance("PKCS12");
        try (InputStream source = Files.newInputStream(directory.resolve("client.p12"))) {
            local.load(source, password);
        }
        X509Certificate certificate = (X509Certificate) local.getCertificate("validation-client");
        key = new Ed25519NodeKey(new KeyPair(certificate.getPublicKey(),
                (java.security.PrivateKey) local.getKey("validation-client", password)));
        keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(local, password);
        java.util.Arrays.fill(password, '\0');
        agentTrust = KeyStore.getInstance("PKCS12");
        agentTrust.load(null, null);
        X509Certificate agentCertificate;
        try (InputStream source = Files.newInputStream(directory.resolve("agent.crt"))) {
            agentCertificate = (X509Certificate) java.security.cert.CertificateFactory
                    .getInstance("X.509").generateCertificate(source);
        }
        agentTrust.setCertificateEntry("validation-agent", agentCertificate);
        agentFingerprint = NodeKeyFingerprint.from(agentCertificate.getPublicKey());
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 1) throw new IllegalArgumentException("one validation directory is required");
        new RelayValidationClient(Path.of(arguments[0])).run();
    }

    private void run() throws Exception {
        bindIdentity();
        String controlCredential = text(post("/api/v2/link/control-credentials",
                Map.of("deviceId", deviceId.toString(), "clientKeyFingerprint", key.fingerprint().value()),
                Map.of("Authorization", "Bearer " + jwt), 201), "credential");
        TransportBudget budget = new TransportBudget(65_536, 8_192, 64, 1_048_576,
                131_072, 4_194_304, 16, Duration.ofSeconds(30));
        NioEventLoopGroup eventLoops = new NioEventLoopGroup(2);
        try (RelayProofClient proof = new RelayProofClient(Duration.ofSeconds(10),
                Duration.ofSeconds(15), proofs, java.util.concurrent.ForkJoinPool.commonPool());
             ClientControl control = new ClientControl(controlCredential)) {
            control.connect();
            IssuedAccess previous = exercise(TARGETS.getFirst(), controlCredential,
                    budget, eventLoops, proof, control, null);
            exercise(TARGETS.getFirst(), controlCredential, budget, eventLoops, proof, control, previous);
            exerciseRevocation(TARGETS.get(2), controlCredential, budget, eventLoops, proof, control);
            exerciseParallelRevocation(controlCredential, budget, eventLoops, proof, control);
            for (TargetEndpoint target : TARGETS.subList(1, TARGETS.size())) {
                exercise(target, controlCredential, budget, eventLoops, proof, control, null);
            }
        } finally {
            eventLoops.shutdownGracefully(0, 5, TimeUnit.SECONDS).syncUninterruptibly();
        }
    }

    private void bindIdentity() throws Exception {
        String publicKey = Base64.getEncoder().encodeToString(key.publicKey().getEncoded());
        Map<String, Object> identity = Map.of("algorithm", "Ed25519", "publicKey", publicKey,
                "nodeKeyFingerprint", key.fingerprint().value());
        Map<String, Object> challenge = post("/api/v2/link/node-challenges",
                Map.of("purpose", "device-binding", "nodeId", deviceId.toString(), "identity", identity),
                Map.of("Authorization", "Bearer " + jwt), 201);
        byte[] nonce = Base64.getUrlDecoder().decode(text(challenge, "challenge"));
        byte[] signature = proofs.sign(key,
                new NodeProofContext("device-binding", deviceId, Optional.empty()), nonce);
        put("/api/v2/link/devices/" + deviceId + "/identity",
                Map.of("identity", identity, "protocolVersion", "link-v2", "proof", Map.of(
                        "challengeId", text(challenge, "challengeId"),
                        "signature", Base64.getUrlEncoder().withoutPadding().encodeToString(signature))),
                Map.of("Authorization", "Bearer " + jwt), 200);
        System.out.println("A device identity bound to isolated Website");
    }

    private IssuedAccess exercise(TargetEndpoint target, String credential, TransportBudget budget,
                          NioEventLoopGroup loops, RelayProofClient proof, ClientControl control,
                          IssuedAccess previous) throws Exception {
        Map<String, Object> access = post("/api/v2/link/access-requests",
                Map.of("agentId", agentId.toString(), "targetIp", target.address(),
                        "targetPort", target.port(), "connectPolicy", "RELAY_ONLY"),
                Map.of("X-Link-Control-Credential", credential), 201);
        LinkSessionId session = LinkSessionId.parse(text(access, "sessionId"));
        TunnelId tunnel = TunnelId.parse(text(access, "tunnelId"));
        String ticket = text(access, "accessTicket");
        if (previous != null && (previous.sessionId().equals(session)
                || previous.tunnelId().equals(tunnel) || previous.ticket().equals(ticket))) {
            throw new IllegalStateException("reconnect reused a prior Website authorization artifact");
        }
        control.awaitInvite(session.value());
        post("/api/v2/link/sessions/" + session + "/relay-activation", Map.of(),
                Map.of("X-Link-Control-Credential", credential), 200);
        // Pair first; C's next bounded HTTPS poll opens the other outbound carrier.
        SSLContext inner = TlsPeerContext.create(keyManagers.getKeyManagers(), agentTrust,
                HexFormat.of().parseHex(agentFingerprint.value()));
        long started = System.nanoTime();
        io.netty.channel.Channel carrier = null;
        try {
            carrier = proof.connectClient(loops, RELAY, credential, deviceId,
                    agentId, session, tunnel, key, agentFingerprint, SSLContext.getDefault(), inner,
                    "jlshell-agent-" + agentFingerprint.value(), 443, budget,
                    new TlsHandshakeGate(budget.maxConcurrentHandshakes()))
                    .toCompletableFuture().get(40, TimeUnit.SECONDS);
            ConnectClientMultiplexer multiplex = new ConnectClientMultiplexer(carrier, budget,
                    new TransportBufferBudget(budget.maxBufferedBytesTotal()));
            try (ConnectClientMultiplexer.ConnectTunnel stream = multiplex.open(target, tunnel, ticket)
                    .toCompletableFuture().get(15, TimeUnit.SECONDS)) {
                long returnedBytes = 0;
                String prefix;
                if (target.port() == 80) {
                    stream.write(ByteBuffer.wrap(("GET / HTTP/1.0\r\nHost: " + target.address()
                            + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII)))
                            .toCompletableFuture().get(10, TimeUnit.SECONDS);
                    stream.shutdownOutput().toCompletableFuture().get(10, TimeUnit.SECONDS);
                    ByteBuffer first = stream.read(128).toCompletableFuture().get(10, TimeUnit.SECONDS);
                    byte[] firstBytes = new byte[first.remaining()];
                    first.get(firstBytes);
                    prefix = new String(firstBytes, StandardCharsets.US_ASCII);
                    returnedBytes += firstBytes.length;
                }
                else {
                    ByteBuffer banner = stream.read(128).toCompletableFuture().get(10, TimeUnit.SECONDS);
                    byte[] bannerBytes = new byte[banner.remaining()];
                    banner.get(bannerBytes);
                    prefix = new String(bannerBytes, StandardCharsets.US_ASCII);
                    returnedBytes += bannerBytes.length;
                    stream.write(ByteBuffer.wrap("SSH-2.0-JLShellValidation_1.0\r\n"
                            .getBytes(StandardCharsets.US_ASCII))).toCompletableFuture()
                            .get(10, TimeUnit.SECONDS);
                    stream.shutdownOutput().toCompletableFuture().get(10, TimeUnit.SECONDS);
                }
                if (!(target.port() == 80 ? prefix.startsWith("HTTP/") : prefix.startsWith("SSH-"))) {
                    throw new IllegalStateException("target did not return expected protocol banner");
                }
                boolean inputEnded = false;
                while (!inputEnded) {
                    ByteBuffer response = stream.read(4096).toCompletableFuture().get(10, TimeUnit.SECONDS);
                    if (!response.hasRemaining()) {
                        inputEnded = true;
                        continue;
                    }
                    returnedBytes = Math.addExact(returnedBytes, response.remaining());
                    if (returnedBytes > 1_048_576) {
                        throw new IllegalStateException("target response exceeded the validation bound");
                    }
                }
                System.out.println("target=" + target + " path=A-B-C bytes=" + returnedBytes
                        + " connect_ms=" + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                        + " half_close=bidirectional signal_invite=received"
                        + (previous == null ? "" : " reconnect=reauthorized"));
            }
        } finally {
            if (carrier != null) carrier.close().syncUninterruptibly();
            post("/api/v2/link/sessions/" + session + "/close", Map.of(),
                    Map.of("X-Link-Control-Credential", credential), 204);
        }
        return new IssuedAccess(session, tunnel, ticket);
    }

    private record IssuedAccess(LinkSessionId sessionId, TunnelId tunnelId, String ticket) { }

    private ActiveValidationTunnel openValidationTunnel(TargetEndpoint target, String credential,
                                                        TransportBudget budget, NioEventLoopGroup loops,
                                                        RelayProofClient proof, ClientControl control)
            throws Exception {
        Map<String, Object> access = post("/api/v2/link/access-requests",
                Map.of("agentId", agentId.toString(), "targetIp", target.address(),
                        "targetPort", target.port(), "connectPolicy", "RELAY_ONLY"),
                Map.of("X-Link-Control-Credential", credential), 201);
        LinkSessionId session = LinkSessionId.parse(text(access, "sessionId"));
        TunnelId tunnel = TunnelId.parse(text(access, "tunnelId"));
        String ticket = text(access, "accessTicket");
        io.netty.channel.Channel carrier = null;
        ConnectClientMultiplexer.ConnectTunnel stream = null;
        try {
            control.awaitInvite(session.value());
            post("/api/v2/link/sessions/" + session + "/relay-activation", Map.of(),
                    Map.of("X-Link-Control-Credential", credential), 200);
            SSLContext inner = TlsPeerContext.create(keyManagers.getKeyManagers(), agentTrust,
                    HexFormat.of().parseHex(agentFingerprint.value()));
            carrier = proof.connectClient(loops, RELAY, credential, deviceId,
                    agentId, session, tunnel, key, agentFingerprint, SSLContext.getDefault(), inner,
                    "jlshell-agent-" + agentFingerprint.value(), 443, budget,
                    new TlsHandshakeGate(budget.maxConcurrentHandshakes()))
                    .toCompletableFuture().get(40, TimeUnit.SECONDS);
            ConnectClientMultiplexer multiplex = new ConnectClientMultiplexer(carrier, budget,
                    new TransportBufferBudget(budget.maxBufferedBytesTotal()));
            stream = multiplex.open(target, tunnel, ticket).toCompletableFuture()
                    .get(15, TimeUnit.SECONDS);
            ByteBuffer banner = stream.read(128).toCompletableFuture().get(10, TimeUnit.SECONDS);
            byte[] bannerBytes = new byte[banner.remaining()];
            banner.get(bannerBytes);
            if (!new String(bannerBytes, StandardCharsets.US_ASCII).startsWith("SSH-")) {
                throw new IllegalStateException("parallel-revocation target did not return an SSH banner");
            }
            return new ActiveValidationTunnel(session, carrier, stream);
        } catch (Exception failure) {
            if (stream != null) stream.close();
            if (carrier != null) carrier.close().syncUninterruptibly();
            post("/api/v2/link/sessions/" + session + "/close", Map.of(),
                    Map.of("X-Link-Control-Credential", credential), 204);
            throw failure;
        }
    }

    private void exerciseParallelRevocation(String credential, TransportBudget budget,
                                            NioEventLoopGroup loops, RelayProofClient proof,
                                            ClientControl control) throws Exception {
        ActiveValidationTunnel revoked = openValidationTunnel(TARGETS.get(2), credential,
                budget, loops, proof, control);
        ActiveValidationTunnel survivor = null;
        try {
            survivor = openValidationTunnel(TARGETS.get(1), credential,
                    budget, loops, proof, control);
            long revokedAt = System.nanoTime();
            post("/api/v2/link/sessions/" + revoked.session() + "/close", Map.of(),
                    Map.of("X-Link-Control-Credential", credential), 204);
            control.awaitRevocation(revoked.session().value());
            revoked.stream().closed().toCompletableFuture().get(5, TimeUnit.SECONDS);
            Thread.sleep(300);
            if (survivor.stream().closed().toCompletableFuture().isDone()) {
                throw new IllegalStateException("revoking one Website session also closed its sibling session");
            }
            survivor.stream().write(ByteBuffer.wrap("SSH-2.0-JLShellParallelValidation_1.0\r\n"
                    .getBytes(StandardCharsets.US_ASCII))).toCompletableFuture().get(10, TimeUnit.SECONDS);
            survivor.stream().shutdownOutput().toCompletableFuture().get(10, TimeUnit.SECONDS);
            long bytes = 0;
            boolean ended = false;
            while (!ended) {
                ByteBuffer response = survivor.stream().read(4096).toCompletableFuture()
                        .get(10, TimeUnit.SECONDS);
                if (!response.hasRemaining()) {
                    ended = true;
                } else {
                    bytes = Math.addExact(bytes, response.remaining());
                    if (bytes > 1_048_576) throw new IllegalStateException("parallel target response exceeded bound");
                }
            }
            System.out.println("parallel_sessions=2 revoke=targeted survivor=active-then-completed"
                    + " survivor_bytes=" + bytes
                    + " revoked_stream_closed_ms="
                    + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - revokedAt));
        } finally {
            if (survivor != null) {
                try {
                    post("/api/v2/link/sessions/" + survivor.session() + "/close", Map.of(),
                            Map.of("X-Link-Control-Credential", credential), 204);
                } finally {
                    survivor.close();
                }
            }
            revoked.close();
        }
    }

    private record ActiveValidationTunnel(LinkSessionId session,
                                          io.netty.channel.Channel carrier,
                                          ConnectClientMultiplexer.ConnectTunnel stream)
            implements AutoCloseable {
        @Override public void close() {
            stream.close();
            carrier.close().syncUninterruptibly();
        }
    }

    private void exerciseRevocation(TargetEndpoint target, String credential, TransportBudget budget,
                                    NioEventLoopGroup loops, RelayProofClient proof,
                                    ClientControl control) throws Exception {
        Map<String, Object> access = post("/api/v2/link/access-requests",
                Map.of("agentId", agentId.toString(), "targetIp", target.address(),
                        "targetPort", target.port(), "connectPolicy", "RELAY_ONLY"),
                Map.of("X-Link-Control-Credential", credential), 201);
        LinkSessionId session = LinkSessionId.parse(text(access, "sessionId"));
        TunnelId tunnel = TunnelId.parse(text(access, "tunnelId"));
        String ticket = text(access, "accessTicket");
        control.awaitInvite(session.value());
        post("/api/v2/link/sessions/" + session + "/relay-activation", Map.of(),
                Map.of("X-Link-Control-Credential", credential), 200);
        SSLContext inner = TlsPeerContext.create(keyManagers.getKeyManagers(), agentTrust,
                HexFormat.of().parseHex(agentFingerprint.value()));
        io.netty.channel.Channel carrier = null;
        try {
            carrier = proof.connectClient(loops, RELAY, credential, deviceId,
                    agentId, session, tunnel, key, agentFingerprint, SSLContext.getDefault(), inner,
                    "jlshell-agent-" + agentFingerprint.value(), 443, budget,
                    new TlsHandshakeGate(budget.maxConcurrentHandshakes()))
                    .toCompletableFuture().get(40, TimeUnit.SECONDS);
            ConnectClientMultiplexer multiplex = new ConnectClientMultiplexer(carrier, budget,
                    new TransportBufferBudget(budget.maxBufferedBytesTotal()));
            try (ConnectClientMultiplexer.ConnectTunnel stream = multiplex.open(target, tunnel, ticket)
                    .toCompletableFuture().get(15, TimeUnit.SECONDS)) {
                ByteBuffer banner = stream.read(128).toCompletableFuture().get(10, TimeUnit.SECONDS);
                byte[] bannerBytes = new byte[banner.remaining()];
                banner.get(bannerBytes);
                if (!new String(bannerBytes, StandardCharsets.US_ASCII).startsWith("SSH-")) {
                    throw new IllegalStateException("revocation target did not return an SSH banner");
                }
                long revokedAt = System.nanoTime();
                post("/api/v2/link/sessions/" + session + "/close", Map.of(),
                        Map.of("X-Link-Control-Credential", credential), 204);
                control.awaitRevocation(session.value());
                stream.closed().toCompletableFuture().get(5, TimeUnit.SECONDS);
                System.out.println("session=" + session + " revoke=website-to-agent-to-relay"
                        + " closed_ms=" + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - revokedAt));
            }
        } finally {
            if (carrier != null) carrier.close().syncUninterruptibly();
        }
    }

    private Map<String, Object> post(String path, Map<String, ?> body, Map<String, String> headers, int status)
            throws Exception { return request("POST", path, body, headers, status); }

    private Map<String, Object> put(String path, Map<String, ?> body, Map<String, String> headers, int status)
            throws Exception { return request("PUT", path, body, headers, status); }

    private Map<String, Object> request(String method, String path, Map<String, ?> body,
                                        Map<String, String> headers, int status) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(WEBSITE.resolve(path))
                .timeout(Duration.ofSeconds(15)).header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(JSONObjectUtils.toJSONString(body)));
        headers.forEach(builder::header);
        HttpResponse<InputStream> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream stream = response.body()) {
            byte[] bytes = stream.readNBytes(65_537);
            if (response.statusCode() != status || bytes.length > 65_536) {
                throw new IllegalStateException("Isolated Website returned HTTP " + response.statusCode()
                        + " for " + path);
            }
            return status == 204 ? Map.of() : JSONObjectUtils.parse(new String(bytes, StandardCharsets.UTF_8));
        }
    }

    private String read(String name) throws Exception { return Files.readString(directory.resolve(name)).trim(); }
    private static String text(Map<String, Object> value, String key) throws Exception {
        return JSONObjectUtils.getString(value, key);
    }

    private final class ClientControl implements AutoCloseable, WebSocket.Listener {
        private final String credential;
        private final CompletableFuture<Void> ready = new CompletableFuture<>();
        private final ConcurrentHashMap<UUID, CompletableFuture<Void>> invites = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<UUID, CompletableFuture<Void>> revocations = new ConcurrentHashMap<>();
        private final StringBuilder incoming = new StringBuilder();
        private WebSocket socket;

        private ClientControl(String credential) { this.credential = credential; }

        private void connect() throws Exception {
            URI challengeUri = URI.create("https://ooml.net:13575/link/v2/control-challenges");
            HttpRequest request = HttpRequest.newBuilder(challengeUri).timeout(Duration.ofSeconds(15))
                    .header("Authorization", "Bearer " + credential)
                    .header("X-Link-Role", "client")
                    .header("X-Link-Node-Id", deviceId.toString())
                    .header("X-Link-Key-Fingerprint", key.fingerprint().value())
                    .POST(HttpRequest.BodyPublishers.noBody()).build();
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            Map<String, Object> challenge;
            try (InputStream stream = response.body()) {
                byte[] bytes = stream.readNBytes(4097);
                if (response.statusCode() != 201 || bytes.length > 4096) {
                    throw new IllegalStateException("client control challenge failed (HTTP "
                            + response.statusCode() + ")");
                }
                challenge = JSONObjectUtils.parse(new String(bytes, StandardCharsets.UTF_8));
            }
            byte[] nonce = Base64.getUrlDecoder().decode(text(challenge, "challenge"));
            byte[] signature = proofs.sign(key,
                    new NodeProofContext("control-channel", deviceId, Optional.empty()), nonce);
            socket = http.newWebSocketBuilder().connectTimeout(Duration.ofSeconds(15))
                    .header("Authorization", "Bearer " + credential)
                    .header("X-Link-Role", "client")
                    .header("X-Link-Node-Id", deviceId.toString())
                    .header("X-Link-Key-Fingerprint", key.fingerprint().value())
                    .header("X-Link-Challenge-Id", text(challenge, "challengeId"))
                    .header("X-Link-Proof", Base64.getUrlEncoder().withoutPadding().encodeToString(signature))
                    .buildAsync(URI.create("wss://ooml.net:13575/link/v2/control"), this)
                    .get(15, TimeUnit.SECONDS);
            ready.get(15, TimeUnit.SECONDS);
        }

        private void awaitInvite(UUID sessionId) throws Exception {
            invites.computeIfAbsent(sessionId, ignored -> new CompletableFuture<>())
                    .get(10, TimeUnit.SECONDS);
        }

        private void awaitRevocation(UUID sessionId) throws Exception {
            revocations.computeIfAbsent(sessionId, ignored -> new CompletableFuture<>())
                    .get(5, TimeUnit.SECONDS);
        }

        @Override public void onOpen(WebSocket webSocket) {
            webSocket.request(1);
            webSocket.sendText(JSONObjectUtils.toJSONString(Map.of(
                    "type", "HELLO", "role", "client", "nodeId", deviceId.toString(),
                    "keyFingerprint", key.fingerprint().value(),
                    "minProtocol", "link-v2", "maxProtocol", "link-v2",
                    "capabilities", List.of("tcp-connect"),
                    "sentAt", java.time.Instant.now().toString())), true);
        }

        @Override public java.util.concurrent.CompletionStage<?> onText(
                WebSocket webSocket, CharSequence data, boolean last) {
            try {
                if (incoming.length() + data.length() > 65_536) {
                    throw new IllegalArgumentException("control signal too large");
                }
                incoming.append(data);
                if (last) {
                    Map<String, Object> message = JSONObjectUtils.parse(incoming.toString());
                    incoming.setLength(0);
                    String type = text(message, "type");
                    if ("READY".equals(type)) ready.complete(null);
                    if ("SESSION_INVITE".equals(type)) {
                        UUID sessionId = UUID.fromString(text(message, "sessionId"));
                        invites.computeIfAbsent(sessionId, ignored -> new CompletableFuture<>()).complete(null);
                    }
                    if ("SESSION_REVOKED".equals(type)) {
                        UUID sessionId = UUID.fromString(text(message, "sessionId"));
                        revocations.computeIfAbsent(sessionId, ignored -> new CompletableFuture<>()).complete(null);
                    }
                }
                webSocket.request(1);
            } catch (Exception error) {
                ready.completeExceptionally(error);
                webSocket.abort();
            }
            return CompletableFuture.completedFuture(null);
        }

        @Override public java.util.concurrent.CompletionStage<?> onClose(
                WebSocket webSocket, int statusCode, String reason) {
            ready.completeExceptionally(new IllegalStateException("control WSS closed"));
            return CompletableFuture.completedFuture(null);
        }

        @Override public void onError(WebSocket webSocket, Throwable error) {
            ready.completeExceptionally(error);
        }

        @Override public void close() {
            if (socket != null) socket.sendClose(WebSocket.NORMAL_CLOSURE, "");
        }
    }
}
