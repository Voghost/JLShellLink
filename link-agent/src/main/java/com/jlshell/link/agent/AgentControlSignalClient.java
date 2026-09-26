package com.jlshell.link.agent;

import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
import com.jlshell.link.core.signal.ControlSignal;
import com.jlshell.link.core.signal.ControlSignalJsonCodec;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;

/** C's proof-bound, node-level WSS signaling connection to the embedded Website Link Server. */
public final class AgentControlSignalClient implements AutoCloseable {
    private static final int MAX_MESSAGE_CHARS = 65_536;
    private final URI controlUri;
    private final URI challengeUri;
    private final UUID agentId;
    private final LocalNodeKey nodeKey;
    private final String credential;
    private final HttpClient http;
    private final NodeProofService proofs = new NodeProofService();
    private final ControlSignalJsonCodec codec = new ControlSignalJsonCodec();
    private final Consumer<ControlSignal.SessionInvite> invitations;
    private final Consumer<ControlSignal> signals;
    private final Consumer<AgentControlSignalClient> disconnected;
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean disconnectNotified = new AtomicBoolean();
    private final CompletableFuture<Void> ready = new CompletableFuture<>();
    private volatile WebSocket socket;

    public AgentControlSignalClient(URI controlUri, UUID agentId, LocalNodeKey nodeKey,
            String credential, SSLContext tls, Consumer<ControlSignal.SessionInvite> invitations,
            Consumer<ControlSignal> signals, Consumer<AgentControlSignalClient> disconnected) {
        this.controlUri = requireControlUri(controlUri);
        this.challengeUri = challengeUri(controlUri);
        this.agentId = Objects.requireNonNull(agentId, "agentId");
        this.nodeKey = Objects.requireNonNull(nodeKey, "nodeKey");
        if (credential == null || credential.isBlank() || credential.length() > 4096
                || credential.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("Agent credential is invalid");
        }
        this.credential = credential;
        this.http = HttpClient.newBuilder().sslContext(Objects.requireNonNull(tls, "tls"))
                .connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1).build();
        this.invitations = Objects.requireNonNull(invitations, "invitations");
        this.signals = Objects.requireNonNull(signals, "signals");
        this.disconnected = disconnected == null ? ignored -> { } : disconnected;
    }

    public CompletionStage<Void> connect() {
        if (closed.get()) return CompletableFuture.failedFuture(new IllegalStateException("control client is closed"));
        if (!started.compareAndSet(false, true)) return ready;
        HttpRequest request = HttpRequest.newBuilder(challengeUri).timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + credential)
                .header("X-Link-Role", "agent")
                .header("X-Link-Node-Id", agentId.toString())
                .header("X-Link-Key-Fingerprint", nodeKey.fingerprint().value())
                .POST(HttpRequest.BodyPublishers.noBody()).build();
        http.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream())
                .thenCompose(response -> {
                    try (var bodyStream = response.body()) {
                        byte[] raw = bodyStream.readNBytes(4097);
                        if (response.statusCode() != 201 || raw.length > 4096) {
                            throw new IllegalStateException("control challenge was rejected");
                        }
                        Map<String, Object> body = JSONObjectUtils.parse(
                                new String(raw, java.nio.charset.StandardCharsets.UTF_8));
                        UUID challengeId = UUID.fromString(JSONObjectUtils.getString(body, "challengeId"));
                        byte[] nonce = Base64.getUrlDecoder().decode(JSONObjectUtils.getString(body, "challenge"));
                        Instant expiresAt = Instant.parse(JSONObjectUtils.getString(body, "expiresAt"));
                        if (nonce.length < 32 || !expiresAt.isAfter(Instant.now())) {
                            throw new IllegalStateException("control challenge is invalid or expired");
                        }
                        byte[] signature = proofs.sign(nodeKey,
                                new NodeProofContext("control-channel", agentId, Optional.empty()), nonce);
                        String proof = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
                        return http.newWebSocketBuilder().connectTimeout(Duration.ofSeconds(15))
                                .header("Authorization", "Bearer " + credential)
                                .header("X-Link-Role", "agent")
                                .header("X-Link-Node-Id", agentId.toString())
                                .header("X-Link-Key-Fingerprint", nodeKey.fingerprint().value())
                                .header("X-Link-Challenge-Id", challengeId.toString())
                                .header("X-Link-Proof", proof)
                                .buildAsync(controlUri, new Listener());
                    } catch (Exception invalid) {
                        return CompletableFuture.failedFuture(
                                new IllegalStateException("control identity proof failed", invalid));
                    }
                }).whenComplete((connected, error) -> {
                    if (error != null) fail();
                    else if (closed.get()) connected.sendClose(WebSocket.NORMAL_CLOSURE, "");
                    else socket = connected;
                });
        return ready;
    }

    public CompletionStage<WebSocket> send(ControlSignal signal) {
        Objects.requireNonNull(signal, "signal");
        if (signal instanceof ControlSignal.SessionInvite || signal instanceof ControlSignal.SessionRevoked) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("session state is server-only"));
        }
        return ready.thenCompose(ignored -> {
            WebSocket current = socket;
            if (closed.get() || current == null) {
                return CompletableFuture.failedFuture(new IllegalStateException("control WebSocket is unavailable"));
            }
            return current.sendText(codec.encode(signal), true);
        });
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) return;
        WebSocket current = socket;
        if (current != null) current.sendClose(WebSocket.NORMAL_CLOSURE, "");
        ready.completeExceptionally(new IllegalStateException("control client is closed"));
        http.shutdown();
    }

    private void fail() {
        ready.completeExceptionally(new IllegalStateException("control connection failed"));
        if (!closed.get()) close();
        if (disconnectNotified.compareAndSet(false, true)) {
            try { disconnected.accept(this); } catch (RuntimeException ignored) { }
        }
    }

    private String hello() {
        return JSONObjectUtils.toJSONString(Map.of(
                "type", "HELLO", "role", "agent", "nodeId", agentId.toString(),
                "keyFingerprint", nodeKey.fingerprint().value(),
                "minProtocol", "link-v2", "maxProtocol", "link-v2",
                "capabilities", List.of("tcp-connect"), "sentAt", Instant.now().toString()));
    }

    private final class Listener implements WebSocket.Listener {
        private final StringBuilder pending = new StringBuilder();

        @Override
        public void onOpen(WebSocket webSocket) {
            socket = webSocket;
            webSocket.request(1);
            webSocket.sendText(hello(), true).whenComplete((ignored, error) -> {
                if (error != null) {
                    webSocket.abort();
                    fail();
                }
            });
        }

        @Override
        public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
            try {
                if (pending.length() + data.length() > MAX_MESSAGE_CHARS) {
                    throw new IllegalArgumentException("control message is too large");
                }
                pending.append(data);
                if (last) {
                    String json = pending.toString();
                    pending.setLength(0);
                    receive(json);
                }
                webSocket.request(1);
            } catch (RuntimeException invalid) {
                webSocket.abort();
                fail();
            }
            return CompletableFuture.completedFuture(null);
        }

        private void receive(String json) {
            try {
                if (closed.get()) throw new IllegalStateException("control client is closed");
                Map<String, Object> value = JSONObjectUtils.parse(json);
                String type = JSONObjectUtils.getString(value, "type");
                if ("READY".equals(type)) {
                    if (ready.isDone() || !"link-v2".equals(JSONObjectUtils.getString(value, "protocol"))
                            || !agentId.equals(UUID.fromString(JSONObjectUtils.getString(value, "nodeId")))) {
                        throw new IllegalArgumentException("control READY identity is invalid");
                    }
                    ready.complete(null);
                    return;
                }
                if (!ready.isDone()) throw new IllegalArgumentException("control READY is required first");
                if ("ERROR".equals(type)) throw new IllegalArgumentException("control server rejected a message");
                ControlSignal signal = codec.decodeServerSignal(json);
                if (signal instanceof ControlSignal.SessionInvite invite) {
                    if (!agentId.equals(invite.agentId())
                            || !nodeKey.fingerprint().equals(invite.agentKeyFingerprint())
                            || !invite.expiresAt().isAfter(Instant.now())) {
                        throw new IllegalArgumentException("control invitation is not for this Agent");
                    }
                    invitations.accept(invite);
                } else {
                    signals.accept(signal);
                }
            } catch (Exception invalid) {
                throw new IllegalArgumentException("control message was rejected", invalid);
            }
        }

        @Override
        public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
            webSocket.abort();
            fail();
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            fail();
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public void onError(WebSocket webSocket, Throwable error) {
            fail();
        }
    }

    private static URI requireControlUri(URI uri) {
        Objects.requireNonNull(uri, "controlUri");
        if (!"wss".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !"/link/v2/control".equals(uri.getPath())) {
            throw new IllegalArgumentException("control URI must be an origin-bound WSS Link control path");
        }
        return uri;
    }

    private static URI challengeUri(URI controlUri) {
        try {
            return new URI("https", null, controlUri.getHost(), controlUri.getPort(),
                    "/link/v2/control-challenges", null, null);
        } catch (URISyntaxException invalid) {
            throw new IllegalArgumentException("control URI is invalid", invalid);
        }
    }
}
