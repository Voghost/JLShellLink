package com.jlshell.link.client;

import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
import com.jlshell.link.core.signal.ControlSignal;
import com.jlshell.link.core.signal.ControlSignalJsonCodec;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.InputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;

/** A's device-proof-bound WSS signaling connection to the Website Link Server. */
public final class ClientControlSignalClient implements AutoCloseable {
    private static final int MAX_MESSAGE_CHARS = 65_536;
    private final URI controlUri;
    private final URI challengeUri;
    private final UUID deviceId;
    private final LocalNodeKey nodeKey;
    private final Supplier<? extends CompletionStage<String>> credential;
    private final HttpClient http;
    private final NodeProofService proofs = new NodeProofService();
    private final ControlSignalJsonCodec codec = new ControlSignalJsonCodec();
    private final ClientIceSignalBroker signals;
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean reconnectScheduled = new AtomicBoolean();
    private final AtomicInteger reconnectAttempts = new AtomicInteger();
    private final AtomicReference<CompletableFuture<Void>> failedGeneration = new AtomicReference<>();
    private final ScheduledExecutorService reconnectTimer = Executors.newSingleThreadScheduledExecutor(
            task -> Thread.ofPlatform().name("jlshell-link-control-reconnect").daemon().unstarted(task));
    private final Consumer<Throwable> disconnected;
    private volatile CompletableFuture<Void> ready = new CompletableFuture<>();
    private volatile WebSocket socket;

    public ClientControlSignalClient(URI controlUri, UUID deviceId, LocalNodeKey nodeKey,
            Supplier<? extends CompletionStage<String>> credential, SSLContext tls,
            ClientIceSignalBroker signals, Consumer<Throwable> disconnected) {
        this.controlUri = requireControlUri(controlUri);
        this.challengeUri = challengeUri(controlUri);
        this.deviceId = Objects.requireNonNull(deviceId, "deviceId");
        this.nodeKey = Objects.requireNonNull(nodeKey, "nodeKey");
        this.credential = Objects.requireNonNull(credential, "credential");
        this.http = HttpClient.newBuilder().sslContext(Objects.requireNonNull(tls, "tls"))
                .connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1).build();
        this.signals = Objects.requireNonNull(signals, "signals");
        this.disconnected = disconnected == null ? ignored -> { } : disconnected;
        signals.attachSender(this::send);
    }

    public synchronized CompletionStage<Void> connect() {
        if (closed.get()) return CompletableFuture.failedFuture(new IllegalStateException("control client is closed"));
        if (!started.compareAndSet(false, true)) return ready;
        CompletableFuture<Void> currentReady = new CompletableFuture<>();
        ready = currentReady;
        failedGeneration.set(null);
        CompletionStage<String> token;
        try { token = Objects.requireNonNull(credential.get(), "control credential provider returned null"); }
        catch (RuntimeException error) { fail(currentReady, error); return currentReady; }
        token.thenCompose(value -> requestChallenge(value).thenCompose(challenge -> openWebSocket(value, challenge)))
                .whenComplete((connected, error) -> {
                    if (error != null) fail(currentReady, unwrap(error));
                    else if (closed.get()) connected.sendClose(WebSocket.NORMAL_CLOSURE, "");
                    else if (socket == null) socket = connected;
                });
        return currentReady;
    }

    public CompletionStage<Void> send(ControlSignal signal) {
        Objects.requireNonNull(signal, "signal");
        if (signal instanceof ControlSignal.SessionInvite || signal instanceof ControlSignal.SessionRevoked) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("session state is Website-owned"));
        }
        CompletableFuture<Void> currentReady = ready;
        return currentReady.thenCompose(ignored -> {
            WebSocket current = socket;
            if (closed.get() || current == null) {
                return CompletableFuture.failedFuture(new IllegalStateException("Client WSS is unavailable"));
            }
            return current.sendText(codec.encode(signal), true).thenApply(done -> null);
        });
    }

    /** Low-cardinality connection state suitable for a local diagnostics view. */
    public String state() {
        if (closed.get()) return "CLOSED";
        CompletableFuture<Void> current = ready;
        if (current.isDone() && !current.isCompletedExceptionally() && socket != null) return "CONNECTED";
        if (started.get()) return "CONNECTING";
        if (reconnectScheduled.get()) return "RECONNECTING";
        return "DISCONNECTED";
    }

    private CompletionStage<Challenge> requestChallenge(String token) {
        if (token == null || token.isBlank() || token.length() > 4096
                || token.chars().anyMatch(Character::isWhitespace)) {
            return CompletableFuture.failedFuture(new SecurityException("control credential is invalid"));
        }
        HttpRequest request = HttpRequest.newBuilder(challengeUri).timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + token)
                .header("X-Link-Role", "client")
                .header("X-Link-Node-Id", deviceId.toString())
                .header("X-Link-Key-Fingerprint", nodeKey.fingerprint().value())
                .POST(HttpRequest.BodyPublishers.noBody()).build();
        return http.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream()).thenApply(response -> {
            try (InputStream input = response.body()) {
                byte[] raw = input.readNBytes(4097);
                if (response.statusCode() != 201 || raw.length > 4096) {
                    throw new SecurityException("control challenge was rejected");
                }
                Map<String, Object> body = JSONObjectUtils.parse(new String(raw, StandardCharsets.UTF_8));
                UUID challengeId = UUID.fromString(JSONObjectUtils.getString(body, "challengeId"));
                byte[] nonce = Base64.getUrlDecoder().decode(JSONObjectUtils.getString(body, "challenge"));
                Instant expiresAt = Instant.parse(JSONObjectUtils.getString(body, "expiresAt"));
                if (nonce.length < 32 || !expiresAt.isAfter(Instant.now())) {
                    throw new SecurityException("control challenge is invalid or expired");
                }
                byte[] signature = proofs.sign(nodeKey,
                        new NodeProofContext("control-channel", deviceId, Optional.empty()), nonce);
                String proof = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
                java.util.Arrays.fill(nonce, (byte) 0);
                java.util.Arrays.fill(signature, (byte) 0);
                return new Challenge(challengeId, proof);
            } catch (Exception rejected) {
                throw new java.util.concurrent.CompletionException(
                        new SecurityException("control identity proof failed", rejected));
            }
        });
    }

    private CompletionStage<WebSocket> openWebSocket(String token, Challenge challenge) {
        return http.newWebSocketBuilder().connectTimeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + token)
                .header("X-Link-Role", "client")
                .header("X-Link-Node-Id", deviceId.toString())
                .header("X-Link-Key-Fingerprint", nodeKey.fingerprint().value())
                .header("X-Link-Challenge-Id", challenge.id().toString())
                .header("X-Link-Proof", challenge.proof())
                .buildAsync(controlUri, new Listener(ready));
    }

    private String hello() {
        return JSONObjectUtils.toJSONString(Map.of(
                "type", "HELLO", "role", "client", "nodeId", deviceId.toString(),
                "keyFingerprint", nodeKey.fingerprint().value(),
                "minProtocol", "link-v2", "maxProtocol", "link-v2",
                "capabilities", List.of("tcp-connect", ControlSignal.ICE_CREDENTIALS_CAPABILITY),
                "sentAt", Instant.now().toString()));
    }

    private final class Listener implements WebSocket.Listener {
        private final StringBuilder pending = new StringBuilder();
        private final CompletableFuture<Void> connectionReady;

        private Listener(CompletableFuture<Void> connectionReady) { this.connectionReady = connectionReady; }

        @Override public void onOpen(WebSocket webSocket) {
            socket = webSocket;
            webSocket.request(1);
            webSocket.sendText(hello(), true).whenComplete((ignored, error) -> {
                if (error != null) fail(connectionReady, unwrap(error));
            });
        }

        @Override public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
            try {
                if (closed.get() || connectionReady != ready
                        || pending.length() + data.length() > MAX_MESSAGE_CHARS) {
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
                fail(connectionReady, invalid);
            }
            return CompletableFuture.completedFuture(null);
        }

        private void receive(String json) {
            try {
                Map<String, Object> value = JSONObjectUtils.parse(json);
                String type = JSONObjectUtils.getString(value, "type");
                if ("READY".equals(type)) {
                    if (connectionReady.isDone() || !"link-v2".equals(JSONObjectUtils.getString(value, "protocol"))
                            || !deviceId.equals(UUID.fromString(JSONObjectUtils.getString(value, "nodeId")))) {
                        throw new SecurityException("control READY identity is invalid");
                    }
                    reconnectAttempts.set(0);
                    reconnectScheduled.set(false);
                    connectionReady.complete(null);
                    return;
                }
                if (!connectionReady.isDone()) throw new IllegalStateException("control READY is required first");
                if ("ERROR".equals(type)) throw new SecurityException("control server rejected a message");
                ControlSignal signal = codec.decodeServerSignal(json);
                if (signal instanceof ControlSignal.SessionInvite invite
                        && (!deviceId.equals(invite.clientDeviceId())
                        || !nodeKey.fingerprint().equals(invite.clientKeyFingerprint())
                        || !invite.expiresAt().isAfter(Instant.now()))) {
                    throw new SecurityException("control invitation does not match this Client identity");
                }
                signals.accept(signal);
            } catch (Exception invalid) {
                throw new IllegalArgumentException("control message was rejected", invalid);
            }
        }

        @Override public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
            webSocket.abort();
            fail(connectionReady, new IllegalArgumentException("binary control messages are not supported"));
            return CompletableFuture.completedFuture(null);
        }
        @Override public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
            fail(connectionReady, new IOException("control WebSocket closed"));
            return CompletableFuture.completedFuture(null);
        }
        @Override public void onError(WebSocket webSocket, Throwable error) { fail(connectionReady, error); }
    }

    private void fail(CompletableFuture<Void> connectionReady, Throwable error) {
        if (connectionReady != ready || closed.get()) return;
        if (!failedGeneration.compareAndSet(null, connectionReady)) return;
        started.set(false);
        socket = null;
        connectionReady.completeExceptionally(error);
        signals.connectionLost(error);
        try { disconnected.accept(error); } catch (RuntimeException ignored) { }
        if (reconnectScheduled.compareAndSet(false, true) && !closed.get()) {
            int attempt = Math.min(6, reconnectAttempts.incrementAndGet());
            long baseSeconds = Math.min(30, 1L << (attempt - 1));
            long jitterSeconds = java.util.concurrent.ThreadLocalRandom.current().nextLong(0, 3);
            reconnectTimer.schedule(() -> {
                reconnectScheduled.set(false);
                connect();
            }, baseSeconds + jitterSeconds, TimeUnit.SECONDS);
        }
    }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        WebSocket current = socket;
        if (current != null) current.sendClose(WebSocket.NORMAL_CLOSURE, "");
        ready.completeExceptionally(new IllegalStateException("control client is closed"));
        signals.close();
        http.shutdown();
        reconnectTimer.shutdownNow();
    }

    private static URI requireControlUri(URI uri) {
        Objects.requireNonNull(uri, "controlUri");
        if (!"wss".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !"/link/v2/control".equals(uri.getPath())) {
            throw new IllegalArgumentException("control URI must be the Website Link WSS control path");
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

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while ((current instanceof java.util.concurrent.CompletionException
                || current instanceof java.util.concurrent.ExecutionException) && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private record Challenge(UUID id, String proof) { }
}
