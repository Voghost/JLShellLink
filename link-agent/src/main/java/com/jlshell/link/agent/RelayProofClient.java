package com.jlshell.link.agent;

import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.model.TunnelId;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpHeaders;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import javax.net.ssl.SSLContext;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.ConnectStreamMultiplexer;
import com.jlshell.link.transport.TlsHandshakeGate;
import com.jlshell.link.transport.WssSecureConnector;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;

/** Requests a one-use B challenge, signs the role/session/tunnel-bound proof, then opens a WSS A—C carrier. */
public final class RelayProofClient {
    private static final int MAX_RESPONSE_BYTES = 16 * 1024;
    private final HttpClient http;
    private final NodeProofService proofs;
    private final Duration timeout;
    private final Executor worker;

    public RelayProofClient(Duration connectTimeout, Duration requestTimeout,
                            NodeProofService proofs, Executor worker) {
        this.http = HttpClient.newBuilder()
                .connectTimeout(positive(connectTimeout))
                .followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        this.timeout = positive(requestTimeout);
        this.proofs = Objects.requireNonNull(proofs, "proofs");
        this.worker = Objects.requireNonNull(worker, "worker");
    }

    public CompletionStage<Channel> connectGateway(EventLoopGroup group, URI relayUri,
            String credential, UUID agentId, LinkSessionId sessionId, TunnelId tunnelId,
            LocalNodeKey nodeKey, SSLContext outerTls, SSLContext innerTls,
            String innerPeerHost, int innerPeerPort, TransportBudget budget,
            TlsHandshakeGate gate, ConnectStreamMultiplexer multiplexer) {
        RelayRequest request = new RelayRequest(NodeRole.AGENT, agentId, agentId, sessionId, tunnelId,
                nodeKey.fingerprint(), credential);
        return connect(group, relayUri, request, nodeKey, outerTls, innerTls,
                innerPeerHost, innerPeerPort, budget, gate, multiplexer);
    }

    public CompletionStage<Channel> connectClient(EventLoopGroup group, URI relayUri,
            String controlCredential, UUID deviceId, UUID agentId, LinkSessionId sessionId,
            TunnelId tunnelId, LocalNodeKey nodeKey, NodeKeyFingerprint expectedAgentFingerprint,
            SSLContext outerTls, SSLContext innerTls, String innerPeerHost, int innerPeerPort,
            TransportBudget budget, TlsHandshakeGate gate) {
        RelayRequest request = new RelayRequest(NodeRole.CLIENT, deviceId, agentId, sessionId, tunnelId,
                nodeKey.fingerprint(), controlCredential);
        return connect(group, relayUri, request, nodeKey, outerTls, innerTls,
                innerPeerHost, innerPeerPort, budget, gate, null);
    }

    private CompletionStage<Channel> connect(EventLoopGroup group, URI relayUri, RelayRequest request,
            LocalNodeKey nodeKey, SSLContext outerTls, SSLContext innerTls,
            String innerPeerHost, int innerPeerPort, TransportBudget budget,
            TlsHandshakeGate gate, ConnectStreamMultiplexer multiplexer) {
        validateRelayUri(relayUri);
        return CompletableFuture.supplyAsync(() -> prepareHeaders(relayUri, request, nodeKey), worker)
                .thenCompose(headers -> request.role() == NodeRole.AGENT
                        ? WssSecureConnector.connectGateway(group, relayUri, outerTls, headers, innerTls,
                                innerPeerHost, innerPeerPort, budget, gate, multiplexer)
                        : WssSecureConnector.connectClient(group, relayUri, outerTls, headers, innerTls,
                                innerPeerHost, innerPeerPort, budget, gate));
    }

    private HttpHeaders prepareHeaders(URI relayUri, RelayRequest relay, LocalNodeKey nodeKey) {
        URI challengeUri = URI.create("https://" + relayUri.getRawAuthority() + WssRelayPaths.CHALLENGE_PATH);
        String body = "";
        HttpRequest request = HttpRequest.newBuilder(challengeUri)
                .timeout(timeout)
                .header("Authorization", "Bearer " + relay.credential())
                .header("X-Link-Role", relay.role() == NodeRole.CLIENT ? "client" : "agent")
                .header("X-Link-Node-Id", relay.nodeId().toString())
                .header("X-Link-Agent-Id", relay.agentId().toString())
                .header("X-Link-Session-Id", relay.sessionId().toString())
                .header("X-Link-Tunnel-Id", relay.tunnelId().toString())
                .header("X-Link-Key-Fingerprint", relay.keyFingerprint().value())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream input = response.body()) {
                byte[] bytes = input.readNBytes(MAX_RESPONSE_BYTES + 1);
                if (bytes.length > MAX_RESPONSE_BYTES || response.statusCode() != 201) {
                    throw new IllegalStateException("B did not issue a relay proof challenge");
                }
                var json = JSONObjectUtils.parse(new String(bytes, StandardCharsets.UTF_8));
                UUID challengeId = UUID.fromString(JSONObjectUtils.getString(json, "challengeId"));
                byte[] challenge = Base64.getUrlDecoder().decode(JSONObjectUtils.getString(json, "challenge"));
                if (challenge.length != 32) throw new IllegalStateException("B challenge length is invalid");
                byte[] signature = proofs.sign(nodeKey,
                        new NodeProofContext("relay-control", relay.nodeId(), Optional.of(relay.sessionId())),
                        challenge);
                return new DefaultHttpHeaders()
                        .set("Authorization", "Bearer " + relay.credential())
                        .set("X-Link-Role", relay.role() == NodeRole.CLIENT ? "client" : "agent")
                        .set("X-Link-Node-Id", relay.nodeId().toString())
                        .set("X-Link-Agent-Id", relay.agentId().toString())
                        .set("X-Link-Session-Id", relay.sessionId().toString())
                        .set("X-Link-Tunnel-Id", relay.tunnelId().toString())
                        .set("X-Link-Key-Fingerprint", relay.keyFingerprint().value())
                        .set("X-Link-Challenge-Id", challengeId.toString())
                        .set("X-Link-Proof", Base64.getUrlEncoder().withoutPadding().encodeToString(signature));
            }
        } catch (IOException | InterruptedException | ParseException | java.security.GeneralSecurityException
                 | IllegalArgumentException error) {
            if (error instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new IllegalStateException("Could not complete relay identity proof", error);
        }
    }

    private static void validateRelayUri(URI uri) {
        Objects.requireNonNull(uri, "relayUri");
        if (!"wss".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !WssRelayPaths.RELAY_PATH.equals(uri.getPath())) {
            throw new IllegalArgumentException("relay URI must be an origin-bound WSS Link relay path");
        }
    }

    private static Duration positive(Duration duration) {
        Objects.requireNonNull(duration, "duration");
        if (duration.isZero() || duration.isNegative()) throw new IllegalArgumentException("timeout must be positive");
        return duration;
    }

    /** Secret-bearing value object deliberately has a redacted printable representation. */
    private record RelayRequest(NodeRole role, UUID nodeId, UUID agentId, LinkSessionId sessionId,
                                TunnelId tunnelId, NodeKeyFingerprint keyFingerprint, String credential) {
        private RelayRequest {
            Objects.requireNonNull(role, "role");
            Objects.requireNonNull(nodeId, "nodeId");
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(tunnelId, "tunnelId");
            Objects.requireNonNull(keyFingerprint, "keyFingerprint");
            if (credential == null || credential.isBlank()) throw new IllegalArgumentException("credential required");
        }
        @Override public String toString() { return "RelayRequest[<redacted>]"; }
    }

    private static final class WssRelayPaths {
        private static final String RELAY_PATH = "/link/v2/relay";
        private static final String CHALLENGE_PATH = "/link/v2/relay-challenges";
    }
}
