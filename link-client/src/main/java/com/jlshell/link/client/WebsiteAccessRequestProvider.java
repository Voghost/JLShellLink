package com.jlshell.link.client;

import com.jlshell.link.core.model.ConnectPolicy;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

/** Concrete WEB-02 adapter. Each connect/reconnect gets a fresh one-use tunnel ticket from Website. */
public final class WebsiteAccessRequestProvider implements ReauthorizingConnectionFlow.AccessRequestProvider {
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private final URI websiteOrigin;
    private final HttpClient http;
    private final Duration timeout;
    private final Supplier<? extends CompletionStage<String>> controlCredential;
    private final Executor worker;

    public WebsiteAccessRequestProvider(URI websiteOrigin, Duration connectTimeout, Duration requestTimeout,
            Supplier<? extends CompletionStage<String>> controlCredential, Executor worker) {
        this.websiteOrigin = validateOrigin(websiteOrigin);
        this.timeout = positive(requestTimeout);
        this.controlCredential = Objects.requireNonNull(controlCredential, "controlCredential");
        this.worker = Objects.requireNonNull(worker, "worker");
        this.http = HttpClient.newBuilder().connectTimeout(positive(connectTimeout))
                .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).build();
    }

    @Override
    public CompletionStage<ReauthorizingConnectionFlow.AuthorizedTunnel> request(
            Optional<LinkSessionId> reuseSessionId, UUID agentId, TargetEndpoint target, ConnectPolicy policy) {
        Objects.requireNonNull(reuseSessionId, "reuseSessionId");
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(policy, "policy");
        return controlCredential.get().thenCompose(credential -> CompletableFuture.supplyAsync(() -> {
            if (credential == null || credential.isBlank() || credential.length() > 4096) {
                throw new IllegalStateException("Host did not provide a valid Link control credential");
            }
            String json = "{\"sessionId\":" + reuseSessionId.map(id -> quote(id.toString())).orElse("null")
                    + ",\"agentId\":" + quote(agentId.toString())
                    + ",\"targetIp\":" + quote(target.address())
                    + ",\"targetPort\":" + target.port()
                    + ",\"connectPolicy\":" + quote(policy.name()) + "}";
            HttpRequest request = HttpRequest.newBuilder(websiteOrigin.resolve("/api/v2/link/access-requests"))
                    .timeout(timeout)
                    .header("X-Link-Control-Credential", credential)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();
            try {
                HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
                try (InputStream stream = response.body()) {
                    byte[] bytes = stream.readNBytes(MAX_RESPONSE_BYTES + 1);
                    if (bytes.length > MAX_RESPONSE_BYTES) throw new IOException("Website access response exceeds limit");
                    if (response.statusCode() != 201) throw new AccessRequestException(response.statusCode());
                    var body = JSONObjectUtils.parse(new String(bytes, StandardCharsets.UTF_8));
                    LinkSessionId session = LinkSessionId.parse(JSONObjectUtils.getString(body, "sessionId"));
                    TunnelId tunnel = TunnelId.parse(JSONObjectUtils.getString(body, "tunnelId"));
                    UUID returnedAgent = UUID.fromString(JSONObjectUtils.getString(body, "agentId"));
                    TargetEndpoint returnedTarget = new TargetEndpoint(JSONObjectUtils.getString(body, "targetIp"),
                            JSONObjectUtils.getInt(body, "targetPort"));
                    if (!agentId.equals(returnedAgent) || !target.equals(returnedTarget)) {
                        throw new SecurityException("Website authorized a different Agent or target");
                    }
                    return new ReauthorizingConnectionFlow.AuthorizedTunnel(session, tunnel, returnedAgent,
                            returnedTarget, JSONObjectUtils.getString(body, "accessTicket"),
                            Instant.parse(JSONObjectUtils.getString(body, "ticketExpiresAt")),
                            Instant.parse(JSONObjectUtils.getString(body, "authorizationLeaseExpiresAt")),
                            JSONObjectUtils.getLong(body, "policyVersion"));
                }
            } catch (IOException | InterruptedException | ParseException | IllegalArgumentException error) {
                if (error instanceof InterruptedException) Thread.currentThread().interrupt();
                throw new java.util.concurrent.CompletionException(error);
            }
        }, worker));
    }

    private static URI validateOrigin(URI uri) {
        Objects.requireNonNull(uri, "websiteOrigin");
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || !(uri.getPath().isEmpty() || "/".equals(uri.getPath()))) {
            throw new IllegalArgumentException("Website origin must be an origin-only HTTPS URI");
        }
        return uri;
    }

    private static Duration positive(Duration value) {
        Objects.requireNonNull(value, "timeout");
        if (value.isZero() || value.isNegative()) throw new IllegalArgumentException("timeout must be positive");
        return value;
    }

    private static String quote(String value) {
        String json = com.nimbusds.jose.util.JSONObjectUtils.toJSONString(java.util.Map.of("value", value));
        return json.substring("{\"value\":".length(), json.length() - 1);
    }

    public static final class AccessRequestException extends IOException {
        private final int statusCode;
        public AccessRequestException(int statusCode) {
            super("Website access request was rejected (HTTP " + statusCode + ")");
            this.statusCode = statusCode;
        }
        public int statusCode() { return statusCode; }
    }
}
