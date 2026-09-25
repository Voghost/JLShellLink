package com.jlshell.link.agent;

import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/** HTTPS adapter for the implemented JLShell Website v2 Agent heartbeat and revocation APIs. */
public final class AgentControlPlaneClient {
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private final URI baseUri;
    private final HttpClient http;
    private final Duration requestTimeout;

    public AgentControlPlaneClient(URI baseUri, Duration connectTimeout, Duration requestTimeout) {
        this.baseUri = validateBaseUri(baseUri);
        this.requestTimeout = positive(requestTimeout, "requestTimeout");
        this.http = HttpClient.newBuilder()
                .connectTimeout(positive(connectTimeout, "connectTimeout"))
                .followRedirects(HttpClient.Redirect.NEVER)
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    public AgentLeaseSnapshot heartbeat(String credential, UUID sessionId, UUID agentId,
                                        NodeKeyFingerprint keyFingerprint, String version,
                                        Set<String> capabilities) throws IOException, InterruptedException {
        requireCredential(credential);
        String json = "{\"sessionId\":" + quote(sessionId.toString())
                + ",\"version\":" + quote(version == null ? "" : version)
                + ",\"capabilities\":" + stringArray(capabilities) + "}";
        HttpRequest request = HttpRequest.newBuilder(endpoint("/api/v2/link/agent-heartbeats"))
                .timeout(requestTimeout)
                .header("X-Agent-Token", credential)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        String response = send(request, 200);
        try {
            var body = JSONObjectUtils.parse(response);
            if (!agentId.equals(UUID.fromString(JSONObjectUtils.getString(body, "agentId")))) {
                throw new IOException("Website heartbeat returned a different Agent identity");
            }
            if (!keyFingerprint.value().equalsIgnoreCase(JSONObjectUtils.getString(body, "nodeKeyFingerprint"))) {
                throw new IOException("Website heartbeat returned a different Agent key");
            }
            String state = JSONObjectUtils.getString(body, "state");
            Instant leaseUntil = Instant.parse(JSONObjectUtils.getString(body, "controlLeaseExpiresAt"));
            return new AgentLeaseSnapshot(agentId, keyFingerprint,
                    JSONObjectUtils.getLong(body, "policyVersion"), leaseUntil, "REVOKED".equals(state));
        } catch (ParseException | IllegalArgumentException error) {
            throw new IOException("Website heartbeat response is invalid", error);
        }
    }

    public RevocationBatch pollRevocations(String credential, long afterSequence)
            throws IOException, InterruptedException {
        requireCredential(credential);
        if (afterSequence < 0) throw new IllegalArgumentException("afterSequence cannot be negative");
        HttpRequest request = HttpRequest.newBuilder(endpoint(
                        "/api/v2/link/agent-revocations?after=" + afterSequence))
                .timeout(requestTimeout)
                .header("X-Agent-Token", credential)
                .GET()
                .build();
        String response = send(request, 200);
        try {
            List<Object> values = JSONArrayUtils.parse(response);
            List<RevocationEvent> events = new ArrayList<>(values.size());
            long latestVersion = 1;
            long latestSequence = afterSequence;
            for (Object value : values) {
                if (!(value instanceof java.util.Map<?, ?> raw)) throw new IOException("Invalid revocation event");
                @SuppressWarnings("unchecked")
                java.util.Map<String, Object> event = (java.util.Map<String, Object>) raw;
                UUID eventAgent = UUID.fromString(JSONObjectUtils.getString(event, "agentId"));
                long sequence = JSONObjectUtils.getLong(event, "sequence");
                long version = JSONObjectUtils.getLong(event, "policyVersion");
                String reason = JSONObjectUtils.getString(event, "reason");
                if (sequence <= latestSequence) throw new IOException("Website returned unordered revocation events");
                latestSequence = sequence;
                latestVersion = Math.max(latestVersion, version);
                events.add(new RevocationEvent(sequence, eventAgent, version, reason,
                        Instant.parse(JSONObjectUtils.getString(event, "createdAt"))));
            }
            return new RevocationBatch(latestSequence, latestVersion, List.copyOf(events));
        } catch (ParseException | IllegalArgumentException error) {
            throw new IOException("Website revocation response is invalid", error);
        }
    }

    public List<RelayOpenRequest> pollRelayRequests(String credential)
            throws IOException, InterruptedException {
        requireCredential(credential);
        HttpRequest request = HttpRequest.newBuilder(endpoint("/api/v2/link/agent-relay-requests"))
                .timeout(requestTimeout)
                .header("X-Agent-Token", credential)
                .GET()
                .build();
        String response = send(request, 200);
        try {
            List<Object> values = JSONArrayUtils.parse(response);
            List<RelayOpenRequest> requests = new ArrayList<>(values.size());
            for (Object value : values) {
                if (!(value instanceof java.util.Map<?, ?> raw)) throw new IOException("Invalid relay request");
                @SuppressWarnings("unchecked")
                java.util.Map<String, Object> entry = (java.util.Map<String, Object>) raw;
                requests.add(new RelayOpenRequest(
                        UUID.fromString(JSONObjectUtils.getString(entry, "sessionId")),
                        UUID.fromString(JSONObjectUtils.getString(entry, "tunnelId")),
                        UUID.fromString(JSONObjectUtils.getString(entry, "agentId")),
                        JSONObjectUtils.getString(entry, "clientKeyFingerprint"),
                        JSONObjectUtils.getString(entry, "agentKeyFingerprint"),
                        JSONObjectUtils.getString(entry, "targetIp"),
                        JSONObjectUtils.getInt(entry, "targetPort"),
                        JSONObjectUtils.getLong(entry, "policyVersion"),
                        Instant.parse(JSONObjectUtils.getString(entry, "ticketExpiresAt")),
                        Instant.parse(JSONObjectUtils.getString(entry, "authorizationLeaseExpiresAt"))));
            }
            return List.copyOf(requests);
        } catch (ParseException | IllegalArgumentException error) {
            throw new IOException("Website relay request response is invalid", error);
        }
    }

    private String send(HttpRequest request, int expectedStatus) throws IOException, InterruptedException {
        HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream body = response.body()) {
            byte[] bytes = body.readNBytes(MAX_RESPONSE_BYTES + 1);
            if (bytes.length > MAX_RESPONSE_BYTES) throw new IOException("Website response exceeds limit");
            if (response.statusCode() != expectedStatus) throw new ApiException(response.statusCode());
            return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    private URI endpoint(String path) {
        return baseUri.resolve(path);
    }

    private static URI validateBaseUri(URI uri) {
        Objects.requireNonNull(uri, "baseUri");
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                || !(uri.getPath().isEmpty() || "/".equals(uri.getPath()))) {
            throw new IllegalArgumentException("Website base URI must be an origin-only HTTPS URI");
        }
        return uri;
    }

    private static Duration positive(Duration duration, String name) {
        Objects.requireNonNull(duration, name);
        if (duration.isZero() || duration.isNegative()) throw new IllegalArgumentException(name + " must be positive");
        return duration;
    }

    private static void requireCredential(String credential) {
        if (credential == null || credential.isBlank() || credential.length() > 4096) {
            throw new IllegalArgumentException("Agent credential is missing or invalid");
        }
    }

    private static String stringArray(Set<String> strings) {
        TreeSet<String> sorted = new TreeSet<>(Objects.requireNonNull(strings, "capabilities"));
        return "[" + sorted.stream().map(AgentControlPlaneClient::quote)
                .collect(java.util.stream.Collectors.joining(",")) + "]";
    }

    private static String quote(String value) {
        Objects.requireNonNull(value, "value");
        StringBuilder out = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.append('"').toString();
    }

    public record RevocationEvent(long sequence, UUID agentId, long policyVersion,
                                  String reason, Instant createdAt) { }
    public record RevocationBatch(long latestSequence, long latestPolicyVersion,
                                  List<RevocationEvent> events) { }
    public record RelayOpenRequest(UUID sessionId, UUID tunnelId, UUID agentId,
                                   String clientKeyFingerprint, String agentKeyFingerprint,
                                   String targetIp, int targetPort, long policyVersion,
                                   Instant ticketExpiresAt, Instant authorizationLeaseExpiresAt) { }

    public static final class ApiException extends IOException {
        private final int statusCode;
        public ApiException(int statusCode) {
            super("Website Link API returned HTTP " + statusCode);
            this.statusCode = statusCode;
        }
        public int statusCode() { return statusCode; }
    }
}
