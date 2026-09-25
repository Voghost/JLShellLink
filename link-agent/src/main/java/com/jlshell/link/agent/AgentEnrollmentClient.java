package com.jlshell.link.agent;

import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
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
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Completes the Website's one-time enrollment challenge and persists the returned C credential. */
public final class AgentEnrollmentClient {
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private final HttpClient http;
    private final Duration timeout;
    private final NodeProofService proofs;

    public AgentEnrollmentClient(Duration connectTimeout, Duration requestTimeout, NodeProofService proofs) {
        this.timeout = positive(requestTimeout);
        this.http = HttpClient.newBuilder().connectTimeout(positive(connectTimeout))
                .followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1).build();
        this.proofs = Objects.requireNonNull(proofs, "proofs");
    }

    public Registration register(URI websiteOrigin, UUID agentId, String enrollmentToken,
            String platform, String architecture, String version, AgentIdentityStore identityStore,
            LocalNodeKey nodeKey) throws IOException, InterruptedException {
        URI website = validateOrigin(websiteOrigin);
        if (enrollmentToken == null || enrollmentToken.isBlank() || enrollmentToken.length() > 512) {
            throw new IllegalArgumentException("enrollment token is invalid");
        }
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(identityStore, "identityStore");
        Objects.requireNonNull(nodeKey, "nodeKey");
        String publicKey = Base64.getEncoder().encodeToString(nodeKey.publicKey().getEncoded());
        String fingerprint = nodeKey.fingerprint().value();

        String challengeBody = "{\"purpose\":\"enrollment\",\"nodeId\":" + quote(agentId.toString())
                + ",\"enrollmentToken\":" + quote(enrollmentToken)
                + ",\"identity\":{\"algorithm\":\"Ed25519\",\"publicKey\":" + quote(publicKey)
                + ",\"nodeKeyFingerprint\":" + quote(fingerprint) + "}}";
        var challengeJson = postJson(website.resolve("/api/v2/link/node-challenges"), null, challengeBody, 201);
        UUID challengeId = uuid(challengeJson, "challengeId");
        byte[] challenge = base64Url(challengeJson, "challenge");
        if (challenge.length != 32) throw new IOException("Website returned an invalid enrollment challenge");
        byte[] signature;
        try {
            signature = proofs.sign(nodeKey, new NodeProofContext("enrollment", agentId, Optional.empty()), challenge);
        } catch (java.security.GeneralSecurityException error) {
            throw new IOException("Could not prove ownership of the Agent key", error);
        }
        String consumeBody = "{\"agentId\":" + quote(agentId.toString())
                + ",\"enrollmentToken\":" + quote(enrollmentToken)
                + ",\"platform\":" + quote(platform)
                + ",\"architecture\":" + quote(architecture)
                + ",\"version\":" + quote(version == null ? "" : version)
                + ",\"capabilities\":[\"tcp-connect\"]"
                + ",\"identity\":{\"algorithm\":\"Ed25519\",\"publicKey\":" + quote(publicKey)
                + ",\"nodeKeyFingerprint\":" + quote(fingerprint) + "}"
                + ",\"proof\":{\"challengeId\":" + quote(challengeId.toString())
                + ",\"signature\":" + quote(Base64.getUrlEncoder().withoutPadding().encodeToString(signature))
                + "},\"protocolVersion\":\"link-v2\"}";
        var registration = postJson(website.resolve("/api/v2/link/enrollments/consume"), null, consumeBody, 200);
        UUID returnedId = uuid(registration, "nodeId");
        if (!agentId.equals(returnedId)
                || !fingerprint.equalsIgnoreCase(string(registration, "nodeKeyFingerprint"))) {
            throw new IOException("Website bound a different Agent identity");
        }
        String credential = string(registration, "nodeCredential");
        identityStore.storeRegistration(agentId, website, credential);
        Instant expires = Instant.parse(string(registration, "credentialExpiresAt"));
        return new Registration(agentId, nodeKey.fingerprint(), expires);
    }

    private java.util.Map<String, Object> postJson(URI uri, String bearer, String body, int expectedStatus)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(timeout)
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        if (bearer != null) builder.header("Authorization", "Bearer " + bearer);
        HttpResponse<InputStream> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream stream = response.body()) {
            byte[] bytes = stream.readNBytes(MAX_RESPONSE_BYTES + 1);
            if (bytes.length > MAX_RESPONSE_BYTES) throw new IOException("Website response exceeds limit");
            if (response.statusCode() != expectedStatus) {
                throw new ApiException(response.statusCode());
            }
            try {
                return JSONObjectUtils.parse(new String(bytes, StandardCharsets.UTF_8));
            } catch (ParseException error) {
                throw new IOException("Website enrollment response is invalid", error);
            }
        }
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
        Objects.requireNonNull(value, "duration");
        if (value.isZero() || value.isNegative()) throw new IllegalArgumentException("duration must be positive");
        return value;
    }

    private static String quote(String value) {
        StringBuilder result = new StringBuilder(value.length() + 2).append('"');
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            switch (c) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> { if (c < 0x20) result.append(String.format("\\u%04x", (int) c)); else result.append(c); }
            }
        }
        return result.append('"').toString();
    }

    private static UUID uuid(java.util.Map<String, Object> json, String field) throws IOException {
        try { return UUID.fromString(JSONObjectUtils.getString(json, field)); }
        catch (ParseException | IllegalArgumentException error) { throw new IOException("Invalid Website " + field, error); }
    }
    private static String string(java.util.Map<String, Object> json, String field) throws IOException {
        try { return JSONObjectUtils.getString(json, field); }
        catch (ParseException error) { throw new IOException("Invalid Website " + field, error); }
    }
    private static byte[] base64Url(java.util.Map<String, Object> json, String field) throws IOException {
        try { return Base64.getUrlDecoder().decode(string(json, field)); }
        catch (IllegalArgumentException error) { throw new IOException("Invalid Website " + field, error); }
    }

    public record Registration(UUID agentId, com.jlshell.link.core.model.NodeKeyFingerprint keyFingerprint,
                               Instant credentialExpiresAt) { }

    public static final class ApiException extends IOException {
        private final int statusCode;
        public ApiException(int statusCode) {
            super("Website enrollment API returned HTTP " + statusCode);
            this.statusCode = statusCode;
        }
        public int statusCode() { return statusCode; }
    }
}
