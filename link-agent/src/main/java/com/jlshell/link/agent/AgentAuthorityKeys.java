package com.jlshell.link.agent;

import com.jlshell.link.core.auth.SigningKeyResolver;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Fetches the Website's published Ed25519 ticket verification keys over HTTPS. */
public final class AgentAuthorityKeys implements SigningKeyResolver, AutoCloseable {
    private static final byte[] X509_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
    private final URI endpoint;
    private final HttpClient http;
    private volatile Map<String, PublicKey> keys = Map.of();

    public AgentAuthorityKeys(URI website) {
        if (website == null || !"https".equalsIgnoreCase(website.getScheme())
                || website.getHost() == null || website.getUserInfo() != null
                || website.getRawQuery() != null || website.getRawFragment() != null) {
            throw new IllegalArgumentException("ticket authority requires the registered HTTPS Website origin");
        }
        endpoint = website.resolve("/api/v1/link/ticket-authority");
        http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    public synchronized void refresh() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(15)).GET().build();
        HttpResponse<java.io.InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        byte[] raw;
        try (var body = response.body()) { raw = body.readNBytes(16_385); }
        if (response.statusCode() != 200 || raw.length > 16_384) {
            throw new IOException("Website ticket authority is unavailable");
        }
        try {
            Map<String, Object> body = JSONObjectUtils.parse(
                    new String(raw, java.nio.charset.StandardCharsets.UTF_8));
            if (!"Ed25519".equals(JSONObjectUtils.getString(body, "algorithm"))) {
                throw new IllegalArgumentException("unsupported ticket authority algorithm");
            }
            var published = JSONObjectUtils.getJSONArray(body, "keys");
            if (published.isEmpty() || published.size() > 16) {
                throw new IllegalArgumentException("ticket authority key count is invalid");
            }
            Map<String, PublicKey> next = new HashMap<>();
            for (Object entry : published) {
                if (!(entry instanceof Map<?, ?> rawEntry)) throw new IllegalArgumentException("invalid authority key");
                @SuppressWarnings("unchecked") Map<String, Object> value = (Map<String, Object>) rawEntry;
                String id = JSONObjectUtils.getString(value, "keyId");
                if (id == null || !id.matches("[A-Za-z0-9._-]{1,80}")) {
                    throw new IllegalArgumentException("invalid authority key id");
                }
                byte[] rawKey = Base64.getUrlDecoder().decode(JSONObjectUtils.getString(value, "publicKey"));
                if (rawKey.length != 32) throw new IllegalArgumentException("invalid authority public key");
                byte[] encoded = new byte[X509_PREFIX.length + rawKey.length];
                System.arraycopy(X509_PREFIX, 0, encoded, 0, X509_PREFIX.length);
                System.arraycopy(rawKey, 0, encoded, X509_PREFIX.length, rawKey.length);
                PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
                if (next.putIfAbsent(id, key) != null) throw new IllegalArgumentException("duplicate authority key");
            }
            keys = Map.copyOf(next);
        } catch (Exception invalid) {
            throw new IOException("Website ticket authority response is invalid", invalid);
        }
    }

    @Override public Optional<PublicKey> resolve(String keyId) {
        PublicKey known = keys.get(keyId);
        if (known != null) return Optional.of(known);
        try { refresh(); } catch (IOException | InterruptedException unavailable) {
            if (unavailable instanceof InterruptedException) Thread.currentThread().interrupt();
            return Optional.empty();
        }
        return Optional.ofNullable(keys.get(keyId));
    }

    @Override public void close() { http.shutdown(); }
}
