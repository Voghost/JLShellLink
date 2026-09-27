package com.jlshell.link.client;

import com.jlshell.link.core.ProtocolVersion;
import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/** Binds A's persistent node key to its account device through the host's authenticated API gateway. */
public final class WebsiteClientIdentityBinder {
    private final AccountApi account;
    private final NodeProofService proofs;

    public WebsiteClientIdentityBinder(AccountApi account) {
        this(account, new NodeProofService());
    }

    public WebsiteClientIdentityBinder(AccountApi account, NodeProofService proofs) {
        this.account = Objects.requireNonNull(account, "account");
        this.proofs = Objects.requireNonNull(proofs, "proofs");
    }

    public CompletionStage<DeviceIdentity> bind(UUID deviceRecordId, LocalNodeKey nodeKey) {
        Objects.requireNonNull(deviceRecordId, "deviceRecordId");
        Objects.requireNonNull(nodeKey, "nodeKey");
        Map<String, Object> identity = Map.of(
                "algorithm", "Ed25519",
                "publicKey", Base64.getEncoder().encodeToString(nodeKey.publicKey().getEncoded()),
                "nodeKeyFingerprint", nodeKey.fingerprint().value());
        Map<String, Object> challengeRequest = Map.of(
                "purpose", "device-binding",
                "nodeId", deviceRecordId.toString(),
                "identity", identity);

        return account.request("POST", "/api/v2/link/node-challenges", json(challengeRequest))
                .thenCompose(raw -> completeBinding(deviceRecordId, nodeKey, identity, parse(raw)))
                .exceptionallyCompose(error -> CompletableFuture.failedFuture(unwrap(error)));
    }

    private CompletionStage<DeviceIdentity> completeBinding(UUID deviceId, LocalNodeKey nodeKey,
            Map<String, Object> identity, Map<String, Object> challenge) {
        try {
            UUID challengeId = UUID.fromString(string(challenge, "challengeId"));
            String purpose = string(challenge, "purpose");
            UUID challengeNode = UUID.fromString(string(challenge, "nodeId"));
            byte[] nonce = Base64.getUrlDecoder().decode(string(challenge, "challenge"));
            Instant expiresAt = Instant.parse(string(challenge, "expiresAt"));
            if (!"device-binding".equals(purpose) || !deviceId.equals(challengeNode)
                    || nonce.length != 32 || !expiresAt.isAfter(Instant.now())) {
                throw new SecurityException("Website returned an invalid or expired client identity challenge");
            }
            byte[] signature = proofs.sign(nodeKey,
                    new NodeProofContext("device-binding", deviceId, Optional.empty()), nonce);
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("identity", identity);
            request.put("proof", Map.of("challengeId", challengeId.toString(),
                    "signature", Base64.getUrlEncoder().withoutPadding().encodeToString(signature)));
            request.put("protocolVersion", ProtocolVersion.V2);
            return account.request("PUT", "/api/v2/link/devices/" + deviceId + "/identity", json(request))
                    .thenApply(WebsiteClientIdentityBinder::parse)
                    .thenApply(bound -> verifyBinding(deviceId, nodeKey, bound));
        } catch (Exception error) {
            return CompletableFuture.failedFuture(error);
        }
    }

    private static DeviceIdentity verifyBinding(UUID deviceId, LocalNodeKey key, Map<String, Object> response) {
        UUID returnedId = UUID.fromString(string(response, "nodeId"));
        NodeKeyFingerprint fingerprint = new NodeKeyFingerprint(string(response, "nodeKeyFingerprint"));
        String protocolVersion = string(response, "protocolVersion");
        if (!deviceId.equals(returnedId) || !key.fingerprint().equals(fingerprint)
                || !ProtocolVersion.V2.equals(protocolVersion)) {
            throw new SecurityException("Website bound a different client device identity");
        }
        return new DeviceIdentity(returnedId, fingerprint, protocolVersion);
    }

    private static String json(Map<String, Object> value) {
        return JSONObjectUtils.toJSONString(value);
    }

    private static Map<String, Object> parse(String json) {
        if (json == null || json.getBytes(StandardCharsets.UTF_8).length > 64 * 1024) {
            throw new IllegalStateException("Website Link response is empty or exceeds the size limit");
        }
        try { return JSONObjectUtils.parse(json); }
        catch (java.text.ParseException error) { throw new IllegalStateException("Website Link response is invalid", error); }
    }

    private static String string(Map<String, Object> value, String key) {
        Object field = value.get(key);
        if (!(field instanceof String text) || text.isBlank()) {
            throw new IllegalStateException("Website Link response is missing " + key);
        }
        return text;
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while ((current instanceof java.util.concurrent.CompletionException
                || current instanceof java.util.concurrent.ExecutionException) && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    /** Implemented by JLShell using AccountSessionService; implementations must route only via the host gateway. */
    @FunctionalInterface
    public interface AccountApi {
        CompletionStage<String> request(String method, String path, String jsonBody);
    }

    public record DeviceIdentity(UUID deviceId, NodeKeyFingerprint keyFingerprint, String protocolVersion) {
        public DeviceIdentity {
            Objects.requireNonNull(deviceId, "deviceId");
            Objects.requireNonNull(keyFingerprint, "keyFingerprint");
            Objects.requireNonNull(protocolVersion, "protocolVersion");
        }
    }
}
