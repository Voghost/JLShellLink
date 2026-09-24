package com.jlshell.link.core.model;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/** SHA-256 over the standard X.509 SubjectPublicKeyInfo encoding. */
public record NodeKeyFingerprint(String value) {
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");

    public NodeKeyFingerprint {
        Objects.requireNonNull(value, "value");
        value = value.toLowerCase(Locale.ROOT);
        if (!SHA256_HEX.matcher(value).matches()) {
            throw new IllegalArgumentException("Fingerprint must be 64 lowercase hexadecimal characters");
        }
    }

    public static NodeKeyFingerprint from(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        byte[] encoded = Objects.requireNonNull(publicKey.getEncoded(), "Public key has no standard encoding");
        try {
            return new NodeKeyFingerprint(HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(encoded)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
