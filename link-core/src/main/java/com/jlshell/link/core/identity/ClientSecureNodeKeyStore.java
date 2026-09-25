package com.jlshell.link.core.identity;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;
import java.util.Optional;

public final class ClientSecureNodeKeyStore implements NodeKeyStore {
    private final SecureSecretStore secrets;
    private final String name;

    public ClientSecureNodeKeyStore(SecureSecretStore secrets, String name) {
        this.secrets = Objects.requireNonNull(secrets, "secrets");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Store name is required");
        this.name = name;
    }

    @Override
    public Optional<Ed25519NodeKey> load() throws IOException, GeneralSecurityException {
        Optional<byte[]> encoded = secrets.read(name);
        if (encoded.isEmpty()) return Optional.empty();
        byte[] publicBytes;
        byte[] privateBytes;
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded.orElseThrow()))) {
            publicBytes = input.readNBytes(checkedLength(input.readInt()));
            privateBytes = input.readNBytes(checkedLength(input.readInt()));
            if (input.available() != 0) throw new IOException("Node key entry has trailing data");
        }
        KeyFactory factory = KeyFactory.getInstance("Ed25519");
        KeyPair keyPair = new KeyPair(
                factory.generatePublic(new X509EncodedKeySpec(publicBytes)),
                factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes)));
        return Optional.of(new Ed25519NodeKey(keyPair));
    }

    @Override
    public void store(Ed25519NodeKey key) throws IOException {
        Objects.requireNonNull(key, "key");
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(buffer)) {
            byte[] publicBytes = key.publicKey().getEncoded();
            byte[] privateBytes = key.privateKey().getEncoded();
            output.writeInt(publicBytes.length);
            output.write(publicBytes);
            output.writeInt(privateBytes.length);
            output.write(privateBytes);
        }
        secrets.write(name, buffer.toByteArray());
    }

    private static int checkedLength(int length) throws IOException {
        if (length < 1 || length > 4096) throw new IOException("Node key entry length is invalid");
        return length;
    }
}
