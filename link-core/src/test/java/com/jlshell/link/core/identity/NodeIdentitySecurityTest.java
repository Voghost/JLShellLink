package com.jlshell.link.core.identity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NodeIdentitySecurityTest {
    @TempDir Path temporary;

    @Test
    void proofBindsPurposeNodeSessionAndChallenge() throws Exception {
        Ed25519NodeKey key = Ed25519NodeKey.generate();
        NodeProofContext context = new NodeProofContext("relay", UUID.randomUUID(),
                Optional.of(LinkSessionId.random()));
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        NodeProofService proofs = new NodeProofService();

        byte[] proof = proofs.sign(key, context, challenge);
        assertTrue(proofs.verify(key.publicKey(), context, challenge, proof));
        assertFalse(proofs.verify(key.publicKey(),
                new NodeProofContext("control", context.nodeId(), context.sessionId()), challenge, proof));
        challenge[0] ^= 1;
        assertFalse(proofs.verify(key.publicKey(), context, challenge, proof));
    }

    @Test
    void fingerprintUsesStablePublicEncoding() throws Exception {
        Ed25519NodeKey key = Ed25519NodeKey.generate();
        NodeKeyFingerprint first = key.fingerprint();
        NodeKeyFingerprint second = NodeKeyFingerprint.from(key.publicKey());
        assertEquals(first, second);
        assertEquals(64, first.value().length());
    }

    @Test
    void restrictedFileStoreRoundTripsAndUsesOwnerOnlyPermissions() throws Exception {
        Path path = temporary.resolve("identity/node.key");
        RestrictedFileNodeKeyStore store = new RestrictedFileNodeKeyStore(path);
        Ed25519NodeKey original = Ed25519NodeKey.generate();
        store.store(original);

        Ed25519NodeKey loaded = store.load().orElseThrow();
        assertArrayEquals(original.publicKey().getEncoded(), loaded.publicKey().getEncoded());
        assertArrayEquals(original.privateKey().getEncoded(), loaded.privateKey().getEncoded());
        if (Files.getFileAttributeView(path, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            assertEquals(java.util.Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(path));
        }
    }

    @Test
    void clientAdapterStoresOneAtomicSecretEntry() throws Exception {
        AtomicReference<byte[]> stored = new AtomicReference<>();
        SecureSecretStore secrets = new SecureSecretStore() {
            @Override public Optional<byte[]> read(String key) {
                return Optional.ofNullable(stored.get()).map(byte[]::clone);
            }
            @Override public void write(String key, byte[] secret) {
                stored.set(secret.clone());
            }
        };
        ClientSecureNodeKeyStore store = new ClientSecureNodeKeyStore(secrets, "link-node-key");
        Ed25519NodeKey original = Ed25519NodeKey.generate();
        store.store(original);
        Ed25519NodeKey loaded = store.load().orElseThrow();
        assertArrayEquals(original.publicKey().getEncoded(), loaded.publicKey().getEncoded());
        assertArrayEquals(original.privateKey().getEncoded(), loaded.privateKey().getEncoded());
    }

    @Test
    void restrictedFileStoreRejectsExposedPermissions() throws Exception {
        Path path = temporary.resolve("exposed/node.key");
        RestrictedFileNodeKeyStore store = new RestrictedFileNodeKeyStore(path);
        store.store(Ed25519NodeKey.generate());
        if (Files.getFileAttributeView(path, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(path, java.util.Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                    java.nio.file.attribute.PosixFilePermission.GROUP_READ));
            assertThrows(java.io.IOException.class, store::load);
        }
    }
}
