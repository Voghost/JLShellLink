package com.jlshell.link.core.identity;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Agent key storage with atomic replacement and owner-only POSIX permissions where supported. */
public final class RestrictedFileNodeKeyStore implements NodeKeyStore {
    private static final Set<PosixFilePermission> OWNER_ONLY =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private final Path file;

    public RestrictedFileNodeKeyStore(Path file) {
        this.file = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
    }

    @Override
    public Optional<Ed25519NodeKey> load() throws IOException, GeneralSecurityException {
        if (!Files.exists(file)) return Optional.empty();
        if (Files.isSymbolicLink(file)) throw new IOException("Node key file must not be a symbolic link");
        verifyOwnerOnly(file);
        String[] lines = Files.readString(file).split("\\R", -1);
        if (lines.length < 2) throw new IOException("Node key file is incomplete");
        KeyFactory factory = KeyFactory.getInstance("Ed25519");
        KeyPair keyPair = new KeyPair(
                factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(lines[0]))),
                factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(lines[1]))));
        return Optional.of(new Ed25519NodeKey(keyPair));
    }

    @Override
    public void store(Ed25519NodeKey key) throws IOException {
        Objects.requireNonNull(key, "key");
        Path parent = Objects.requireNonNull(file.getParent(), "Key file needs a parent directory");
        Files.createDirectories(parent);
        Path temporary = Files.createTempFile(parent, ".jlshell-link-key-", ".tmp");
        try {
            setOwnerOnly(temporary);
            String encoded = Base64.getEncoder().encodeToString(key.publicKey().getEncoded()) + "\n"
                    + Base64.getEncoder().encodeToString(key.privateKey().getEncoded()) + "\n";
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                channel.write(ByteBuffer.wrap(encoded.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
                channel.force(true);
            }
            try {
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
            }
            setOwnerOnly(file);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void setOwnerOnly(Path path) throws IOException {
        if (Files.getFileAttributeView(path, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        }
    }

    private static void verifyOwnerOnly(Path path) throws IOException {
        if (Files.getFileAttributeView(path, java.nio.file.attribute.PosixFileAttributeView.class) == null) return;
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
        if (permissions.stream().anyMatch(permission -> permission.name().startsWith("GROUP_")
                || permission.name().startsWith("OTHERS_"))) {
            throw new IOException("Node key file permissions expose key material");
        }
    }
}
