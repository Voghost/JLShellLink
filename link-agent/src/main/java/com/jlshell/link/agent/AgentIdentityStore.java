package com.jlshell.link.agent;

import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.identity.NodeKeyStore;
import com.jlshell.link.core.identity.RestrictedFileNodeKeyStore;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** C identity storage: persistent node key, metadata and bearer credential are separate owner-only files. */
public final class AgentIdentityStore {
    private static final Set<PosixFilePermission> OWNER_ONLY_FILE =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> OWNER_ONLY_DIR =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE);
    private final Path directory;
    private final Path metadataFile;
    private final Path credentialFile;
    private final NodeKeyStore keys;

    public AgentIdentityStore(Path directory) throws IOException {
        this.directory = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
        Files.createDirectories(this.directory);
        rejectSymlink(this.directory);
        setOwnerOnlyDirectory(this.directory);
        this.metadataFile = this.directory.resolve("agent.properties");
        this.credentialFile = this.directory.resolve("agent.credential");
        this.keys = new RestrictedFileNodeKeyStore(this.directory.resolve("node-key.ed25519"));
    }

    public Ed25519NodeKey loadOrCreateKey() throws IOException, GeneralSecurityException {
        Optional<Ed25519NodeKey> existing = keys.load();
        if (existing.isPresent()) return existing.get();
        Ed25519NodeKey generated = Ed25519NodeKey.generate();
        keys.store(generated);
        return generated;
    }

    public Optional<Ed25519NodeKey> loadKey() throws IOException, GeneralSecurityException {
        return keys.load();
    }

    public Optional<Registration> loadRegistration() throws IOException {
        if (!Files.exists(metadataFile)) return Optional.empty();
        verifyOwnerOnly(metadataFile);
        rejectSymlink(metadataFile);
        if (!Files.exists(credentialFile)) throw new IOException("Agent registration credential is missing");
        verifyOwnerOnly(credentialFile);
        rejectSymlink(credentialFile);
        String[] metadata = Files.readString(metadataFile, java.nio.charset.StandardCharsets.UTF_8).split("\\R", -1);
        if (metadata.length < 2) throw new IOException("Agent registration metadata is incomplete");
        String credential = Files.readString(credentialFile, java.nio.charset.StandardCharsets.UTF_8).trim();
        if (credential.isBlank() || credential.length() > 4096) throw new IOException("Agent credential is invalid");
        try {
            java.net.URI website = java.net.URI.create(metadata[1]);
            if (!"https".equalsIgnoreCase(website.getScheme()) || website.getHost() == null
                    || website.getUserInfo() != null || website.getQuery() != null || website.getFragment() != null) {
                throw new IOException("Stored Website URI is not HTTPS");
            }
            return Optional.of(new Registration(UUID.fromString(metadata[0]), website, credential));
        } catch (IllegalArgumentException malformed) {
            throw new IOException("Agent registration metadata is invalid", malformed);
        }
    }

    public void storeRegistration(UUID agentId, java.net.URI website, String credential) throws IOException {
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(website, "website");
        if (!"https".equalsIgnoreCase(website.getScheme()) || website.getHost() == null
                || website.getUserInfo() != null || website.getQuery() != null || website.getFragment() != null) {
            throw new IllegalArgumentException("Website URI must use HTTPS without user info or query");
        }
        if (credential == null || credential.isBlank() || credential.length() > 4096
                || credential.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("Agent credential is invalid");
        }
        atomicWrite(metadataFile, agentId + "\n" + website + "\n");
        atomicWrite(credentialFile, credential + "\n");
    }

    public record Registration(UUID agentId, java.net.URI website, String credential) {
        public Registration {
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(website, "website");
            if (credential == null || credential.isBlank()) throw new IllegalArgumentException("credential required");
        }
        @Override public String toString() { return "Registration[agentId=" + agentId + ", website=" + website
                + ", credential=<redacted>]"; }
    }

    private void atomicWrite(Path file, String content) throws IOException {
        Path temporary = Files.createTempFile(directory, ".jlshell-link-agent-", ".tmp");
        try {
            setOwnerOnlyFile(temporary);
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                channel.write(ByteBuffer.wrap(content.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                channel.force(true);
            }
            try {
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
                Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
            }
            setOwnerOnlyFile(file);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void rejectSymlink(Path path) throws IOException {
        if (Files.isSymbolicLink(path)) throw new IOException("Agent identity path must not be a symbolic link");
    }

    private static void setOwnerOnlyFile(Path path) throws IOException {
        if (Files.getFileAttributeView(path, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(path, OWNER_ONLY_FILE);
        }
    }

    private static void setOwnerOnlyDirectory(Path path) throws IOException {
        if (Files.getFileAttributeView(path, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(path, OWNER_ONLY_DIR);
        }
    }

    private static void verifyOwnerOnly(Path path) throws IOException {
        if (Files.getFileAttributeView(path, java.nio.file.attribute.PosixFileAttributeView.class) == null) return;
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
        if (permissions.stream().anyMatch(permission -> permission.name().startsWith("GROUP_")
                || permission.name().startsWith("OTHERS_"))) {
            throw new IOException("Agent identity file is accessible by other users");
        }
    }
}
