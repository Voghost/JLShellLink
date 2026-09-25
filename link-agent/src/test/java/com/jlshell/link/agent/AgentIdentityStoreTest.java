package com.jlshell.link.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AgentIdentityStoreTest {
    @TempDir Path temporaryDirectory;

    @Test
    void persistsKeyAndCredentialSeparatelyWithOwnerOnlyPermissions() throws Exception {
        Path identityDirectory = temporaryDirectory.resolve("agent-identity");
        AgentIdentityStore store = new AgentIdentityStore(identityDirectory);
        var firstKey = store.loadOrCreateKey();
        UUID agentId = UUID.randomUUID();
        String credential = "agent-secret-token";
        store.storeRegistration(agentId, URI.create("https://link.example.test"), credential);

        AgentIdentityStore reopened = new AgentIdentityStore(identityDirectory);
        assertEquals(firstKey.fingerprint(), reopened.loadOrCreateKey().fingerprint());
        var registration = reopened.loadRegistration().orElseThrow();
        assertEquals(agentId, registration.agentId());
        assertEquals(credential, registration.credential());
        assertFalse(registration.toString().contains(credential));

        if (Files.getFileAttributeView(identityDirectory, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Set<PosixFilePermission> ownerOnly = Set.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE);
            assertEquals(ownerOnly, Files.getPosixFilePermissions(identityDirectory.resolve("agent.credential")));
            assertTrue(Files.getPosixFilePermissions(identityDirectory).stream()
                    .noneMatch(permission -> permission.name().startsWith("GROUP_")
                            || permission.name().startsWith("OTHERS_")));
        }
    }

    @Test
    void rejectsCredentialFileSymlinks() throws Exception {
        Path identityDirectory = temporaryDirectory.resolve("agent-identity");
        AgentIdentityStore store = new AgentIdentityStore(identityDirectory);
        store.storeRegistration(UUID.randomUUID(), URI.create("https://link.example.test"), "secret-token");
        Path credentialFile = identityDirectory.resolve("agent.credential");
        Path outside = temporaryDirectory.resolve("outside.credential");
        Files.writeString(outside, "secret-token\n");
        Files.delete(credentialFile);
        try {
            Files.createSymbolicLink(credentialFile, outside);
        } catch (UnsupportedOperationException | IOException unavailable) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "symbolic links are unavailable");
        }

        assertThrows(IOException.class, store::loadRegistration);
    }
}
