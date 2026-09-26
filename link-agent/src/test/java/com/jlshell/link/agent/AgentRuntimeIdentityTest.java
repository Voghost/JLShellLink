package com.jlshell.link.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AgentRuntimeIdentityTest {
    @TempDir Path directory;

    @Test
    void importsTlsNodeKeyAndEnforcesOneRunningInstanceAndOwnerStop() throws Exception {
        Path p12 = directory.resolve("agent.p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool").toString();
        Process process = new ProcessBuilder(keytool, "-genkeypair", "-noprompt", "-alias", "agent",
                "-keyalg", "Ed25519", "-sigalg", "Ed25519", "-dname", "CN=agent",
                "-validity", "2", "-storetype", "PKCS12", "-keystore", p12.toString(),
                "-storepass", "testpass12").redirectErrorStream(true).start();
        assertTrue(process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(0, process.exitValue(), new String(process.getInputStream().readAllBytes()));
        if (Files.getFileAttributeView(p12, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Files.setPosixFilePermissions(p12, EnumSet.of(PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        }
        Path state = directory.resolve("state");
        AgentIdentityStore identity = new AgentIdentityStore(state);
        Ed25519NodeKey imported = identity.importTlsIdentity(p12, "testpass12".toCharArray());
        assertEquals(imported.fingerprint(), identity.loadKey().orElseThrow().fingerprint());
        AgentTlsIdentity tls = AgentTlsIdentity.load(p12, "testpass12".toCharArray(), imported);
        assertTrue(tls.forClient(new NodeKeyFingerprint("11".repeat(32))) != null);
        assertThrows(SecurityException.class, () -> AgentTlsIdentity.load(p12,
                "testpass12".toCharArray(), Ed25519NodeKey.generate()));

        assertFalse(AgentServiceControl.running(state));
        try (AgentServiceControl running = AgentServiceControl.acquire(state)) {
            assertTrue(AgentServiceControl.running(state));
            assertThrows(java.io.IOException.class, () -> AgentServiceControl.acquire(state));
            AgentServiceControl.requestStop(state);
            assertTrue(running.stopRequested());
        }
        assertFalse(AgentServiceControl.running(state));
    }
}
