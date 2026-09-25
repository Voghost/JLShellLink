package com.jlshell.link.server;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.model.NodeIdentity;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class NodeConnectionRegistryTest {
    private static final Instant NOW = Instant.parse("2026-09-25T08:00:00Z");

    @Test
    void staleControlSessionCannotRefreshOrRemoveNewerOnlineGeneration() {
        NodeConnectionRegistry registry = new NodeConnectionRegistry(Clock.fixed(NOW, ZoneOffset.UTC));
        UUID nodeId = UUID.randomUUID();
        UUID accountId = UUID.randomUUID();
        NodeIdentity identity = new NodeIdentity(nodeId, NodeRole.AGENT,
                new NodeKeyFingerprint("ab".repeat(32)));
        var old = registry.register(identity, accountId, UUID.randomUUID(), NOW.plusSeconds(30));
        var current = registry.register(identity, accountId, UUID.randomUUID(), NOW.plusSeconds(60));

        assertNotEquals(old.generation(), current.generation());
        assertFalse(registry.heartbeat(old, NOW.plusSeconds(300)));
        registry.unregister(old);
        assertTrue(registry.findOnline(nodeId).isPresent());
        assertTrue(registry.heartbeat(current, NOW.plusSeconds(120)));
    }
}
