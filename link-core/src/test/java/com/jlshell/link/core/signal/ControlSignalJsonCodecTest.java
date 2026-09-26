package com.jlshell.link.core.signal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ControlSignalJsonCodecTest {
    private final ControlSignalJsonCodec codec = new ControlSignalJsonCodec();
    private final LinkSessionId sessionId = LinkSessionId.random();

    @Test
    void decodesAndEncodesNumericCandidateAddresses() {
        UUID messageId = UUID.randomUUID();
        UUID candidateId = UUID.randomUUID();
        String json = "{\"type\":\"ICE_CANDIDATE\",\"messageId\":\"" + messageId
                + "\",\"sessionId\":\"" + sessionId + "\",\"generation\":2,\"candidateId\":\""
                + candidateId + "\",\"candidateType\":\"SERVER_REFLEXIVE\",\"transport\":\"UDP\","
                + "\"address\":\"2001:db8::2\",\"port\":23000,\"priority\":17,"
                + "\"foundation\":\"f1\",\"sentAt\":\"2026-09-25T00:00:00Z\"}";

        ControlSignal.IceCandidate signal = (ControlSignal.IceCandidate) codec.decodeSignal(json);
        assertEquals("2001:db8:0:0:0:0:0:2", signal.address().getHostAddress());
        assertEquals(signal, codec.decodeSignal(codec.encode(signal)));
    }

    @Test
    void rejectsHostnamesAndMalformedCandidates() {
        String json = "{\"type\":\"ICE_CANDIDATE\",\"messageId\":\"" + UUID.randomUUID()
                + "\",\"sessionId\":\"" + sessionId + "\",\"generation\":2,\"candidateId\":\""
                + UUID.randomUUID() + "\",\"candidateType\":\"HOST\",\"transport\":\"UDP\","
                + "\"address\":\"example.com\",\"port\":23000,\"priority\":17,"
                + "\"foundation\":\"f1\",\"sentAt\":\"2026-09-25T00:00:00Z\"}";
        assertThrows(IllegalArgumentException.class, () -> codec.decodeSignal(json));
    }

    @Test
    void relayPathDoesNotRequireIceCandidates() {
        ControlSignal.PathReady ready = new ControlSignal.PathReady(UUID.randomUUID(), sessionId, 1,
                ControlSignal.Path.RELAY, null, null);
        ControlSignal.PathReady decoded = (ControlSignal.PathReady) codec.decodeSignal(codec.encode(ready));
        assertEquals(ControlSignal.Path.RELAY, decoded.path());
        assertNull(decoded.localCandidateId());
        assertNull(decoded.remoteCandidateId());
    }

    @Test
    void invitationIsAcceptedOnlyFromTheServerDirection() {
        var invite = new ControlSignal.SessionInvite(UUID.randomUUID(), sessionId, 3,
                UUID.randomUUID(), UUID.randomUUID(), new NodeKeyFingerprint("22".repeat(32)),
                new NodeKeyFingerprint("11".repeat(32)), 4, Instant.parse("2026-09-26T01:00:00Z"));
        String json = codec.encode(invite);
        assertEquals(invite, codec.decodeServerSignal(json));
        assertThrows(IllegalArgumentException.class, () -> codec.decodeSignal(json));
    }

    @Test
    void revocationIsAcceptedOnlyFromTheServerDirection() {
        var revoked = new ControlSignal.SessionRevoked(UUID.randomUUID(), sessionId, 3);
        String json = codec.encode(revoked);
        assertEquals(revoked, codec.decodeServerSignal(json));
        assertThrows(IllegalArgumentException.class, () -> codec.decodeSignal(json));
    }

    @Test
    void parsesNodeHelloAndRejectsUnsupportedRoles() {
        UUID nodeId = UUID.randomUUID();
        var hello = codec.decodeHello("{\"type\":\"HELLO\",\"role\":\"agent\",\"nodeId\":\""
                + nodeId + "\",\"keyFingerprint\":\"" + "22".repeat(32)
                + "\",\"minProtocol\":\"link-v2\",\"maxProtocol\":\"link-v2\","
                + "\"capabilities\":[\"tcp-connect\"],\"sentAt\":\"2026-09-25T00:00:00Z\"}");
        assertEquals(NodeRole.AGENT, hello.role());
        assertEquals(nodeId, hello.nodeId());
        assertThrows(IllegalArgumentException.class, () -> codec.decodeHello("{\"type\":\"HELLO\","
                + "\"role\":\"admin\",\"sentAt\":\"2026-09-25T00:00:00Z\"}"));
    }
}
