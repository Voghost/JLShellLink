package com.jlshell.link.server;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.model.TunnelId;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.UUID;

/** Public, non-secret fields that bind one WSS relay handshake to a Website-authorized tunnel. */
public record RelayHandshake(NodeRole role, UUID nodeId, UUID agentId,
                             LinkSessionId sessionId, TunnelId tunnelId,
                             NodeKeyFingerprint keyFingerprint) {
    public RelayHandshake {
        if (role != NodeRole.CLIENT && role != NodeRole.AGENT) {
            throw new IllegalArgumentException("relay role must be CLIENT or AGENT");
        }
        Objects.requireNonNull(nodeId, "nodeId");
        Objects.requireNonNull(agentId, "agentId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(tunnelId, "tunnelId");
        Objects.requireNonNull(keyFingerprint, "keyFingerprint");
    }

    /** Length-prefixed canonical challenge binding; the bearer credential is never part of signed bytes. */
    public byte[] signingInput(byte[] nonce) {
        Objects.requireNonNull(nonce, "nonce");
        if (nonce.length != 32) throw new IllegalArgumentException("relay challenge must be 32 bytes");
        byte[][] fields = {
            "JLSHELL-LINK-RELAY-HANDSHAKE-V2".getBytes(StandardCharsets.US_ASCII),
            role.name().getBytes(StandardCharsets.US_ASCII),
            nodeId.toString().getBytes(StandardCharsets.US_ASCII),
            agentId.toString().getBytes(StandardCharsets.US_ASCII),
            sessionId.toString().getBytes(StandardCharsets.US_ASCII),
            tunnelId.toString().getBytes(StandardCharsets.US_ASCII),
            keyFingerprint.value().getBytes(StandardCharsets.US_ASCII),
            nonce.clone()
        };
        int length = 0;
        for (byte[] field : fields) length = Math.addExact(length, Integer.BYTES + field.length);
        ByteBuffer output = ByteBuffer.allocate(length);
        for (byte[] field : fields) output.putInt(field.length).put(field);
        return output.array();
    }
}
