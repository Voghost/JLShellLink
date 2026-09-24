package com.jlshell.link.core.identity;

import com.jlshell.link.core.ProtocolVersion;
import com.jlshell.link.core.model.LinkSessionId;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public record NodeProofContext(String purpose, UUID nodeId, Optional<LinkSessionId> sessionId) {
    public NodeProofContext {
        if (purpose == null || purpose.isBlank()) throw new IllegalArgumentException("Purpose is required");
        Objects.requireNonNull(nodeId, "nodeId");
        sessionId = Objects.requireNonNull(sessionId, "sessionId");
    }

    byte[] signingInput(byte[] challenge) {
        Objects.requireNonNull(challenge, "challenge");
        if (challenge.length < 32) throw new IllegalArgumentException("Challenge must contain at least 256 bits");
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(buffer);
            write(output, "JLSHELL-LINK-NODE-PROOF");
            write(output, ProtocolVersion.V2);
            write(output, purpose);
            write(output, nodeId.toString());
            write(output, sessionId.map(LinkSessionId::toString).orElse(""));
            output.writeInt(challenge.length);
            output.write(challenge);
            return buffer.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static void write(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }
}
