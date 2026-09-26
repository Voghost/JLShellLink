package com.jlshell.link.core.signal;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.net.InetAddress;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Typed, secret-free WSS control messages. Candidate addresses are numeric IPs, never hostnames. */
public sealed interface ControlSignal permits ControlSignal.SessionInvite,
        ControlSignal.SessionRevoked, ControlSignal.IceCandidate, ControlSignal.IceEnd, ControlSignal.PathReady {
    UUID messageId();
    LinkSessionId sessionId();
    long generation();

    record SessionInvite(UUID messageId, LinkSessionId sessionId, long generation,
                         UUID agentId, UUID clientDeviceId,
                         NodeKeyFingerprint agentKeyFingerprint,
                         NodeKeyFingerprint clientKeyFingerprint,
                         long policyVersion, Instant expiresAt) implements ControlSignal {
        public SessionInvite {
            common(messageId, sessionId, generation);
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(clientDeviceId, "clientDeviceId");
            Objects.requireNonNull(agentKeyFingerprint, "agentKeyFingerprint");
            Objects.requireNonNull(clientKeyFingerprint, "clientKeyFingerprint");
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (policyVersion < 0) throw new IllegalArgumentException("policyVersion cannot be negative");
        }
    }

    /** Server-only notification that this business authorization has ended. */
    record SessionRevoked(UUID messageId, LinkSessionId sessionId, long generation)
            implements ControlSignal {
        public SessionRevoked { common(messageId, sessionId, generation); }
    }

    record IceCandidate(UUID messageId, LinkSessionId sessionId, long generation,
                        UUID candidateId, CandidateType candidateType, Transport transport,
                        InetAddress address, int port, long priority, String foundation)
            implements ControlSignal {
        public IceCandidate {
            common(messageId, sessionId, generation);
            Objects.requireNonNull(candidateId, "candidateId");
            Objects.requireNonNull(candidateType, "candidateType");
            Objects.requireNonNull(transport, "transport");
            Objects.requireNonNull(address, "address");
            if (address.isAnyLocalAddress() || address.isMulticastAddress()) {
                throw new IllegalArgumentException("candidate address must be a unicast IP");
            }
            if (port < 1 || port > 65_535) throw new IllegalArgumentException("candidate port is invalid");
            if (priority < 0 || priority > 0xffff_ffffL) throw new IllegalArgumentException("candidate priority is invalid");
            if (foundation == null || !foundation.matches("[A-Za-z0-9+/]{1,32}")) {
                throw new IllegalArgumentException("candidate foundation is invalid");
            }
        }
    }

    record IceEnd(UUID messageId, LinkSessionId sessionId, long generation) implements ControlSignal {
        public IceEnd { common(messageId, sessionId, generation); }
    }

    record PathReady(UUID messageId, LinkSessionId sessionId, long generation,
                     Path path, UUID localCandidateId, UUID remoteCandidateId)
            implements ControlSignal {
        public PathReady {
            common(messageId, sessionId, generation);
            Objects.requireNonNull(path, "path");
            if (path == Path.DIRECT && (localCandidateId == null || remoteCandidateId == null)) {
                throw new IllegalArgumentException("direct path requires both selected candidate ids");
            }
            if (path == Path.RELAY && (localCandidateId != null || remoteCandidateId != null)) {
                throw new IllegalArgumentException("relay path cannot select ICE candidates");
            }
        }
    }

    enum CandidateType { HOST, SERVER_REFLEXIVE, PEER_REFLEXIVE, RELAY }
    enum Transport { UDP, TCP }
    enum Path { DIRECT, RELAY }

    private static void common(UUID messageId, LinkSessionId sessionId, long generation) {
        Objects.requireNonNull(messageId, "messageId");
        Objects.requireNonNull(sessionId, "sessionId");
        if (generation < 1) throw new IllegalArgumentException("generation must be positive");
    }
}
