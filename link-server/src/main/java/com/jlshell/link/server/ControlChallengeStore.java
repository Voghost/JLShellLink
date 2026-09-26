package com.jlshell.link.server;

import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Bounded single-use proof challenges for long-lived node-level control WSS connections. */
public final class ControlChallengeStore {
    private final Object lock = new Object();
    private final Map<UUID, StoredChallenge> challenges = new HashMap<>();
    private final SecureRandom random;
    private final NodeProofService proofs;
    private final Clock clock;
    private final Duration ttl;
    private final int capacity;

    public ControlChallengeStore(SecureRandom random, NodeProofService proofs, Clock clock,
                                 Duration ttl, int capacity) {
        this.random = Objects.requireNonNull(random, "random");
        this.proofs = Objects.requireNonNull(proofs, "proofs");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        if (ttl.isZero() || ttl.isNegative() || ttl.compareTo(Duration.ofMinutes(2)) > 0) {
            throw new IllegalArgumentException("control challenge ttl must be between 1ms and 2 minutes");
        }
        if (capacity < 1 || capacity > 1_000_000) throw new IllegalArgumentException("invalid challenge capacity");
        this.capacity = capacity;
    }

    public ChallengeResponse issue(ControlHandshake handshake,
                                   ControlPeerAuthenticator.AuthenticatedPeer peer) {
        Objects.requireNonNull(handshake, "handshake");
        Objects.requireNonNull(peer, "peer");
        if (!peer.matches(handshake)) throw new SecurityException("authenticated node does not match handshake");
        synchronized (lock) {
            prune();
            if (challenges.size() >= capacity) throw new IllegalStateException("control challenge capacity reached");
            byte[] nonce = new byte[32];
            random.nextBytes(nonce);
            UUID id = UUID.randomUUID();
            Instant expires = clock.instant().plus(ttl);
            challenges.put(id, new StoredChallenge(handshake, peer, nonce, expires));
            return new ChallengeResponse(id, Base64.getUrlEncoder().withoutPadding().encodeToString(nonce), expires);
        }
    }

    public boolean consume(UUID challengeId, ControlHandshake handshake,
                           ControlPeerAuthenticator.AuthenticatedPeer peer, String encodedProof) {
        Objects.requireNonNull(challengeId, "challengeId");
        Objects.requireNonNull(handshake, "handshake");
        Objects.requireNonNull(peer, "peer");
        StoredChallenge challenge;
        synchronized (lock) { challenge = challenges.remove(challengeId); }
        if (challenge == null || !challenge.expiresAt().isAfter(clock.instant())
                || !challenge.handshake().equals(handshake) || !peer.matches(handshake)
                || !challenge.peer().accountId().equals(peer.accountId())) return false;
        try {
            byte[] signature = Base64.getUrlDecoder().decode(Objects.requireNonNull(encodedProof, "proof"));
            return proofs.verify(peer.nodePublicKey(),
                    new NodeProofContext("control-channel", handshake.nodeId(), Optional.empty()),
                    challenge.nonce(), signature);
        } catch (Exception invalid) {
            return false;
        }
    }

    public int size() {
        synchronized (lock) { prune(); return challenges.size(); }
    }

    private void prune() {
        Instant now = clock.instant();
        challenges.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
    }

    public record ChallengeResponse(UUID challengeId, String challenge, Instant expiresAt) { }
    private record StoredChallenge(ControlHandshake handshake,
                                   ControlPeerAuthenticator.AuthenticatedPeer peer,
                                   byte[] nonce, Instant expiresAt) {
        private StoredChallenge { nonce = nonce.clone(); }
        @Override public byte[] nonce() { return nonce.clone(); }
    }
}
