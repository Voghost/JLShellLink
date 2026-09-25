package com.jlshell.link.server;

import com.jlshell.link.core.identity.NodeProofContext;
import com.jlshell.link.core.identity.NodeProofService;
import com.jlshell.link.core.model.LinkSessionId;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Bounded, short-lived, one-use proof challenges for WSS upgrade authentication. */
public final class RelayChallengeStore {
    private final ConcurrentHashMap<UUID, Entry> entries = new ConcurrentHashMap<>();
    private final SecureRandom random;
    private final NodeProofService proofs;
    private final Clock clock;
    private final Duration ttl;
    private final int capacity;

    public RelayChallengeStore(SecureRandom random, NodeProofService proofs, Clock clock,
                               Duration ttl, int capacity) {
        this.random = Objects.requireNonNull(random, "random");
        this.proofs = Objects.requireNonNull(proofs, "proofs");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        if (ttl.isZero() || ttl.isNegative() || ttl.compareTo(Duration.ofMinutes(2)) > 0) {
            throw new IllegalArgumentException("challenge ttl must be at most two minutes");
        }
        if (capacity < 1 || capacity > 1_000_000) throw new IllegalArgumentException("invalid challenge capacity");
        this.capacity = capacity;
    }

    public synchronized Challenge issue(RelayHandshake handshake, RelayControlAuthenticator.AuthenticatedPeer peer) {
        Objects.requireNonNull(handshake, "handshake");
        Objects.requireNonNull(peer, "peer");
        if (!peer.matches(handshake)) throw new SecurityException("relay identity does not match credential");
        prune();
        if (entries.size() >= capacity) throw new IllegalStateException("relay challenge capacity is full");
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        UUID id = UUID.randomUUID();
        Instant expiresAt = clock.instant().plus(ttl);
        Entry entry = new Entry(handshake, peer, nonce, expiresAt);
        if (entries.putIfAbsent(id, entry) != null) throw new IllegalStateException("challenge id collision");
        return new Challenge(id, Base64.getUrlEncoder().withoutPadding().encodeToString(nonce), expiresAt);
    }

    /** Removes the challenge before proof verification, so racing/repeated proof attempts are single-use. */
    public boolean consume(UUID challengeId, RelayHandshake handshake,
                           RelayControlAuthenticator.AuthenticatedPeer peer, String proofBase64Url) {
        Objects.requireNonNull(challengeId, "challengeId");
        Entry entry = entries.remove(challengeId);
        if (entry == null || !entry.expiresAt().isAfter(clock.instant())
                || !entry.handshake().equals(handshake) || !samePrincipal(entry.peer(), peer)) return false;
        try {
            byte[] signature = Base64.getUrlDecoder().decode(Objects.requireNonNull(proofBase64Url,
                    "proofBase64Url"));
            return signature.length == 64 && proofs.verify(peer.nodePublicKey(),
                    new NodeProofContext("relay-control", handshake.nodeId(),
                            java.util.Optional.of(handshake.sessionId())), entry.nonce(), signature);
        } catch (IllegalArgumentException | GeneralSecurityException error) {
            return false;
        }
    }

    public synchronized int size() {
        prune();
        return entries.size();
    }

    private void prune() {
        Instant now = clock.instant();
        entries.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
    }

    private static boolean samePrincipal(RelayControlAuthenticator.AuthenticatedPeer left,
                                         RelayControlAuthenticator.AuthenticatedPeer right) {
        return left != null && right != null && left.role() == right.role()
                && left.accountId().equals(right.accountId()) && left.nodeId().equals(right.nodeId())
                && left.agentId().equals(right.agentId()) && left.keyFingerprint().equals(right.keyFingerprint());
    }

    public record Challenge(UUID challengeId, String challenge, Instant expiresAt) { }
    private record Entry(RelayHandshake handshake, RelayControlAuthenticator.AuthenticatedPeer peer,
                         byte[] nonce, Instant expiresAt) {
        private Entry {
            nonce = nonce.clone();
        }
    }
}
