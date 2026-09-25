package com.jlshell.link.server;

import com.jlshell.link.core.model.NodeIdentity;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** In-memory source of truth for live control sessions; stale generations cannot unregister newer ones. */
public final class NodeConnectionRegistry {
    private final ConcurrentHashMap<UUID, Entry> nodes = new ConcurrentHashMap<>();
    private final AtomicLong generations = new AtomicLong();
    private final Clock clock;

    public NodeConnectionRegistry(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public Registration register(NodeIdentity identity, UUID accountId, UUID controlSessionId,
                                 Instant leaseExpiresAt) {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(accountId, "accountId");
        Objects.requireNonNull(controlSessionId, "controlSessionId");
        requireFuture(leaseExpiresAt);
        long generation = generations.incrementAndGet();
        Entry entry = new Entry(identity, accountId, controlSessionId, leaseExpiresAt, generation);
        nodes.compute(identity.nodeId(), (ignored, current) ->
                current == null || current.generation() < generation ? entry : current);
        Entry active = nodes.get(identity.nodeId());
        if (active.generation() != generation) {
            throw new IllegalStateException("a newer control session already registered this node");
        }
        return new Registration(identity.nodeId(), controlSessionId, generation);
    }

    public boolean heartbeat(Registration registration, Instant leaseExpiresAt) {
        Objects.requireNonNull(registration, "registration");
        requireFuture(leaseExpiresAt);
        java.util.concurrent.atomic.AtomicBoolean updated = new java.util.concurrent.atomic.AtomicBoolean();
        nodes.computeIfPresent(registration.nodeId(), (ignored, entry) -> {
            if (entry.generation() != registration.generation()
                    || !entry.controlSessionId().equals(registration.controlSessionId())) return entry;
            updated.set(true);
            return new Entry(entry.identity(), entry.accountId(), entry.controlSessionId(),
                    leaseExpiresAt, entry.generation());
        });
        return updated.get();
    }

    public void unregister(Registration registration) {
        Objects.requireNonNull(registration, "registration");
        nodes.computeIfPresent(registration.nodeId(), (ignored, entry) ->
                entry.generation() == registration.generation()
                        && entry.controlSessionId().equals(registration.controlSessionId()) ? null : entry);
    }

    public Optional<Entry> findOnline(UUID nodeId) {
        Objects.requireNonNull(nodeId, "nodeId");
        Entry entry = nodes.get(nodeId);
        if (entry == null) return Optional.empty();
        if (!entry.leaseExpiresAt().isAfter(clock.instant())) {
            nodes.remove(nodeId, entry);
            return Optional.empty();
        }
        return Optional.of(entry);
    }

    public int onlineCount() {
        Instant now = clock.instant();
        nodes.entrySet().removeIf(entry -> !entry.getValue().leaseExpiresAt().isAfter(now));
        return nodes.size();
    }

    private void requireFuture(Instant expiry) {
        Objects.requireNonNull(expiry, "leaseExpiresAt");
        if (!expiry.isAfter(clock.instant())) throw new IllegalArgumentException("lease must be in the future");
    }

    public record Registration(UUID nodeId, UUID controlSessionId, long generation) {
        public Registration {
            Objects.requireNonNull(nodeId, "nodeId");
            Objects.requireNonNull(controlSessionId, "controlSessionId");
            if (generation < 1) throw new IllegalArgumentException("generation must be positive");
        }
    }

    public record Entry(NodeIdentity identity, UUID accountId, UUID controlSessionId,
                        Instant leaseExpiresAt, long generation) {
        public Entry {
            Objects.requireNonNull(identity, "identity");
            Objects.requireNonNull(accountId, "accountId");
            Objects.requireNonNull(controlSessionId, "controlSessionId");
            Objects.requireNonNull(leaseExpiresAt, "leaseExpiresAt");
        }
    }
}
