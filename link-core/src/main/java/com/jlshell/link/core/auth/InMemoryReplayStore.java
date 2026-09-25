package com.jlshell.link.core.auth;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/** Bounded by token lifetime; production can replace this with a shared atomic store. */
public final class InMemoryReplayStore implements ReplayStore {
    private final ConcurrentHashMap<String, Instant> consumed = new ConcurrentHashMap<>();

    @Override
    public boolean consume(String jti, Instant expiresAt, Instant now) {
        if (jti == null || jti.isBlank()) throw new IllegalArgumentException("jti is required");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(now, "now");
        if (!expiresAt.isAfter(now)) return false;
        AtomicBoolean accepted = new AtomicBoolean();
        consumed.compute(jti, (ignored, existing) -> {
            if (existing == null || !existing.isAfter(now)) {
                accepted.set(true);
                return expiresAt;
            }
            return existing;
        });
        if ((consumed.size() & 255) == 0) consumed.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
        return accepted.get();
    }
}
