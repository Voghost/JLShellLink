package com.jlshell.link.core.auth;

import java.time.Instant;

public interface ReplayStore {
    /** Atomically consumes a jti once. Returns false when it was already consumed and remains live. */
    boolean consume(String jti, Instant expiresAt, Instant now);
}
