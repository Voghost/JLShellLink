package com.jlshell.link.core.transport;

import java.util.concurrent.atomic.AtomicLong;

/** Shared byte reservation ledger for all streams under one transport session. */
public final class TransportBufferBudget {
    private final long limitBytes;
    private final AtomicLong inUseBytes = new AtomicLong();

    public TransportBufferBudget(long limitBytes) {
        if (limitBytes <= 0) {
            throw new IllegalArgumentException("limitBytes must be positive");
        }
        this.limitBytes = limitBytes;
    }

    public boolean tryReserve(long bytes) {
        if (bytes <= 0) {
            throw new IllegalArgumentException("bytes must be positive");
        }
        while (true) {
            long current = inUseBytes.get();
            if (bytes > limitBytes - current) {
                return false;
            }
            if (inUseBytes.compareAndSet(current, current + bytes)) {
                return true;
            }
        }
    }

    public void release(long bytes) {
        if (bytes <= 0) {
            throw new IllegalArgumentException("bytes must be positive");
        }
        long remaining = inUseBytes.addAndGet(-bytes);
        if (remaining < 0) {
            inUseBytes.addAndGet(bytes);
            throw new IllegalStateException("released more transport memory than was reserved");
        }
    }

    public long inUseBytes() {
        return inUseBytes.get();
    }

    public long limitBytes() {
        return limitBytes;
    }
}
