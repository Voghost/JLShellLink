package com.jlshell.link.core.transport;

import java.time.Duration;
import java.util.Objects;

/** Immutable upper bounds shared by TLS, HTTP/2 and carrier adapters. */
public record TransportBudget(
        int maxFrameBytes,
        int maxHeaderBytes,
        int maxConcurrentStreams,
        int maxQueuedWriteBytes,
        int maxBufferedBytesPerStream,
        int maxBufferedBytesTotal,
        int maxConcurrentHandshakes,
        Duration handshakeTimeout) {

    public TransportBudget {
        positive(maxFrameBytes, "maxFrameBytes");
        positive(maxHeaderBytes, "maxHeaderBytes");
        positive(maxConcurrentStreams, "maxConcurrentStreams");
        positive(maxQueuedWriteBytes, "maxQueuedWriteBytes");
        positive(maxBufferedBytesPerStream, "maxBufferedBytesPerStream");
        positive(maxBufferedBytesTotal, "maxBufferedBytesTotal");
        positive(maxConcurrentHandshakes, "maxConcurrentHandshakes");
        Objects.requireNonNull(handshakeTimeout, "handshakeTimeout");
        if (handshakeTimeout.isZero() || handshakeTimeout.isNegative()) {
            throw new IllegalArgumentException("handshakeTimeout must be positive");
        }
        if (maxHeaderBytes > maxFrameBytes) {
            throw new IllegalArgumentException("maxHeaderBytes cannot exceed maxFrameBytes");
        }
        if (maxQueuedWriteBytes > maxBufferedBytesTotal) {
            throw new IllegalArgumentException("write queue cannot exceed total buffer budget");
        }
        if (maxBufferedBytesPerStream > maxBufferedBytesTotal) {
            throw new IllegalArgumentException("per-stream budget cannot exceed total buffer budget");
        }
    }

    private static void positive(int value, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
