package com.jlshell.link.core.transport;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletionStage;

/**
 * Bounded, ordered byte-stream contract shared by direct and relayed carriers.
 *
 * <p>Each read completes with at most the requested number of bytes. An empty
 * buffer means orderly input EOF. A successful write consumes the complete
 * remaining input; implementations must copy or otherwise retain the bytes
 * before the returned stage completes. Completion of {@link #whenWritable()}
 * means that the channel can accept at least one byte without exceeding its
 * configured queue budget.
 */
public interface ReliableDuplexChannel extends AutoCloseable {
    CompletionStage<ByteBuffer> read(int maxBytes);

    CompletionStage<Void> write(ByteBuffer data);

    CompletionStage<Void> whenWritable();

    /** Half-closes the local output after all previously accepted writes. */
    CompletionStage<Void> shutdownOutput();

    /** Completes normally on orderly closure and exceptionally on transport failure. */
    CompletionStage<Void> closed();

    /** Fails pending operations and closes the carrier with the supplied cause. */
    void abort(Throwable cause);

    /** Closing the channel cancels pending operations and releases carrier resources. */
    @Override
    void close();
}
