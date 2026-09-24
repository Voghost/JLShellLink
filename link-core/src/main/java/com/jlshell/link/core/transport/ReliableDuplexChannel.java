package com.jlshell.link.core.transport;

import java.nio.ByteBuffer;
import java.util.concurrent.CompletionStage;

/** Minimal byte-stream contract for comparing direct and relayed carriers. */
public interface ReliableDuplexChannel extends AutoCloseable {
    /** Closing the channel cancels pending writes and releases carrier resources. */
    CompletionStage<Void> write(ByteBuffer data);

    CompletionStage<Void> shutdownOutput();

    CompletionStage<Void> closed();

    @Override
    void close();
}
