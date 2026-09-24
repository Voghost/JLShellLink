package com.jlshell.link.core.transport;

import java.util.concurrent.CompletionStage;

/** Read-only cancellation signal shared by transport operations. */
public interface CancellationSignal {
    boolean isCancelled();

    CompletionStage<Void> cancelled();
}
