package com.jlshell.link.core.transport;

import com.jlshell.link.core.model.LinkPath;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TunnelId;
import java.util.concurrent.CompletionStage;

/** Runtime tunnel handle. close() must be idempotent and propagate cancellation. */
public interface TunnelLease extends AutoCloseable {
    LinkSessionId sessionId();
    TunnelId tunnelId();
    LinkPath path();
    CompletionStage<Void> closed();
    @Override void close();
}
