package com.jlshell.link.server;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TunnelId;

/** Must enqueue quickly; persistence and batching belong on a separate worker. */
@FunctionalInterface
public interface UsageRecorder {
    UsageRecorder NOOP = (session, tunnel, direction, bytes) -> { };

    void record(LinkSessionId sessionId, TunnelId tunnelId, Direction direction, long bytes);

    enum Direction { CLIENT_TO_AGENT, AGENT_TO_CLIENT }
}
