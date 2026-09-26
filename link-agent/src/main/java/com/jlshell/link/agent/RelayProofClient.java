package com.jlshell.link.agent;

import com.jlshell.link.core.identity.NodeProofService;
import java.time.Duration;
import java.util.concurrent.Executor;

/** Binary-compatible forwarding type for existing Agent integrations. */
@Deprecated(forRemoval = false)
public final class RelayProofClient extends com.jlshell.link.transport.RelayProofClient {
    public RelayProofClient(Duration connectTimeout, Duration requestTimeout,
                            NodeProofService proofs, Executor worker) {
        super(connectTimeout, requestTimeout, proofs, worker);
    }
}
