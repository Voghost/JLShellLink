package com.jlshell.link.transport;

import com.jlshell.link.core.transport.TlsPeerContext;
import com.jlshell.link.core.transport.TransportBudget;
import io.netty.handler.ssl.SslHandler;
import java.util.Objects;
import javax.net.ssl.SSLContext;

/** Netty TLS handler factory with the shared bounded handshake deadline. */
public final class TlsPeerHandler {
    private TlsPeerHandler() { }

    public static SslHandler create(SSLContext context, String peerHost, int peerPort,
            boolean clientMode, TransportBudget budget) {
        Objects.requireNonNull(budget, "budget");
        SslHandler handler = new SslHandler(
                TlsPeerContext.newEngine(context, peerHost, peerPort, clientMode));
        long timeoutMillis = Math.max(1, budget.handshakeTimeout().toMillis());
        handler.setHandshakeTimeoutMillis(timeoutMillis);
        return handler;
    }
}
