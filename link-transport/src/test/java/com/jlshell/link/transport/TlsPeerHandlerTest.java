package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.jlshell.link.core.transport.TlsPeerContext;
import com.jlshell.link.core.transport.TransportBudget;
import java.security.KeyStore;
import java.time.Duration;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;

class TlsPeerHandlerTest {
    @Test
    void limitsHandshakeAndUsesOnlyTls13() throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, new char[0]);
        SSLContext context = TlsPeerContext.create(new javax.net.ssl.KeyManager[0], trust, new byte[32]);
        TransportBudget budget = new TransportBudget(16_384, 8_192, 32, 1_048_576,
                262_144, 4_194_304, 4, Duration.ofSeconds(7));

        var handler = TlsPeerHandler.create(context, "peer.invalid", 443, true, budget);
        assertEquals(7_000, handler.getHandshakeTimeoutMillis());
        assertArrayEquals(new String[] {"TLSv1.3"}, handler.engine().getEnabledProtocols());
    }
}
