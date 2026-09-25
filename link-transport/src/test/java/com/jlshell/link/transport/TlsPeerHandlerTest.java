package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.transport.TlsPeerContext;
import com.jlshell.link.core.transport.TransportBudget;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;
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

    @Test
    void capsConcurrentHandshakesAndReleasesPermitOnClose() throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, new char[0]);
        SSLContext context = TlsPeerContext.create(new javax.net.ssl.KeyManager[0], trust, new byte[32]);
        TransportBudget budget = new TransportBudget(16_384, 8_192, 32, 1_048_576,
                262_144, 4_194_304, 1, Duration.ofSeconds(7));
        TlsHandshakeGate gate = new TlsHandshakeGate(budget.maxConcurrentHandshakes());
        SslHandler firstTls = TlsPeerHandler.create(context, "peer.invalid", 443, true, budget);
        EmbeddedChannel first = new EmbeddedChannel(gate.newHandler(firstTls), firstTls);
        SslHandler secondTls = TlsPeerHandler.create(context, "peer.invalid", 443, true, budget);
        EmbeddedChannel second = new EmbeddedChannel(gate.newHandler(secondTls), secondTls);
        try {
            assertEquals(1, gate.inFlightHandshakes());
            assertFalse(second.isActive());

            first.close();
            assertEquals(0, gate.inFlightHandshakes());

            SslHandler thirdTls = TlsPeerHandler.create(context, "peer.invalid", 443, true, budget);
            EmbeddedChannel third = new EmbeddedChannel(gate.newHandler(thirdTls), thirdTls);
            try {
                assertEquals(1, gate.inFlightHandshakes());
            } finally {
                third.finishAndReleaseAll();
            }
        } finally {
            first.finishAndReleaseAll();
            second.finishAndReleaseAll();
        }
    }

    @Test
    void activeCarrierAcquiresHandshakePermitBeforeAddingInnerTls() throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, new char[0]);
        SSLContext context = TlsPeerContext.create(new javax.net.ssl.KeyManager[0], trust, new byte[32]);
        TransportBudget budget = new TransportBudget(16_384, 8_192, 32, 1_048_576,
                262_144, 4_194_304, 1, Duration.ofSeconds(7));
        TlsHandshakeGate gate = new TlsHandshakeGate(1);
        EmbeddedChannel first = new EmbeddedChannel();
        EmbeddedChannel second = new EmbeddedChannel();
        try {
            SslHandler firstTls = TlsPeerHandler.create(context, "peer.invalid", 443, true, budget);
            assertTrue(gate.installOnActive(first.pipeline(), firstTls, new ChannelInboundHandlerAdapter()));
            assertEquals(1, gate.inFlightHandshakes());

            SslHandler secondTls = TlsPeerHandler.create(context, "peer.invalid", 443, true, budget);
            assertFalse(gate.installOnActive(second.pipeline(), secondTls, new ChannelInboundHandlerAdapter()));
            assertFalse(second.isActive());
            assertEquals(1, gate.inFlightHandshakes());

            first.close();
            assertEquals(0, gate.inFlightHandshakes());
        } finally {
            first.finishAndReleaseAll();
            second.finishAndReleaseAll();
        }
    }
}
