package com.jlshell.link.core.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyStore;
import javax.net.ssl.SSLEngine;
import org.junit.jupiter.api.Test;

class TlsPeerContextTest {
    @Test
    void createsTls13H2EnginesAndRequiresClientCertificateOnServer() throws Exception {
        byte[] pin = new byte[32];
        KeyStore emptyTrust = KeyStore.getInstance("PKCS12");
        emptyTrust.load(null, new char[0]);
        var context = TlsPeerContext.create(new javax.net.ssl.KeyManager[0], emptyTrust, pin);

        SSLEngine client = TlsPeerContext.newEngine(context, "peer.invalid", 443, true);
        SSLEngine server = TlsPeerContext.newEngine(context, "peer.invalid", 443, false);
        assertArrayEquals(new String[] {"TLSv1.3"}, client.getEnabledProtocols());
        assertArrayEquals(new String[] {"h2"}, client.getSSLParameters().getApplicationProtocols());
        assertTrue(server.getNeedClientAuth());
    }
}
