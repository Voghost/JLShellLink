package com.jlshell.link.core.transport;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Objects;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/** Creates a fresh TLS 1.3 context bound to one expected peer key. */
public final class TlsPeerContext {
    private TlsPeerContext() { }

    /**
     * Builds a per-tunnel context from an explicit trust store and adds the
     * exact SPKI pin to normal certificate-chain validation.
     * Do not share the returned context across tunnels, so a later connection
     * cannot resume this tunnel's TLS session.
     */
    public static SSLContext create(KeyManager[] localIdentity, KeyStore trustStore,
            byte[] expectedPeerSpkiSha256)
            throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException {
        Objects.requireNonNull(localIdentity, "localIdentity");
        Objects.requireNonNull(trustStore, "trustStore");
        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);
        X509ExtendedTrustManager chainTrust = null;
        for (TrustManager candidate : trustFactory.getTrustManagers()) {
            if (candidate instanceof X509ExtendedTrustManager x509) {
                chainTrust = x509;
                break;
            }
        }
        if (chainTrust == null) {
            throw new CertificateException("Trust store did not produce an X.509 trust manager");
        }
        PinnedPeerTrustManager pinned = new PinnedPeerTrustManager(chainTrust, expectedPeerSpkiSha256);
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(localIdentity.clone(), new javax.net.ssl.TrustManager[] {pinned}, new SecureRandom());
        return context;
    }

    /** Configures a newly-created engine with TLS 1.3 and HTTP/2 ALPN only. */
    public static SSLEngine newEngine(SSLContext context, String peerHost, int peerPort, boolean clientMode) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(peerHost, "peerHost");
        if (peerPort < 1 || peerPort > 65_535) {
            throw new IllegalArgumentException("peerPort must be between 1 and 65535");
        }
        SSLEngine engine = context.createSSLEngine(peerHost, peerPort);
        engine.setUseClientMode(clientMode);
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setProtocols(new String[] {"TLSv1.3"});
        parameters.setApplicationProtocols(new String[] {"h2"});
        if (!clientMode) {
            parameters.setNeedClientAuth(true);
        }
        engine.setSSLParameters(parameters);
        return engine;
    }
}
