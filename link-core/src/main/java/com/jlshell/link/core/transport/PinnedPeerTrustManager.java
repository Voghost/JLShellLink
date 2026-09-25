package com.jlshell.link.core.transport;

import java.net.Socket;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Adds an exact leaf SubjectPublicKeyInfo SHA-256 pin to normal PKIX trust.
 * The delegate still validates the certificate chain; the pin is an additional
 * identity check and never a replacement for certificate validation.
 */
public final class PinnedPeerTrustManager extends X509ExtendedTrustManager {
    private final X509ExtendedTrustManager delegate;
    private final byte[] expectedSpkiSha256;

    public PinnedPeerTrustManager(X509ExtendedTrustManager delegate, byte[] expectedSpkiSha256) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        Objects.requireNonNull(expectedSpkiSha256, "expectedSpkiSha256");
        if (expectedSpkiSha256.length != 32) {
            throw new IllegalArgumentException("SPKI SHA-256 pin must be exactly 32 bytes");
        }
        this.expectedSpkiSha256 = expectedSpkiSha256.clone();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
        checkPin(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
        checkPin(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
        checkPin(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType, socket);
        checkPin(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType, engine);
        checkPin(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType, engine);
        checkPin(chain);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers().clone();
    }

    private void checkPin(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0 || chain[0] == null) {
            throw new CertificateException("Peer certificate chain is empty");
        }
        try {
            byte[] actual = MessageDigest.getInstance("SHA-256").digest(chain[0].getPublicKey().getEncoded());
            if (!MessageDigest.isEqual(expectedSpkiSha256, actual)) {
                Arrays.fill(actual, (byte) 0);
                throw new CertificateException("Peer public key does not match the expected pin");
            }
            Arrays.fill(actual, (byte) 0);
        } catch (CertificateException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateException("Unable to calculate peer public key pin", e);
        }
    }
}
