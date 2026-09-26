package com.jlshell.link.client;

import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.identity.SecureSecretStore;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/** A's inner mTLS identity, loaded from the host's protected storage and bound to its node key. */
public final class ClientTlsIdentity {
    private final javax.net.ssl.KeyManager[] keyManagers;

    private ClientTlsIdentity(javax.net.ssl.KeyManager[] keyManagers) {
        this.keyManagers = keyManagers.clone();
    }

    public static ClientTlsIdentity load(SecureSecretStore secrets, String name,
            char[] password, LocalNodeKey nodeKey) throws Exception {
        Objects.requireNonNull(secrets, "secrets");
        if (name == null || name.isBlank()) throw new IllegalArgumentException("TLS identity name is required");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(nodeKey, "nodeKey");
        byte[] encoded = secrets.read(name).orElseThrow(
                () -> new IOException("Client TLS identity is missing from secure storage")).clone();
        if (encoded.length == 0 || encoded.length > 64 * 1024) {
            Arrays.fill(encoded, (byte) 0);
            throw new IOException("Client TLS identity size is invalid");
        }
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try {
            keys.load(new ByteArrayInputStream(encoded), password);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
        int entries = 0;
        for (var aliases = keys.aliases(); aliases.hasMoreElements();) {
            String alias = aliases.nextElement();
            if (!keys.isKeyEntry(alias)) continue;
            entries++;
            if (!(keys.getCertificate(alias) instanceof X509Certificate certificate)) {
                throw new SecurityException("Client TLS identity has no X.509 certificate");
            }
            if (keys.getCertificateChain(alias) == null || keys.getCertificateChain(alias).length != 1) {
                throw new SecurityException("Client TLS identity must have one self-signed certificate");
            }
            certificate.checkValidity();
            certificate.verify(certificate.getPublicKey());
            if (!NodeKeyFingerprint.from(certificate.getPublicKey()).equals(nodeKey.fingerprint())) {
                throw new SecurityException("Client TLS certificate does not match the enrolled node key");
            }
            if (!(keys.getKey(alias, password) instanceof PrivateKey privateKey)) {
                throw new SecurityException("Client TLS identity has no private key");
            }
            new com.jlshell.link.core.identity.Ed25519NodeKey(
                    new KeyPair(certificate.getPublicKey(), privateKey));
        }
        if (entries != 1) throw new SecurityException("Client TLS identity must contain one node key");
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, password);
        return new ClientTlsIdentity(factory.getKeyManagers());
    }

    /** Create a fresh context per grant, pinning C's exact Website-authorized node key. */
    public SSLContext forAgent(NodeKeyFingerprint expectedAgent) {
        Objects.requireNonNull(expectedAgent, "expectedAgent");
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keyManagers.clone(), new TrustManager[] { new ExactNodeTrust(expectedAgent) },
                    new SecureRandom());
            return context;
        } catch (Exception error) {
            throw new IllegalStateException("Unable to create pinned client TLS context", error);
        }
    }

    private static final class ExactNodeTrust extends X509ExtendedTrustManager {
        private final NodeKeyFingerprint expected;
        private ExactNodeTrust(NodeKeyFingerprint expected) { this.expected = expected; }

        private void verify(X509Certificate[] chain) throws CertificateException {
            if (chain == null || chain.length != 1 || chain[0] == null) {
                throw new CertificateException("Link Agent certificate chain is invalid");
            }
            X509Certificate certificate = chain[0];
            certificate.checkValidity();
            try {
                certificate.verify(certificate.getPublicKey());
                if (!expected.equals(NodeKeyFingerprint.from(certificate.getPublicKey()))) {
                    throw new CertificateException("Link Agent key does not match Website grant");
                }
            } catch (java.security.GeneralSecurityException error) {
                throw new CertificateException("Link Agent certificate is invalid", error);
            }
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException { verify(chain); }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException { verify(chain); }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, java.net.Socket socket)
                throws CertificateException { verify(chain); }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, java.net.Socket socket)
                throws CertificateException { verify(chain); }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine)
                throws CertificateException { verify(chain); }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine)
                throws CertificateException { verify(chain); }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
