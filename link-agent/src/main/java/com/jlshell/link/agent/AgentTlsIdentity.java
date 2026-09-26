package com.jlshell.link.agent;

import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Set;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509ExtendedTrustManager;

/** Loads C's mTLS certificate and pins each A peer to its Website-bound Ed25519 node key. */
public final class AgentTlsIdentity {
    private final javax.net.ssl.KeyManager[] keyManagers;

    private AgentTlsIdentity(javax.net.ssl.KeyManager[] keyManagers) {
        this.keyManagers = keyManagers.clone();
    }

    public static AgentTlsIdentity load(Path file, char[] password, LocalNodeKey nodeKey) throws Exception {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(nodeKey, "nodeKey");
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Agent TLS identity must be a regular PKCS12 file");
        }
        if (Files.getFileAttributeView(file, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
            if (permissions.stream().anyMatch(permission -> permission.name().startsWith("GROUP_")
                    || permission.name().startsWith("OTHERS_"))) {
                throw new IOException("Agent TLS identity must be owner-only (chmod 600)");
            }
        }
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(file)) { keys.load(input, password); }
        int keyEntries = 0;
        boolean matching = false;
        for (var aliases = keys.aliases(); aliases.hasMoreElements();) {
            String alias = aliases.nextElement();
            if (!keys.isKeyEntry(alias)) continue;
            keyEntries++;
            if (!(keys.getCertificate(alias) instanceof X509Certificate certificate)) continue;
            certificate.checkValidity();
            if (NodeKeyFingerprint.from(certificate.getPublicKey()).equals(nodeKey.fingerprint())) {
                if (!(keys.getKey(alias, password) instanceof PrivateKey privateKey)) {
                    throw new SecurityException("Agent TLS identity has no private key");
                }
                new com.jlshell.link.core.identity.Ed25519NodeKey(
                        new KeyPair(certificate.getPublicKey(), privateKey));
                matching = true;
            }
        }
        if (!matching || keyEntries != 1) {
            throw new SecurityException("Agent TLS identity must contain exactly the enrolled node key");
        }
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keys, password);
        return new AgentTlsIdentity(factory.getKeyManagers());
    }

    public SSLContext forClient(NodeKeyFingerprint expectedClient) {
        Objects.requireNonNull(expectedClient, "expectedClient");
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(keyManagers.clone(), new javax.net.ssl.TrustManager[] {
                    new ExactNodeTrust(expectedClient) }, new SecureRandom());
            return context;
        } catch (Exception error) {
            throw new IllegalStateException("Unable to create pinned Agent TLS context", error);
        }
    }

    private static final class ExactNodeTrust extends X509ExtendedTrustManager {
        private final NodeKeyFingerprint expected;

        private ExactNodeTrust(NodeKeyFingerprint expected) { this.expected = expected; }

        private void verify(X509Certificate[] chain) throws java.security.cert.CertificateException {
            if (chain == null || chain.length != 1 || chain[0] == null) {
                throw new java.security.cert.CertificateException("Link peer certificate chain is invalid");
            }
            X509Certificate certificate = chain[0];
            certificate.checkValidity();
            try {
                certificate.verify(certificate.getPublicKey());
                if (!expected.equals(NodeKeyFingerprint.from(certificate.getPublicKey()))) {
                    throw new java.security.cert.CertificateException("Link peer node key does not match Website");
                }
            } catch (java.security.GeneralSecurityException invalid) {
                throw new java.security.cert.CertificateException("Link peer certificate is invalid", invalid);
            }
        }

        @Override public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException { verify(chain); }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws java.security.cert.CertificateException { verify(chain); }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, java.net.Socket socket)
                throws java.security.cert.CertificateException { verify(chain); }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, java.net.Socket socket)
                throws java.security.cert.CertificateException { verify(chain); }
        @Override public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine)
                throws java.security.cert.CertificateException { verify(chain); }
        @Override public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine)
                throws java.security.cert.CertificateException { verify(chain); }
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}
