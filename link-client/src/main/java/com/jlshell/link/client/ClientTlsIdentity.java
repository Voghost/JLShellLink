package com.jlshell.link.client;

import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.identity.NodeKeyStore;
import com.jlshell.link.core.identity.SecureSecretStore;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** A's inner mTLS identity, loaded from the host's protected storage and bound to its node key. */
public final class ClientTlsIdentity {
    private static final String PKCS12_ALIAS = "jlshell-link-client";
    private static final String PASSWORD_CONTEXT = "JLSHELL-LINK-CLIENT-PKCS12-V1";
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

    /**
     * Creates A's Ed25519 node key and self-signed TLS certificate on first use, then keeps both
     * only in the host's encrypted secure storage. No certificate file or user-managed password
     * is required. Repeated calls reuse the same enrolled node identity.
     */
    public static LocalIdentity loadOrCreate(SecureSecretStore secrets, String tlsIdentityName,
            NodeKeyStore nodeKeys) throws Exception {
        Objects.requireNonNull(secrets, "secrets");
        if (tlsIdentityName == null || tlsIdentityName.isBlank()) {
            throw new IllegalArgumentException("TLS identity name is required");
        }
        Objects.requireNonNull(nodeKeys, "nodeKeys");
        Ed25519NodeKey nodeKey = nodeKeys.load().orElse(null);
        if (nodeKey == null) {
            nodeKey = Ed25519NodeKey.generate();
            nodeKeys.store(nodeKey);
        }
        char[] password = deriveStorePassword(nodeKey);
        try {
            if (needsRenewal(secrets, tlsIdentityName, password, nodeKey)) {
                byte[] identity = createPkcs12(nodeKey, password);
                try { secrets.write(tlsIdentityName, identity); }
                finally { Arrays.fill(identity, (byte) 0); }
            }
            return new LocalIdentity(nodeKey, load(secrets, tlsIdentityName, password, nodeKey));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static boolean needsRenewal(SecureSecretStore secrets, String name,
            char[] password, LocalNodeKey nodeKey) throws Exception {
        var stored = secrets.read(name);
        if (stored.isEmpty()) return true;
        byte[] encoded = stored.orElseThrow().clone();
        try {
            if (encoded.length == 0 || encoded.length > 64 * 1024) {
                throw new IOException("Client TLS identity size is invalid");
            }
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(new ByteArrayInputStream(encoded), password);
            int entries = 0;
            boolean renew = false;
            for (var aliases = keys.aliases(); aliases.hasMoreElements();) {
                String alias = aliases.nextElement();
                if (!keys.isKeyEntry(alias)) continue;
                entries++;
                if (!(keys.getCertificate(alias) instanceof X509Certificate certificate)
                        || keys.getCertificateChain(alias) == null
                        || keys.getCertificateChain(alias).length != 1) {
                    throw new SecurityException("Client TLS identity certificate is invalid");
                }
                certificate.verify(certificate.getPublicKey());
                if (!NodeKeyFingerprint.from(certificate.getPublicKey()).equals(nodeKey.fingerprint())) {
                    throw new SecurityException("Stored client TLS identity belongs to another node key");
                }
                if (!(keys.getKey(alias, password) instanceof PrivateKey privateKey)) {
                    throw new SecurityException("Client TLS identity has no private key");
                }
                new Ed25519NodeKey(new KeyPair(certificate.getPublicKey(), privateKey));
                if (certificate.getNotBefore().after(Date.from(Instant.now().plusSeconds(30)))) {
                    throw new SecurityException("Client TLS identity is not valid yet");
                }
                if (!certificate.getNotAfter().toInstant().isAfter(Instant.now().plus(30, ChronoUnit.DAYS))) {
                    renew = true;
                }
            }
            if (entries != 1) throw new SecurityException("Client TLS identity must contain one node key");
            return renew;
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static byte[] createPkcs12(LocalNodeKey nodeKey, char[] password) throws Exception {
        Instant now = Instant.now();
        X500Name subject = new X500Name("CN=JLShell Link Client "
                + nodeKey.fingerprint().value().substring(0, 16));
        BigInteger serial;
        SecureRandom random = new SecureRandom();
        do { serial = new BigInteger(159, random); } while (serial.signum() == 0);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serial,
                Date.from(now.minus(5, ChronoUnit.MINUTES)), Date.from(now.plus(3650, ChronoUnit.DAYS)),
                subject, nodeKey.publicKey());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
        var holder = builder.build(new JcaContentSignerBuilder("Ed25519").build(nodeKey.privateKey()));
        var certificate = new JcaX509CertificateConverter().getCertificate(holder);
        certificate.verify(nodeKey.publicKey());
        certificate.checkValidity();

        KeyStore keys = KeyStore.getInstance("PKCS12");
        keys.load(null, password);
        keys.setKeyEntry(PKCS12_ALIAS, nodeKey.privateKey(), password,
                new java.security.cert.Certificate[] { certificate });
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        keys.store(output, password);
        return output.toByteArray();
    }

    private static char[] deriveStorePassword(LocalNodeKey key) throws Exception {
        byte[] privateKey = key.privateKey().getEncoded();
        byte[] context = PASSWORD_CONTEXT.getBytes(StandardCharsets.US_ASCII);
        byte[] digest;
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(context);
            digest = sha256.digest(privateKey);
        } finally {
            Arrays.fill(privateKey, (byte) 0);
            Arrays.fill(context, (byte) 0);
        }
        try { return java.util.HexFormat.of().formatHex(digest).toCharArray(); }
        finally { Arrays.fill(digest, (byte) 0); }
    }

    public record LocalIdentity(Ed25519NodeKey nodeKey, ClientTlsIdentity tlsIdentity) {
        public LocalIdentity {
            Objects.requireNonNull(nodeKey, "nodeKey");
            Objects.requireNonNull(tlsIdentity, "tlsIdentity");
        }
        @Override public String toString() { return "LocalIdentity[<redacted>]"; }
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
