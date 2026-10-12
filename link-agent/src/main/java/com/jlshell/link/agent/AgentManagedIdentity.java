package com.jlshell.link.agent;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.*;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Automatically prepares/renews the C certificate using the existing node key. */
final class AgentManagedIdentity {
    private AgentManagedIdentity() { }

    static void ensure(AgentIdentityStore store) throws Exception {
        Path root = store.directory();
        AgentPrivateFiles.directory(root);
        if (store.loadRegistration().isPresent() && store.loadKey().isEmpty()) {
            throw new IOException("已注册节点缺少原私钥，请恢复备份；不会生成新身份");
        }
        var key = store.loadOrCreateKey();
        Path passwordFile = AgentProfile.password(root);
        char[] password;
        if (Files.exists(AgentProfile.identity(root), LinkOption.NOFOLLOW_LINKS)
                && !Files.exists(passwordFile, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("托管身份缺少密码文件，请恢复原文件；不会覆盖现有身份");
        }
        if (Files.exists(passwordFile, LinkOption.NOFOLLOW_LINKS)) {
            AgentPrivateFiles.regular(passwordFile);
            password = AgentRuntimeService.readOwnerOnly(passwordFile);
        } else {
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            password = Base64.getUrlEncoder().withoutPadding().encodeToString(random).toCharArray();
            Arrays.fill(random, (byte) 0);
            byte[] encoded = new String(password).getBytes(StandardCharsets.US_ASCII);
            try { AgentPrivateFiles.write(passwordFile, encoded); }
            finally { Arrays.fill(encoded, (byte) 0); }
        }
        try {
            Path file = AgentProfile.identity(root);
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                AgentPrivateFiles.regular(file);
                KeyStore previous = KeyStore.getInstance("PKCS12");
                try (var input = Files.newInputStream(file)) { previous.load(input, password); }
                if (previous.size() != 1 || !previous.isKeyEntry("agent") ||
                        !(previous.getCertificate("agent") instanceof X509Certificate certificate) ||
                        !key.fingerprint().equals(com.jlshell.link.core.model.NodeKeyFingerprint.from(certificate.getPublicKey()))) {
                    throw new IOException("已有托管身份与节点不一致，请恢复原文件，不会重置已注册身份");
                }
                // Validate the private key too; expiration alone may be renewed using the same key.
                new com.jlshell.link.core.identity.Ed25519NodeKey(new KeyPair(certificate.getPublicKey(),
                        (PrivateKey) previous.getKey("agent", password)));
                certificate.verify(certificate.getPublicKey());
                if (certificate.getNotBefore().toInstant().isAfter(Instant.now().plusSeconds(300))) {
                    throw new IOException("节点证书尚未生效，请检查系统时间");
                }
                if (certificate.getNotAfter().toInstant().isAfter(Instant.now().plus(Duration.ofDays(30)))) return;
            }
            Instant now = Instant.now();
            X500Name subject = new X500Name("CN=JLShell Link Agent");
            BigInteger serial;
            do { serial = new BigInteger(159, new SecureRandom()); } while (serial.signum() == 0);
            var builder = new JcaX509v3CertificateBuilder(subject, serial, Date.from(now.minusSeconds(300)),
                    Date.from(now.plus(Duration.ofDays(365))), subject, key.publicKey());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
            var holder = builder.build(new JcaContentSignerBuilder("Ed25519").build(key.privateKey()));
            var certificate = new JcaX509CertificateConverter().getCertificate(holder);
            certificate.verify(key.publicKey());
            certificate.checkValidity();
            KeyStore p12 = KeyStore.getInstance("PKCS12");
            p12.load(null, password);
            p12.setKeyEntry("agent", key.privateKey(), password, new java.security.cert.Certificate[]{certificate});
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            p12.store(bytes, password);
            byte[] encoded = bytes.toByteArray();
            try { AgentPrivateFiles.write(file, encoded); }
            finally { Arrays.fill(encoded, (byte) 0); }
        } finally { Arrays.fill(password, '\0'); }
    }
}
