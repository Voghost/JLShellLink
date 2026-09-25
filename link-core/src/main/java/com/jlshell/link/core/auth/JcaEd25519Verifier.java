package com.jlshell.link.core.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;
import java.util.Set;

final class JcaEd25519Verifier implements JWSVerifier {
    private final PublicKey key;
    private final JCAContext context = new JCAContext();

    JcaEd25519Verifier(PublicKey key) {
        this.key = Objects.requireNonNull(key, "key");
    }

    @Override public Set<JWSAlgorithm> supportedJWSAlgorithms() { return Set.of(JWSAlgorithm.Ed25519); }
    @Override public JCAContext getJCAContext() { return context; }

    @Override
    public boolean verify(JWSHeader header, byte[] signingInput, Base64URL signatureValue)
            throws JOSEException {
        if (!JWSAlgorithm.Ed25519.equals(header.getAlgorithm())) return false;
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(key);
            signature.update(signingInput);
            return signature.verify(signatureValue.decode());
        } catch (java.security.GeneralSecurityException error) {
            throw new JOSEException("Ed25519 verification failed", error);
        }
    }
}
