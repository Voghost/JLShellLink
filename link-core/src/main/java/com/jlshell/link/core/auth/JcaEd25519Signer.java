package com.jlshell.link.core.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Objects;
import java.util.Set;

final class JcaEd25519Signer implements JWSSigner {
    private final PrivateKey key;
    private final JCAContext context = new JCAContext();

    JcaEd25519Signer(PrivateKey key) {
        this.key = Objects.requireNonNull(key, "key");
    }

    @Override public Set<JWSAlgorithm> supportedJWSAlgorithms() { return Set.of(JWSAlgorithm.Ed25519); }
    @Override public JCAContext getJCAContext() { return context; }

    @Override
    public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
        if (!JWSAlgorithm.Ed25519.equals(header.getAlgorithm())) {
            throw new JOSEException("Only Ed25519 is allowed");
        }
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key);
            signature.update(signingInput);
            return Base64URL.encode(signature.sign());
        } catch (java.security.GeneralSecurityException error) {
            throw new JOSEException("Ed25519 signing failed", error);
        }
    }
}
