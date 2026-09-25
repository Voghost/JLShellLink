package com.jlshell.link.core.identity;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

public final class NodeProofService {
    public byte[] sign(LocalNodeKey key, NodeProofContext context, byte[] challenge)
            throws GeneralSecurityException {
        return Objects.requireNonNull(key, "key").sign(
                Objects.requireNonNull(context, "context").signingInput(challenge));
    }

    public boolean verify(PublicKey key, NodeProofContext context, byte[] challenge, byte[] proof)
            throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(Objects.requireNonNull(key, "key"));
        verifier.update(Objects.requireNonNull(context, "context").signingInput(challenge));
        return verifier.verify(Objects.requireNonNull(proof, "proof"));
    }
}
