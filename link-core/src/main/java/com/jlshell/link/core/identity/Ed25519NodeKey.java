package com.jlshell.link.core.identity;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;

public final class Ed25519NodeKey implements LocalNodeKey {
    private final KeyPair keyPair;

    public Ed25519NodeKey(KeyPair keyPair) {
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
        boolean publicEd25519 = "EdDSA".equals(keyPair.getPublic().getAlgorithm())
                || "Ed25519".equals(keyPair.getPublic().getAlgorithm());
        boolean privateEd25519 = "EdDSA".equals(keyPair.getPrivate().getAlgorithm())
                || "Ed25519".equals(keyPair.getPrivate().getAlgorithm());
        if (!publicEd25519 || !privateEd25519) {
            throw new IllegalArgumentException("Node key must use Ed25519");
        }
        try {
            byte[] check = "jlshell-link-key-pair-check".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyPair.getPrivate());
            signer.update(check);
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(keyPair.getPublic());
            verifier.update(check);
            if (!verifier.verify(signer.sign())) throw new IllegalArgumentException("Node key pair does not match");
        } catch (GeneralSecurityException error) {
            throw new IllegalArgumentException("Node key pair cannot be validated", error);
        }
    }

    public static Ed25519NodeKey generate() throws GeneralSecurityException {
        return new Ed25519NodeKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
    }

    @Override public PublicKey publicKey() { return keyPair.getPublic(); }
    @Override public PrivateKey privateKey() { return keyPair.getPrivate(); }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey());
        signature.update(Objects.requireNonNull(message, "message"));
        return signature.sign();
    }
}
