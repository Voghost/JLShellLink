package com.jlshell.link.core.identity;

import com.jlshell.link.core.model.NodeKeyFingerprint;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface LocalNodeKey {
    PublicKey publicKey();
    PrivateKey privateKey();

    default NodeKeyFingerprint fingerprint() {
        return NodeKeyFingerprint.from(publicKey());
    }

    byte[] sign(byte[] message) throws GeneralSecurityException;
}
