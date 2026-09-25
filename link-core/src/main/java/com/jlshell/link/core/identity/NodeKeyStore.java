package com.jlshell.link.core.identity;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Optional;

public interface NodeKeyStore {
    Optional<Ed25519NodeKey> load() throws IOException, GeneralSecurityException;
    void store(Ed25519NodeKey key) throws IOException;
}
