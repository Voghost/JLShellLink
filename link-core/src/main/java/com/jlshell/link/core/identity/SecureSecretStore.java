package com.jlshell.link.core.identity;

import java.io.IOException;
import java.util.Optional;

/** Adapter point for the desktop host's OS-backed secure storage. */
public interface SecureSecretStore {
    Optional<byte[]> read(String key) throws IOException;
    void write(String key, byte[] secret) throws IOException;
}
