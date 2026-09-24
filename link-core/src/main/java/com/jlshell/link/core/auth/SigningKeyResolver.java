package com.jlshell.link.core.auth;

import java.security.PublicKey;
import java.util.Optional;

@FunctionalInterface
public interface SigningKeyResolver {
    Optional<PublicKey> resolve(String keyId);
}
