package com.jlshell.link.core.model;

import java.util.List;
import java.util.Objects;

public record AccessPolicy(boolean enabled, boolean allowLoopback, long version, List<AccessRule> rules) {
    public AccessPolicy {
        if (version < 1) throw new IllegalArgumentException("Policy version must be positive");
        rules = List.copyOf(Objects.requireNonNull(rules, "rules"));
    }
}
