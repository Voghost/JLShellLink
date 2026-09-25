package com.jlshell.link.core.model;

import java.util.Objects;
import java.util.Set;

public record AccessRule(Effect effect, CidrBlock network, Set<Integer> ports) {
    public enum Effect { ALLOW, DENY }

    public AccessRule {
        Objects.requireNonNull(effect, "effect");
        Objects.requireNonNull(network, "network");
        ports = Set.copyOf(Objects.requireNonNull(ports, "ports"));
        if (ports.stream().anyMatch(port -> port == null || port < 1 || port > 65_535)) {
            throw new IllegalArgumentException("Rule ports must be between 1 and 65535");
        }
    }

    public boolean matches(TargetEndpoint target) {
        return network.contains(target.address()) && (ports.isEmpty() || ports.contains(target.port()));
    }
}
