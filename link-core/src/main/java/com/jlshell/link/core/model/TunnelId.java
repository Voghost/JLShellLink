package com.jlshell.link.core.model;

import java.util.Objects;
import java.util.UUID;

public record TunnelId(UUID value) {
    public TunnelId {
        Objects.requireNonNull(value, "value");
    }

    public static TunnelId random() {
        return new TunnelId(UUID.randomUUID());
    }

    public static TunnelId parse(String value) {
        return new TunnelId(UUID.fromString(value));
    }

    @Override public String toString() { return value.toString(); }
}
