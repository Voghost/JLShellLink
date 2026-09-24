package com.jlshell.link.core.model;

import java.util.Objects;
import java.util.UUID;

public record LinkSessionId(UUID value) {
    public LinkSessionId {
        Objects.requireNonNull(value, "value");
    }

    public static LinkSessionId random() {
        return new LinkSessionId(UUID.randomUUID());
    }

    public static LinkSessionId parse(String value) {
        return new LinkSessionId(UUID.fromString(value));
    }

    @Override public String toString() { return value.toString(); }
}
