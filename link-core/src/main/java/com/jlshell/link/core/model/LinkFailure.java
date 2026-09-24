package com.jlshell.link.core.model;

import java.util.Objects;

public final class LinkFailure extends Exception {
    public enum Category {
        DIRECT_TIMEOUT(true),
        TRANSIENT_NETWORK(true),
        AUTHORIZATION(false),
        IDENTITY(false),
        PROTOCOL(false),
        QUOTA(false),
        CANCELLED(false);

        private final boolean retryableAcrossPath;

        Category(boolean retryableAcrossPath) {
            this.retryableAcrossPath = retryableAcrossPath;
        }

        public boolean retryableAcrossPath() {
            return retryableAcrossPath;
        }
    }

    private final String code;
    private final Category category;

    public LinkFailure(String code, Category category, String message) {
        super(message);
        if (code == null || code.isBlank()) throw new IllegalArgumentException("Failure code is required");
        this.code = code;
        this.category = Objects.requireNonNull(category, "category");
    }

    public String code() { return code; }
    public Category category() { return category; }
    public boolean retryableAcrossPath() { return category.retryableAcrossPath(); }
}
