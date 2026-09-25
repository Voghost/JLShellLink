package com.jlshell.link.core.auth;

public final class TicketValidationException extends Exception {
    public enum Reason {
        MALFORMED,
        ALGORITHM,
        KEY,
        SIGNATURE,
        ISSUER,
        AUDIENCE,
        TIME,
        PROTOCOL,
            IDENTITY,
            TARGET,
            POLICY,
            REPLAY
    }

    private final Reason reason;

    public TicketValidationException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public TicketValidationException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() { return reason; }
}
