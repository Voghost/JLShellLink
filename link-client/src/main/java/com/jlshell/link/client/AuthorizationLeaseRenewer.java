package com.jlshell.link.client;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/** One outstanding renewal per tunnel; rejection or expiry closes the existing data path. */
final class AuthorizationLeaseRenewer implements AutoCloseable {
    private final ReauthorizingConnectionFlow.AuthorizedTunnel grant;
    private final ReauthorizingConnectionFlow.AccessRequestProvider access;
    private final ScheduledExecutorService scheduler;
    private final Clock clock;
    private final Runnable failed;
    private Instant expiresAt;
    private long policyVersion;
    private boolean closed;
    private ScheduledFuture<?> renewalTimer;
    private ScheduledFuture<?> expiryTimer;
    private CompletableFuture<?> pending;

    AuthorizationLeaseRenewer(ReauthorizingConnectionFlow.AuthorizedTunnel grant,
            ReauthorizingConnectionFlow.AccessRequestProvider access,
            ScheduledExecutorService scheduler, Clock clock, Runnable failed) {
        this.grant = Objects.requireNonNull(grant, "grant");
        this.access = Objects.requireNonNull(access, "access");
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.failed = Objects.requireNonNull(failed, "failed");
        expiresAt = grant.authorizationLeaseExpiresAt();
        policyVersion = grant.policyVersion();
    }

    synchronized void start() {
        if (closed || expiryTimer != null) return;
        arm();
    }

    private void arm() {
        long remaining = Duration.between(clock.instant(), expiresAt).toMillis();
        if (remaining <= 0) { fail(); return; }
        try {
            expiryTimer = scheduler.schedule(this::fail, remaining, TimeUnit.MILLISECONDS);
            renewalTimer = scheduler.schedule(this::renew,
                    Math.max(1, Math.min(60_000, remaining / 2)), TimeUnit.MILLISECONDS);
        } catch (RuntimeException unavailable) {
            fail();
        }
    }

    synchronized void renew() {
        if (closed || pending != null) return;
        if (!expiresAt.isAfter(clock.instant())) { fail(); return; }
        try {
            pending = Objects.requireNonNull(access.renewAuthorization(grant.sessionId(), grant.tunnelId()))
                    .toCompletableFuture();
            pending.whenComplete((value, error) -> complete(
                    (ReauthorizingConnectionFlow.RenewedAuthorization) value, error));
        } catch (RuntimeException unavailable) {
            fail();
        }
    }

    private synchronized void complete(ReauthorizingConnectionFlow.RenewedAuthorization value,
            Throwable error) {
        if (closed) return;
        pending = null;
        if (error != null || value == null || !expiresAt.isAfter(clock.instant())
                || !grant.sessionId().equals(value.sessionId())
                || !grant.tunnelId().equals(value.tunnelId())
                || !value.authorizationLeaseExpiresAt().isAfter(expiresAt)
                || value.policyVersion() < policyVersion) {
            fail();
            return;
        }
        renewalTimer.cancel(false);
        expiryTimer.cancel(false);
        expiresAt = value.authorizationLeaseExpiresAt();
        policyVersion = value.policyVersion();
        arm();
    }

    private synchronized void fail() {
        if (closed) return;
        close();
        failed.run();
    }

    @Override public synchronized void close() {
        if (closed) return;
        closed = true;
        if (renewalTimer != null) renewalTimer.cancel(false);
        if (expiryTimer != null) expiryTimer.cancel(false);
        if (pending != null) pending.cancel(true);
    }
}
