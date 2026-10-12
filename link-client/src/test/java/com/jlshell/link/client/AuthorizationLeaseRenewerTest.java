package com.jlshell.link.client;

import static org.junit.jupiter.api.Assertions.*;

import com.jlshell.link.core.model.ConnectPolicy;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class AuthorizationLeaseRenewerTest {
    private static final Instant NOW = Instant.parse("2026-10-12T00:00:00Z");

    @Test void renewsTheSameTunnelBeyondItsOriginalLeaseAndStopsOnClose() {
        var grant = grant();
        var clock = new MutableClock();
        var calls = new AtomicInteger();
        var failures = new AtomicInteger();
        var scheduler = Executors.newSingleThreadScheduledExecutor();
        var provider = provider(() -> {
            calls.incrementAndGet();
            return CompletableFuture.completedFuture(new ReauthorizingConnectionFlow.RenewedAuthorization(
                    grant.sessionId(), grant.tunnelId(), clock.instant().plusSeconds(300), 7));
        });
        try (var renewal = new AuthorizationLeaseRenewer(grant, provider, scheduler, clock,
                failures::incrementAndGet)) {
            renewal.start();
            clock.now = NOW.plusSeconds(60);
            renewal.renew();
            clock.now = NOW.plusSeconds(301);
            renewal.renew();
            assertEquals(2, calls.get());
            assertEquals(0, failures.get());
            renewal.close();
            renewal.renew();
            assertEquals(2, calls.get());
        } finally { scheduler.shutdownNow(); }
    }

    @Test void rejectsFailedRenewalWithoutTryingAnotherDataPath() {
        var failures = new AtomicInteger();
        var scheduler = Executors.newSingleThreadScheduledExecutor();
        try (var renewal = new AuthorizationLeaseRenewer(grant(),
                provider(() -> CompletableFuture.failedFuture(new SecurityException("denied"))),
                scheduler, new MutableClock(), failures::incrementAndGet)) {
            renewal.start();
            renewal.renew();
            renewal.renew();
            assertEquals(1, failures.get());
        } finally { scheduler.shutdownNow(); }
    }

    @Test void rejectsMismatchedIdentitiesRollbackAndNonExtendingLease() {
        var grant = grant();
        for (var value : new ReauthorizingConnectionFlow.RenewedAuthorization[] {
                new ReauthorizingConnectionFlow.RenewedAuthorization(LinkSessionId.random(),
                        grant.tunnelId(), NOW.plusSeconds(600), 7),
                new ReauthorizingConnectionFlow.RenewedAuthorization(grant.sessionId(),
                        TunnelId.random(), NOW.plusSeconds(600), 7),
                new ReauthorizingConnectionFlow.RenewedAuthorization(grant.sessionId(),
                        grant.tunnelId(), NOW.plusSeconds(600), 6),
                new ReauthorizingConnectionFlow.RenewedAuthorization(grant.sessionId(),
                        grant.tunnelId(), NOW.plusSeconds(300), 7) }) {
            var failures = new AtomicInteger();
            var scheduler = Executors.newSingleThreadScheduledExecutor();
            try (var renewal = new AuthorizationLeaseRenewer(grant,
                    provider(() -> CompletableFuture.completedFuture(value)), scheduler,
                    new MutableClock(), failures::incrementAndGet)) {
                renewal.start();
                renewal.renew();
                assertEquals(1, failures.get());
            } finally { scheduler.shutdownNow(); }
        }
    }

    @Test void doesNotOverlapRequestsOrAcceptAResponseAfterExpiry() {
        var grant = grant();
        var clock = new MutableClock();
        var calls = new AtomicInteger();
        var failures = new AtomicInteger();
        var response = new CompletableFuture<ReauthorizingConnectionFlow.RenewedAuthorization>();
        var scheduler = Executors.newSingleThreadScheduledExecutor();
        try (var renewal = new AuthorizationLeaseRenewer(grant,
                provider(() -> { calls.incrementAndGet(); return response; }), scheduler, clock,
                failures::incrementAndGet)) {
            renewal.start();
            renewal.renew();
            renewal.renew();
            assertEquals(1, calls.get());
            clock.now = NOW.plusSeconds(301);
            response.complete(new ReauthorizingConnectionFlow.RenewedAuthorization(grant.sessionId(),
                    grant.tunnelId(), NOW.plusSeconds(600), 7));
            assertEquals(1, failures.get());
            renewal.renew();
            assertEquals(1, calls.get());
        } finally { scheduler.shutdownNow(); }
    }

    private static ReauthorizingConnectionFlow.AuthorizedTunnel grant() {
        return new ReauthorizingConnectionFlow.AuthorizedTunnel(LinkSessionId.random(), TunnelId.random(),
                UUID.randomUUID(), new TargetEndpoint("192.0.2.1", 22), "test-ticket",
                NOW.plusSeconds(30), NOW.plusSeconds(300), 7);
    }

    private static ReauthorizingConnectionFlow.AccessRequestProvider provider(
            Supplier<CompletionStage<ReauthorizingConnectionFlow.RenewedAuthorization>> response) {
        return new ReauthorizingConnectionFlow.AccessRequestProvider() {
            @Override public CompletionStage<ReauthorizingConnectionFlow.AuthorizedTunnel> request(
                    Optional<LinkSessionId> reuse, UUID agent, TargetEndpoint target, ConnectPolicy policy) {
                return CompletableFuture.failedFuture(new UnsupportedOperationException());
            }
            @Override public CompletionStage<ReauthorizingConnectionFlow.RenewedAuthorization> renewAuthorization(
                    LinkSessionId session, TunnelId tunnel) { return response.get(); }
        };
    }

    private static final class MutableClock extends Clock {
        private Instant now = NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
