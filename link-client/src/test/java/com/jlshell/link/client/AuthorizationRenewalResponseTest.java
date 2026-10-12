package com.jlshell.link.client;

import static org.junit.jupiter.api.Assertions.*;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TunnelId;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AuthorizationRenewalResponseTest {
    @Test void cancelsAnOversizedResponseBeforeBufferingIt() {
        var cancelled = new java.util.concurrent.atomic.AtomicBoolean();
        var body = WebsiteAccessRequestProvider.limitedBodySubscriber();
        body.onSubscribe(new java.util.concurrent.Flow.Subscription() {
            @Override public void request(long count) { }
            @Override public void cancel() { cancelled.set(true); }
        });
        body.onNext(java.util.List.of(java.nio.ByteBuffer.allocate(65_537)));
        assertTrue(cancelled.get());
        assertThrows(java.util.concurrent.CompletionException.class,
                () -> body.getBody().toCompletableFuture().join());
    }

    @Test void bindsRenewalResponseToTheRequestedSessionAndTunnel() throws Exception {
        var session = LinkSessionId.random();
        var tunnel = TunnelId.random();
        var body = Map.<String, Object>of("sessionId", session.toString(), "tunnelId", tunnel.toString(),
                "authorizationLeaseExpiresAt", "2026-10-12T01:00:00Z", "policyVersion", 7L);
        assertEquals(7L, WebsiteAccessRequestProvider.parseRenewal(session, tunnel, body).policyVersion());
        assertThrows(SecurityException.class, () -> WebsiteAccessRequestProvider.parseRenewal(
                LinkSessionId.random(), tunnel, body));
        assertThrows(SecurityException.class, () -> WebsiteAccessRequestProvider.parseRenewal(
                session, TunnelId.random(), body));
    }
}
