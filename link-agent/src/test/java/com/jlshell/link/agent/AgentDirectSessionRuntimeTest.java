package com.jlshell.link.agent;

import static org.junit.jupiter.api.Assertions.*;

import com.jlshell.link.core.auth.AccessGrantJwsService;
import com.jlshell.link.core.auth.InMemoryReplayStore;
import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.model.AccessPolicy;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.signal.ControlSignal;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.Ice4jDirectSession;
import com.jlshell.link.transport.TlsHandshakeGate;
import io.netty.channel.DefaultEventLoopGroup;
import java.net.URI;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;

/** Exercises invitation lease handling without starting an ICE network transport. */
class AgentDirectSessionRuntimeTest {
    @Test
    void sameGenerationRenewalExtendsLeaseAndCancelsOldDeadline() throws Exception {
        try (Fixture f = new Fixture()) {
            var first = f.invite(90, f.clientId, 4);
            f.runtime.acceptInvite(first, f.signaling);
            Object session = f.session();
            ScheduledFuture<?> old = f.expiry(session);
            f.runtime.acceptInvite(f.invite(180, f.clientId, 4), f.signaling);
            assertSame(session, f.session());
            assertEquals(f.now.plusSeconds(180), f.deadline(session));
            assertTrue(old.isCancelled());
            assertFalse(f.expiry(session).isCancelled());
            f.runtime.closeSession(f.sessionId);
            assertTrue(f.expiry(session).isCancelled());
        }
    }

    @Test
    void rejectsIdentityPolicyAndDeadlineRollback() throws Exception {
        try (Fixture f = new Fixture()) {
            f.runtime.acceptInvite(f.invite(90, f.clientId, 4), f.signaling);
            Object session = f.session();
            var expiry = f.expiry(session);
            f.runtime.acceptInvite(f.invite(180, UUID.randomUUID(), 4), f.signaling);
            f.runtime.acceptInvite(f.invite(180, f.clientId, 5), f.signaling);
            f.runtime.acceptInvite(f.invite(60, f.clientId, 4), f.signaling);
            assertEquals(f.now.plusSeconds(90), f.deadline(session));
            assertSame(expiry, f.expiry(session));
        }
    }

    @Test
    void renewalDoesNotResurrectExpiredSession() throws Exception {
        try (Fixture f = new Fixture()) {
            f.runtime.acceptInvite(f.invite(90, f.clientId, 4), f.signaling);
            Object session = f.session();
            f.clock.now = f.now.plusSeconds(91);
            f.runtime.acceptInvite(f.invite(180, f.clientId, 4), f.signaling);
            assertEquals(f.now.plusSeconds(90), f.deadline(session));
        }
    }

    private static Object field(Object owner, String name) throws Exception {
        var field = owner.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(owner);
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-10-12T00:00:00Z");
        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    private static final class Fixture implements AutoCloseable {
        private final MutableClock clock = new MutableClock();
        private final Instant now = clock.instant();
        private final UUID agentId = UUID.randomUUID(), clientId = UUID.randomUUID();
        private final LinkSessionId sessionId = LinkSessionId.random();
        private final Ed25519NodeKey agent = Ed25519NodeKey.generate(), client = Ed25519NodeKey.generate();
        private final DefaultEventLoopGroup loops = new DefaultEventLoopGroup(1);
        private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        private final AgentControlSignalClient signaling;
        private final AgentDirectSessionRuntime runtime;

        private Fixture() throws Exception {
            signaling = new AgentControlSignalClient(URI.create("wss://link.example.test/link/v2/control"),
                    agentId, agent, "test-credential", SSLContext.getDefault(), ignored -> {}, ignored -> {}, ignored -> {});
            var budget = new TransportBudget(65536, 8192, 8, 65536, 65536, 262144, 2, Duration.ofSeconds(5));
            runtime = new AgentDirectSessionRuntime(URI.create("https://link.example.test"), agentId, agent,
                    ignored -> null, () -> new AccessPolicy(false, false, 1, List.of()),
                    new AgentLeaseSnapshot(agentId, agent.fingerprint(), 4, now.plusSeconds(600), false),
                    loops, loops, ignored -> {}, scheduler,
                    new AccessGrantJwsService(clock, Duration.ZERO, new InMemoryReplayStore()),
                    ignored -> Optional.empty(), budget,
                    new Ice4jDirectSession.Config(List.of(), 8, Duration.ofSeconds(5), 1500, 100),
                    new TlsHandshakeGate(2), clock, ignored -> {});
        }

        private ControlSignal.SessionInvite invite(long seconds, UUID device, long policy) {
            return new ControlSignal.SessionInvite(UUID.randomUUID(), sessionId, 1, agentId, device,
                    agent.fingerprint(), client.fingerprint(), policy, now.plusSeconds(seconds), true, false);
        }
        private Object session() throws Exception { return ((Map<?, ?>) field(runtime, "active")).get(sessionId); }
        private Instant deadline(Object session) throws Exception { return (Instant) field(session, "authorizationExpiresAt"); }
        private ScheduledFuture<?> expiry(Object session) throws Exception { return (ScheduledFuture<?>) field(session, "expires"); }
        @Override public void close() {
            runtime.close();
            signaling.close();
            scheduler.shutdownNow();
            loops.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
        }
    }
}
