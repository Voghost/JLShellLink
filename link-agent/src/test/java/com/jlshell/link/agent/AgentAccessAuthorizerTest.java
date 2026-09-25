package com.jlshell.link.agent;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jlshell.link.core.ProtocolVersion;
import com.jlshell.link.core.auth.AccessGrantJwsService;
import com.jlshell.link.core.auth.InMemoryReplayStore;
import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.model.AccessGrant;
import com.jlshell.link.core.model.AccessPolicy;
import com.jlshell.link.core.model.AccessRule;
import com.jlshell.link.core.model.CidrBlock;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.ConnectStreamMultiplexer;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.Test;

class AgentAccessAuthorizerTest {
    private static final Instant NOW = Instant.parse("2026-09-25T07:30:00Z");
    private static final URI ISSUER = URI.create("https://link.example.test");

    @Test
    void acceptsFreshBoundTicketOnceAndRejectsReplay() throws Exception {
        Fixture fixture = new Fixture(7, NOW.plusSeconds(60), AccessPolicyEvaluatorFixture.ALLOW_10_20);
        var authorizer = fixture.authorizer();
        ConnectStreamMultiplexer.AuthorizationRequest request = fixture.request("10.20.30.41", 22);

        assertTrue(authorizer.authorize(request).toCompletableFuture().join());
        assertFalse(authorizer.authorize(request).toCompletableFuture().join());
    }

    @Test
    void rejectsStalePolicyExpiredLeaseAndLocalAclBeforeAnyTargetConnect() throws Exception {
        Fixture stale = new Fixture(8, NOW.plusSeconds(60), AccessPolicyEvaluatorFixture.ALLOW_10_20);
        assertFalse(stale.authorizer().authorize(stale.request("10.20.30.41", 22))
                .toCompletableFuture().join());

        Fixture expired = new Fixture(7, NOW.minusSeconds(1), AccessPolicyEvaluatorFixture.ALLOW_10_20);
        assertFalse(expired.authorizer().authorize(expired.request("10.20.30.41", 22))
                .toCompletableFuture().join());

        Fixture localDenied = new Fixture(7, NOW.plusSeconds(60), AccessPolicyEvaluatorFixture.DENY_ALL);
        assertFalse(localDenied.authorizer().authorize(localDenied.request("10.20.30.41", 22))
                .toCompletableFuture().join());
    }

    @Test
    void separateTunnelLeaseExpiresEvenWhileAgentControlLeaseRemainsOnline() throws Exception {
        Fixture fixture = new Fixture(7, NOW.plusSeconds(600), AccessPolicyEvaluatorFixture.ALLOW_10_20);
        AgentAccessAuthorizer authorizer = fixture.authorizer(
                NOW.plusSeconds(600), NOW.minusSeconds(1));

        assertFalse(authorizer.authorize(fixture.request("10.20.30.41", 22)).toCompletableFuture().join());

        authorizer.updateAuthorizationLease(NOW.plusSeconds(120));
        assertTrue(authorizer.authorize(fixture.request("10.20.30.41", 22)).toCompletableFuture().join());
    }

    private static final class Fixture {
        private final Ed25519NodeKey authority;
        private final Ed25519NodeKey client;
        private final Ed25519NodeKey agent;
        private final UUID agentId = UUID.randomUUID();
        private final LinkSessionId session = LinkSessionId.random();
        private final TunnelId tunnel = TunnelId.random();
        private final TargetEndpoint target = new TargetEndpoint("10.20.30.41", 22);
        private final String ticket;
        private final long version;
        private final Instant leaseUntil;
        private final AccessPolicy localPolicy;

        private Fixture(long version, Instant leaseUntil, AccessPolicy localPolicy) throws Exception {
            authority = Ed25519NodeKey.generate();
            client = Ed25519NodeKey.generate();
            agent = Ed25519NodeKey.generate();
            this.version = version;
            this.leaseUntil = leaseUntil;
            this.localPolicy = localPolicy;
            AccessGrant grant = new AccessGrant(ISSUER, "jlshell-link-agent", UUID.randomUUID(), session, tunnel,
                    client.fingerprint(), agentId, agent.fingerprint(), target, Set.of("tcp-connect"), 7,
                    "jti-" + UUID.randomUUID(), NOW, NOW.minusSeconds(1), NOW.plusSeconds(120), ProtocolVersion.V2);
            ticket = grants().issue(grant, "website-key-1", authority.privateKey());
        }

        private AccessGrantJwsService grants() {
            return new AccessGrantJwsService(Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO,
                    new InMemoryReplayStore());
        }

        private AgentAccessAuthorizer authorizer() {
            return authorizer(leaseUntil, leaseUntil);
        }

        private AgentAccessAuthorizer authorizer(Instant controlLeaseUntil, Instant accessLeaseUntil) {
            AccessGrantJwsService grants = grants();
            return new AgentAccessAuthorizer(ISSUER,
                    new AgentAccessAuthorizer.UUIDBinding(session, agentId,
                            client.fingerprint(), agent.fingerprint()), grants,
                    keyId -> keyId.equals("website-key-1") ? Optional.of(authority.publicKey()) : Optional.empty(),
                    localPolicy, new AgentLeaseSnapshot(agentId, agent.fingerprint(), version,
                            controlLeaseUntil, false), accessLeaseUntil,
                    Clock.fixed(NOW, ZoneOffset.UTC), Runnable::run, ignored -> { });
        }

        private ConnectStreamMultiplexer.AuthorizationRequest request(String targetIp, int port) {
            return new ConnectStreamMultiplexer.AuthorizationRequest(new TargetEndpoint(targetIp, port), tunnel,
                    ticket);
        }
    }

    private static final class AccessPolicyEvaluatorFixture {
        private static final AccessPolicy ALLOW_10_20 = new AccessPolicy(true, false, 1,
                List.of(new AccessRule(AccessRule.Effect.ALLOW, CidrBlock.parse("10.20.0.0/16"), Set.of(22))));
        private static final AccessPolicy DENY_ALL = new AccessPolicy(false, false, 1, List.of());
    }
}
