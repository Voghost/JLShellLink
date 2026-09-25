package com.jlshell.link.core.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.jlshell.link.core.ProtocolVersion;
import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.model.AccessGrant;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.TargetEndpoint;
import java.net.URI;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AccessGrantJwsServiceTest {
    private static final Instant NOW = Instant.parse("2026-09-24T08:00:00Z");
    private Ed25519NodeKey signingKey;
    private AccessGrant grant;
    private GrantValidationContext expected;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = Ed25519NodeKey.generate();
        Ed25519NodeKey client = Ed25519NodeKey.generate();
        Ed25519NodeKey agent = Ed25519NodeKey.generate();
        UUID agentId = UUID.randomUUID();
        TargetEndpoint target = new TargetEndpoint("192.168.31.20", 22);
        grant = new AccessGrant(URI.create("https://link.example.test"), "jlshell-link-agent",
                UUID.randomUUID(), client.fingerprint(), agentId, agent.fingerprint(), target,
                Set.of("tcp-connect"), 7, "ticket-1", NOW, NOW.minusSeconds(1),
                NOW.plusSeconds(60), ProtocolVersion.V2);
        expected = new GrantValidationContext(grant.issuer(), grant.audience(),
                grant.clientKeyFingerprint(), agentId, grant.agentKeyFingerprint(), target, ProtocolVersion.V2);
    }

    @Test
    void verifiesAllBindingsAndRejectsReplay() throws Exception {
        AccessGrantJwsService service = service();
        String ticket = service.issue(grant, "signing-key-1", signingKey.privateKey());
        SigningKeyResolver keys = keyId -> keyId.equals("signing-key-1")
                ? Optional.of(signingKey.publicKey()) : Optional.empty();

        assertEquals(grant, service.validate(ticket, expected, keys));
        TicketValidationException replay = assertThrows(TicketValidationException.class,
                () -> service.validate(ticket, expected, keys));
        assertEquals(TicketValidationException.Reason.REPLAY, replay.reason());
    }

    @Test
    void rejectsTargetAndNodeMismatchBeforeConsumption() throws Exception {
        AccessGrantJwsService service = service();
        String ticket = service.issue(grant, "signing-key-1", signingKey.privateKey());
        SigningKeyResolver keys = ignored -> Optional.of(signingKey.publicKey());
        GrantValidationContext wrongTarget = new GrantValidationContext(expected.issuer(), expected.audience(),
                expected.clientKeyFingerprint(), expected.agentId(), expected.agentKeyFingerprint(),
                new TargetEndpoint("192.168.31.21", 22), ProtocolVersion.V2);
        TicketValidationException mismatch = assertThrows(TicketValidationException.class,
                () -> service.validate(ticket, wrongTarget, keys));
        assertEquals(TicketValidationException.Reason.TARGET, mismatch.reason());
        assertEquals(grant, service.validate(ticket, expected, keys));
    }

    @Test
    void rejectsUnknownKeyAndExpiredGrant() throws Exception {
        AccessGrantJwsService service = service();
        String ticket = service.issue(grant, "signing-key-1", signingKey.privateKey());
        TicketValidationException unknown = assertThrows(TicketValidationException.class,
                () -> service.validate(ticket, expected, ignored -> Optional.empty()));
        assertEquals(TicketValidationException.Reason.KEY, unknown.reason());

        AccessGrantJwsService later = new AccessGrantJwsService(
                Clock.fixed(NOW.plusSeconds(70), ZoneOffset.UTC), Duration.ZERO, new InMemoryReplayStore());
        TicketValidationException expired = assertThrows(TicketValidationException.class,
                () -> later.validate(ticket, expected, ignored -> Optional.of(signingKey.publicKey())));
        assertEquals(TicketValidationException.Reason.TIME, expired.reason());
    }

    @Test
    void fingerprintMismatchCannotChangePathAuthorization() throws Exception {
        AccessGrantJwsService service = service();
        String ticket = service.issue(grant, "signing-key-1", signingKey.privateKey());
        NodeKeyFingerprint another = Ed25519NodeKey.generate().fingerprint();
        GrantValidationContext wrongClient = new GrantValidationContext(expected.issuer(), expected.audience(),
                another, expected.agentId(), expected.agentKeyFingerprint(), expected.target(), ProtocolVersion.V2);
        TicketValidationException mismatch = assertThrows(TicketValidationException.class,
                () -> service.validate(ticket, wrongClient, ignored -> Optional.of(signingKey.publicKey())));
        assertEquals(TicketValidationException.Reason.IDENTITY, mismatch.reason());
    }

    @Test
    void rejectsAlgorithmAndAudienceConfusion() throws Exception {
        AccessGrantJwsService service = service();
        String ticket = service.issue(grant, "signing-key-1", signingKey.privateKey());
        String wrongHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"kid\":\"signing-key-1\",\"typ\":\"JWT\",\"alg\":\"EdDSA\"}"
                        .getBytes(StandardCharsets.UTF_8));
        String changedAlgorithm = wrongHeader + ticket.substring(ticket.indexOf('.'));
        TicketValidationException algorithm = assertThrows(TicketValidationException.class,
                () -> service.validate(changedAlgorithm, expected,
                        ignored -> Optional.of(signingKey.publicKey())));
        assertEquals(TicketValidationException.Reason.ALGORITHM, algorithm.reason());

        GrantValidationContext wrongAudience = new GrantValidationContext(expected.issuer(), "another-service",
                expected.clientKeyFingerprint(), expected.agentId(), expected.agentKeyFingerprint(),
                expected.target(), ProtocolVersion.V2);
        TicketValidationException audience = assertThrows(TicketValidationException.class,
                () -> service.validate(ticket, wrongAudience,
                        ignored -> Optional.of(signingKey.publicKey())));
        assertEquals(TicketValidationException.Reason.AUDIENCE, audience.reason());
    }

    @Test
    void validatesPublishedFixedVector() throws Exception {
        Properties vector = new Properties();
        try (var input = getClass().getResourceAsStream("/vectors/access-grant-v2.properties")) {
            vector.load(input);
        }
        PublicKey publicKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(
                Base64.getDecoder().decode(vector.getProperty("publicKeyX509Base64"))));
        assertEquals(vector.getProperty("fingerprint"), NodeKeyFingerprint.from(publicKey).value());
        GrantValidationContext vectorContext = new GrantValidationContext(
                URI.create("https://link.example.test"), "jlshell-link-agent",
                new NodeKeyFingerprint("1".repeat(64)),
                UUID.fromString("22222222-2222-2222-2222-222222222222"),
                new NodeKeyFingerprint("2".repeat(64)),
                new TargetEndpoint("192.168.31.20", 22), ProtocolVersion.V2);
        AccessGrant validated = service().validate(vector.getProperty("compactJws"), vectorContext,
                keyId -> keyId.equals("vector-ed25519-1") ? Optional.of(publicKey) : Optional.empty());
        assertEquals("vector-ticket-1", validated.jti());
    }

    private static AccessGrantJwsService service() {
        return new AccessGrantJwsService(Clock.fixed(NOW, ZoneOffset.UTC),
                Duration.ofSeconds(5), new InMemoryReplayStore());
    }
}
