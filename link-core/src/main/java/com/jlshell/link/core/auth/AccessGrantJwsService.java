package com.jlshell.link.core.auth;

import com.jlshell.link.core.model.AccessGrant;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;

/** Issues and validates raw compact Ed25519 JWS access grants. */
public final class AccessGrantJwsService {
    private static final String ACCOUNT_ID = "accountId";
    private static final String CLIENT_KEY = "clientKeyFingerprint";
    private static final String SESSION_ID = "sessionId";
    private static final String TUNNEL_ID = "tunnelId";
    private static final String AGENT_ID = "agentId";
    private static final String AGENT_KEY = "agentKeyFingerprint";
    private static final String TARGET_IP = "targetIp";
    private static final String TARGET_PORT = "targetPort";
    private static final String CAPABILITIES = "capabilities";
    private static final String POLICY_VERSION = "policyVersion";
    private static final String PROTOCOL_VERSION = "protocolVersion";

    private final Clock clock;
    private final Duration clockSkew;
    private final ReplayStore replayStore;

    public AccessGrantJwsService(Clock clock, Duration clockSkew, ReplayStore replayStore) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew");
        if (clockSkew.isNegative() || clockSkew.compareTo(Duration.ofMinutes(2)) > 0) {
            throw new IllegalArgumentException("Clock skew must be between zero and two minutes");
        }
        this.replayStore = Objects.requireNonNull(replayStore, "replayStore");
    }

    public String issue(AccessGrant grant, String keyId, PrivateKey signingKey) throws JOSEException {
        Objects.requireNonNull(grant, "grant");
        if (keyId == null || keyId.isBlank()) throw new IllegalArgumentException("keyId is required");
        Objects.requireNonNull(signingKey, "signingKey");
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(grant.issuer().toString())
                .audience(grant.audience())
                .jwtID(grant.jti())
                .issueTime(Date.from(grant.issuedAt()))
                .notBeforeTime(Date.from(grant.notBefore()))
                .expirationTime(Date.from(grant.expiresAt()))
                .claim(ACCOUNT_ID, grant.accountId().toString())
                .claim(SESSION_ID, grant.sessionId().toString())
                .claim(TUNNEL_ID, grant.tunnelId().toString())
                .claim(CLIENT_KEY, grant.clientKeyFingerprint().value())
                .claim(AGENT_ID, grant.agentId().toString())
                .claim(AGENT_KEY, grant.agentKeyFingerprint().value())
                .claim(TARGET_IP, grant.target().address())
                .claim(TARGET_PORT, grant.target().port())
                .claim(CAPABILITIES, grant.capabilities().stream().sorted().toList())
                .claim(POLICY_VERSION, grant.policyVersion())
                .claim(PROTOCOL_VERSION, grant.protocolVersion())
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.Ed25519)
                .type(JOSEObjectType.JWT)
                .keyID(keyId)
                .build(), claims);
        jwt.sign(new JcaEd25519Signer(signingKey));
        return jwt.serialize();
    }

    public AccessGrant validate(
            String compactJws,
            GrantValidationContext expected,
            SigningKeyResolver keys) throws TicketValidationException {
        return validate(compactJws, expected, keys, ignored -> true);
    }

    /** Validate signature and bindings, run current policy checks, then atomically consume jti. */
    public AccessGrant validate(
            String compactJws,
            GrantValidationContext expected,
            SigningKeyResolver keys,
            Predicate<AccessGrant> beforeConsume) throws TicketValidationException {
        Objects.requireNonNull(expected, "expected");
        Objects.requireNonNull(keys, "keys");
        Objects.requireNonNull(beforeConsume, "beforeConsume");
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(Objects.requireNonNull(compactJws, "compactJws"));
        } catch (ParseException | RuntimeException error) {
            throw new TicketValidationException(TicketValidationException.Reason.MALFORMED,
                    "Access ticket is malformed", error);
        }
        if (!JWSAlgorithm.Ed25519.equals(jwt.getHeader().getAlgorithm())) {
            throw new TicketValidationException(TicketValidationException.Reason.ALGORITHM,
                    "Access ticket must use Ed25519");
        }
        String keyId = jwt.getHeader().getKeyID();
        if (keyId == null || keyId.isBlank()) {
            throw new TicketValidationException(TicketValidationException.Reason.KEY,
                    "Access ticket has no signing key id");
        }
        PublicKey key = keys.resolve(keyId).orElseThrow(() -> new TicketValidationException(
                TicketValidationException.Reason.KEY, "Access ticket signing key is unknown"));
        try {
            if (!jwt.verify(new JcaEd25519Verifier(key))) {
                throw new TicketValidationException(TicketValidationException.Reason.SIGNATURE,
                        "Access ticket signature is invalid");
            }
        } catch (JOSEException error) {
            throw new TicketValidationException(TicketValidationException.Reason.SIGNATURE,
                    "Access ticket signature verification failed", error);
        }

        AccessGrant grant = claims(jwt);
        validateContext(grant, expected);
        validateTime(grant);
        if (!beforeConsume.test(grant)) {
            throw new TicketValidationException(TicketValidationException.Reason.POLICY,
                    "Access ticket no longer matches current policy");
        }
        if (!replayStore.consume(grant.jti(), grant.expiresAt(), clock.instant())) {
            throw new TicketValidationException(TicketValidationException.Reason.REPLAY,
                    "Access ticket was already consumed");
        }
        return grant;
    }

    private AccessGrant claims(SignedJWT jwt) throws TicketValidationException {
        try {
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            List<String> audience = claims.getAudience();
            if (audience == null || audience.size() != 1) throw new ParseException("audience", 0);
            Date issued = required(claims.getIssueTime(), "iat");
            Date notBefore = required(claims.getNotBeforeTime(), "nbf");
            Date expires = required(claims.getExpirationTime(), "exp");
            Set<String> capabilities = new HashSet<>(required(
                    claims.getStringListClaim(CAPABILITIES), CAPABILITIES));
            return new AccessGrant(
                    URI.create(required(claims.getIssuer(), "iss")),
                    audience.getFirst(),
                    UUID.fromString(required(claims.getStringClaim(ACCOUNT_ID), ACCOUNT_ID)),
                    LinkSessionId.parse(required(claims.getStringClaim(SESSION_ID), SESSION_ID)),
                    TunnelId.parse(required(claims.getStringClaim(TUNNEL_ID), TUNNEL_ID)),
                    new NodeKeyFingerprint(required(claims.getStringClaim(CLIENT_KEY), CLIENT_KEY)),
                    UUID.fromString(required(claims.getStringClaim(AGENT_ID), AGENT_ID)),
                    new NodeKeyFingerprint(required(claims.getStringClaim(AGENT_KEY), AGENT_KEY)),
                    new TargetEndpoint(required(claims.getStringClaim(TARGET_IP), TARGET_IP),
                            Math.toIntExact(required(claims.getLongClaim(TARGET_PORT), TARGET_PORT))),
                    capabilities,
                    required(claims.getLongClaim(POLICY_VERSION), POLICY_VERSION),
                    required(claims.getJWTID(), "jti"),
                    issued.toInstant(), notBefore.toInstant(), expires.toInstant(),
                    required(claims.getStringClaim(PROTOCOL_VERSION), PROTOCOL_VERSION));
        } catch (ParseException | IllegalArgumentException | ArithmeticException error) {
            throw new TicketValidationException(TicketValidationException.Reason.MALFORMED,
                    "Access ticket claims are malformed", error);
        }
    }

    private void validateContext(AccessGrant grant, GrantValidationContext expected)
            throws TicketValidationException {
        if (!grant.issuer().equals(expected.issuer())) fail(TicketValidationException.Reason.ISSUER);
        if (!grant.audience().equals(expected.audience())) fail(TicketValidationException.Reason.AUDIENCE);
        if (!grant.protocolVersion().equals(expected.protocolVersion())) fail(TicketValidationException.Reason.PROTOCOL);
        if (!grant.sessionId().equals(expected.sessionId()) || !grant.tunnelId().equals(expected.tunnelId())) {
            fail(TicketValidationException.Reason.IDENTITY);
        }
        if (!grant.clientKeyFingerprint().equals(expected.clientKeyFingerprint())
                || !grant.agentId().equals(expected.agentId())
                || !grant.agentKeyFingerprint().equals(expected.agentKeyFingerprint())) {
            fail(TicketValidationException.Reason.IDENTITY);
        }
        if (!grant.target().equals(expected.target())) fail(TicketValidationException.Reason.TARGET);
    }

    private void validateTime(AccessGrant grant) throws TicketValidationException {
        Instant now = clock.instant();
        if (grant.issuedAt().isAfter(now.plus(clockSkew))
                || grant.notBefore().isAfter(now.plus(clockSkew))
                || !grant.expiresAt().plus(clockSkew).isAfter(now)) {
            fail(TicketValidationException.Reason.TIME);
        }
    }

    private static void fail(TicketValidationException.Reason reason) throws TicketValidationException {
        throw new TicketValidationException(reason, "Access ticket " + reason.name().toLowerCase());
    }

    private static <T> T required(T value, String claim) throws ParseException {
        if (value == null || value instanceof String text && text.isBlank()) {
            throw new ParseException("Missing claim " + claim, 0);
        }
        return value;
    }
}
