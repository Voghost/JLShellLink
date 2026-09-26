package com.jlshell.link.server;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.signal.ControlSignal;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** Routes authorized ICE/path messages only between the exact online A/C identities in a Website grant. */
public final class SignalRouter implements AutoCloseable {
    private final ConcurrentHashMap<UUID, ControlConnection> online = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<LinkSessionId, ActiveSession> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<LinkSessionId, GenerationState> generations = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<LinkSessionId, AuthorizedSession> pendingGrants = new ConcurrentHashMap<>();
    private final AtomicLong connectionGenerations = new AtomicLong();
    private final Clock clock;
    private final int maxOnlineNodes;
    private final int maxSessions;
    private final int maxCandidatesPerPeer;
    private final int maxSignalsPerSession;
    private volatile boolean closed;

    public SignalRouter(Clock clock, int maxOnlineNodes, int maxSessions,
                        int maxCandidatesPerPeer, int maxSignalsPerSession) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.maxOnlineNodes = bounded(maxOnlineNodes, 1, 100_000, "maxOnlineNodes");
        this.maxSessions = bounded(maxSessions, 1, 100_000, "maxSessions");
        this.maxCandidatesPerPeer = bounded(maxCandidatesPerPeer, 1, 256, "maxCandidatesPerPeer");
        this.maxSignalsPerSession = bounded(maxSignalsPerSession, 2, 4096, "maxSignalsPerSession");
    }

    public synchronized ControlConnection register(ControlPeer peer, SignalSink sink) {
        return register(peer, sink, () -> { });
    }

    public synchronized ControlConnection register(ControlPeer peer, SignalSink sink, Runnable closeSuperseded) {
        Objects.requireNonNull(peer, "peer");
        Objects.requireNonNull(sink, "sink");
        Objects.requireNonNull(closeSuperseded, "closeSuperseded");
        if (closed) throw new IllegalStateException("signal router is closed");
        ControlConnection connection = new ControlConnection(peer, sink, closeSuperseded,
                connectionGenerations.incrementAndGet());
        ControlConnection previous = online.put(peer.nodeId(), connection);
        if (previous == null && online.size() > maxOnlineNodes) {
            online.remove(peer.nodeId(), connection);
            throw new IllegalStateException("online control-node capacity reached");
        }
        if (previous != null) {
            invalidate(previous);
            previous.closeSuperseded();
        }
        activatePendingGrants();
        return connection;
    }

    /** Called only after Website has authorized the requested active A—C session. */
    public synchronized void authorize(AuthorizedSession grant) {
        Objects.requireNonNull(grant, "grant");
        if (closed) throw new IllegalStateException("signal router is closed");
        if (!grant.expiresAt().isAfter(clock.instant())) throw new SecurityException("control session has expired");
        pruneExpired();
        ControlConnection client = online.get(grant.clientDeviceId());
        ControlConnection agent = online.get(grant.agentId());
        if (client != null && !matches(client, grant, NodeRole.CLIENT)
                || agent != null && !matches(agent, grant, NodeRole.AGENT)) {
            throw new SecurityException("online control peer identity does not match the Website grant");
        }
        if (client == null || agent == null) {
            if (!pendingGrants.containsKey(grant.sessionId()) && pendingGrants.size() >= maxSessions) {
                throw new IllegalStateException("pending control-session capacity reached");
            }
            pendingGrants.put(grant.sessionId(), grant);
            return;
        }
        activateGrant(grant, client, agent);
    }

    private void activatePendingGrants() {
        for (AuthorizedSession grant : pendingGrants.values()) {
            if (!grant.expiresAt().isAfter(clock.instant())) {
                pendingGrants.remove(grant.sessionId(), grant);
                continue;
            }
            ControlConnection client = online.get(grant.clientDeviceId());
            ControlConnection agent = online.get(grant.agentId());
            if ((client != null && !matches(client, grant, NodeRole.CLIENT))
                    || (agent != null && !matches(agent, grant, NodeRole.AGENT))) {
                pendingGrants.remove(grant.sessionId(), grant);
                continue;
            }
            if (client != null && agent != null) {
                try {
                    activateGrant(grant, client, agent);
                    pendingGrants.remove(grant.sessionId(), grant);
                } catch (RuntimeException deliveryFailure) {
                    pendingGrants.remove(grant.sessionId(), grant);
                }
            }
        }
    }

    private void activateGrant(AuthorizedSession grant, ControlConnection client, ControlConnection agent) {
        if (!matches(client, grant, NodeRole.CLIENT) || !matches(agent, grant, NodeRole.AGENT)) {
            throw new SecurityException("authorized control peers are not online with the expected identities");
        }
        if (!sessions.containsKey(grant.sessionId()) && sessions.size() >= maxSessions) {
            throw new IllegalStateException("active control-session capacity reached");
        }
        if (!generations.containsKey(grant.sessionId()) && generations.size() >= maxSessions * 2L) {
            throw new IllegalStateException("control-session generation capacity reached");
        }
        GenerationState generation = generations.compute(grant.sessionId(), (ignored, previous) -> {
            long next = previous == null ? 1 : Math.addExact(previous.value(), 1);
            Instant expiry = previous == null || grant.expiresAt().isAfter(previous.expiresAt())
                    ? grant.expiresAt() : previous.expiresAt();
            return new GenerationState(next, expiry);
        });
        ActiveSession next = new ActiveSession(grant, generation.value(), client, agent);
        ActiveSession previous = sessions.get(grant.sessionId());
        if (previous != null) {
            synchronized (previous) {
                if (!grant.expiresAt().isAfter(clock.instant())) {
                    throw new SecurityException("control session generation is stale");
                }
                sessions.remove(grant.sessionId(), previous);
            }
        }
        sessions.put(grant.sessionId(), next);
        try {
            ControlSignal.SessionInvite invite = new ControlSignal.SessionInvite(UUID.randomUUID(),
                    grant.sessionId(), generation.value(), grant.agentId(), grant.clientDeviceId(),
                    grant.agentKeyFingerprint(), grant.clientKeyFingerprint(), grant.policyVersion(), grant.expiresAt());
            agent.sink.send(invite);
            client.sink.send(invite);
        } catch (RuntimeException deliveryFailure) {
            sessions.remove(grant.sessionId(), next);
            throw new IllegalStateException("could not deliver authorized session invite", deliveryFailure);
        }
    }

    public void route(ControlConnection sender, ControlSignal signal) {
        Objects.requireNonNull(sender, "sender");
        Objects.requireNonNull(signal, "signal");
        if (signal instanceof ControlSignal.SessionInvite || signal instanceof ControlSignal.SessionRevoked) {
            throw new SecurityException("only the Website authorization path can issue session state");
        }
        if (online.get(sender.peer.nodeId()) != sender) {
            throw new SecurityException("control connection is stale");
        }
        ActiveSession route = sessions.get(signal.sessionId());
        if (route == null) throw new SecurityException("control session is not authorized");
        synchronized (route) {
            if (sessions.get(signal.sessionId()) != route || !route.grant.expiresAt().isAfter(clock.instant())) {
                sessions.remove(signal.sessionId(), route);
                throw new SecurityException("control session is expired or replaced");
            }
            if (signal.generation() != route.generation) {
                throw new SecurityException("control signal generation is stale");
            }
            NodeRole role = route.role(sender);
            if (role == null) throw new SecurityException("node is not a participant in this session");
            if (!route.messageIds.add(signal.messageId())) {
                throw new SecurityException("control message was replayed");
            }
            if (route.messageIds.size() > maxSignalsPerSession) {
                sessions.remove(signal.sessionId(), route);
                throw new SecurityException("control session signal limit reached");
            }
            route.validate(role, signal, maxCandidatesPerPeer);
            ControlConnection recipient = role == NodeRole.CLIENT ? route.agent : route.client;
            if (online.get(recipient.peer.nodeId()) != recipient) {
                sessions.remove(signal.sessionId(), route);
                throw new SecurityException("control peer disconnected");
            }
            try {
                recipient.sink.send(signal);
            } catch (RuntimeException deliveryFailure) {
                sessions.remove(signal.sessionId(), route);
                throw new IllegalStateException("control signal delivery failed", deliveryFailure);
            }
        }
    }

    public synchronized void revoke(LinkSessionId sessionId) {
        Objects.requireNonNull(sessionId, "sessionId");
        ActiveSession removed = sessions.remove(sessionId);
        pendingGrants.remove(sessionId);
        if (removed != null) {
            ControlSignal.SessionRevoked revoked = new ControlSignal.SessionRevoked(
                    UUID.randomUUID(), sessionId, removed.generation);
            if (online.get(removed.client.peer.nodeId()) == removed.client) {
                try { removed.client.sink.send(revoked); } catch (RuntimeException ignored) { }
            }
            if (online.get(removed.agent.peer.nodeId()) == removed.agent) {
                try { removed.agent.sink.send(revoked); } catch (RuntimeException ignored) { }
            }
        }
    }

    public int onlineCount() { return online.size(); }
    public int activeSessionCount() { pruneExpired(); return sessions.size(); }

    private boolean matches(ControlConnection connection, AuthorizedSession grant, NodeRole role) {
        if (connection == null) return false;
        ControlPeer peer = connection.peer;
        return peer.role() == role && peer.accountId().equals(grant.accountId())
                && (role == NodeRole.CLIENT
                    ? peer.nodeId().equals(grant.clientDeviceId())
                        && peer.keyFingerprint().equals(grant.clientKeyFingerprint())
                    : peer.nodeId().equals(grant.agentId()) && peer.agentId().equals(grant.agentId())
                        && peer.keyFingerprint().equals(grant.agentKeyFingerprint()));
    }

    private void invalidate(ControlConnection connection) {
        sessions.entrySet().removeIf(entry -> entry.getValue().client == connection
                || entry.getValue().agent == connection);
    }

    private void unregister(ControlConnection connection) {
        if (online.remove(connection.peer.nodeId(), connection)) invalidate(connection);
    }

    private void pruneExpired() {
        Instant now = clock.instant();
        sessions.entrySet().removeIf(entry -> !entry.getValue().grant.expiresAt().isAfter(now));
        generations.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
        pendingGrants.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now));
    }

    @Override
    public void close() {
        closed = true;
        sessions.clear();
        pendingGrants.clear();
        online.clear();
        generations.clear();
    }

    private static int bounded(int value, int min, int max, String name) {
        if (value < min || value > max) throw new IllegalArgumentException(name + " is out of range");
        return value;
    }

    public final class ControlConnection implements AutoCloseable {
        private final ControlPeer peer;
        private final SignalSink sink;
        private final Runnable closeSuperseded;
        private final long generation;
        private ControlConnection(ControlPeer peer, SignalSink sink, Runnable closeSuperseded, long generation) {
            this.peer = peer;
            this.sink = sink;
            this.closeSuperseded = closeSuperseded;
            this.generation = generation;
        }
        public ControlPeer peer() { return peer; }
        public long generation() { return generation; }
        private void closeSuperseded() {
            try { closeSuperseded.run(); } catch (RuntimeException ignored) { }
        }
        @Override public void close() { unregister(this); }
    }

    public record ControlPeer(NodeRole role, UUID accountId, UUID nodeId, UUID agentId,
                              NodeKeyFingerprint keyFingerprint) {
        public ControlPeer {
            if (role != NodeRole.CLIENT && role != NodeRole.AGENT) {
                throw new IllegalArgumentException("control role must be CLIENT or AGENT");
            }
            Objects.requireNonNull(accountId, "accountId");
            Objects.requireNonNull(nodeId, "nodeId");
            Objects.requireNonNull(keyFingerprint, "keyFingerprint");
            if (role == NodeRole.AGENT && (agentId == null || !agentId.equals(nodeId))) {
                throw new IllegalArgumentException("Agent node id must equal its Agent id");
            }
            if (role == NodeRole.CLIENT && agentId != null) {
                throw new IllegalArgumentException("client control identity cannot be bound to one Agent");
            }
        }
    }

    public record AuthorizedSession(UUID accountId, LinkSessionId sessionId,
                                    UUID clientDeviceId, UUID agentId,
                                    NodeKeyFingerprint clientKeyFingerprint,
                                    NodeKeyFingerprint agentKeyFingerprint,
                                    long policyVersion, Instant expiresAt) {
        public AuthorizedSession {
            Objects.requireNonNull(accountId, "accountId");
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(clientDeviceId, "clientDeviceId");
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(clientKeyFingerprint, "clientKeyFingerprint");
            Objects.requireNonNull(agentKeyFingerprint, "agentKeyFingerprint");
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (policyVersion < 0) throw new IllegalArgumentException("invalid policy version");
        }
    }

    @FunctionalInterface
    public interface SignalSink { void send(ControlSignal signal); }

    private static final class ActiveSession {
        private final AuthorizedSession grant;
        private final long generation;
        private final ControlConnection client;
        private final ControlConnection agent;
        private final Set<UUID> messageIds = new HashSet<>();
        private final Map<NodeRole, Set<UUID>> candidates = new HashMap<>();
        private final Set<NodeRole> iceEnded = new HashSet<>();
        private final Map<NodeRole, ControlSignal.PathReady> readyPaths = new HashMap<>();

        private ActiveSession(AuthorizedSession grant, long generation,
                              ControlConnection client, ControlConnection agent) {
            this.grant = grant;
            this.generation = generation;
            this.client = client;
            this.agent = agent;
            candidates.put(NodeRole.CLIENT, new HashSet<>());
            candidates.put(NodeRole.AGENT, new HashSet<>());
        }

        private NodeRole role(ControlConnection connection) {
            if (connection == client) return NodeRole.CLIENT;
            if (connection == agent) return NodeRole.AGENT;
            return null;
        }

        private void validate(NodeRole sender, ControlSignal signal, int candidateLimit) {
            if (signal instanceof ControlSignal.IceCandidate candidate) {
                if (iceEnded.contains(sender)) throw new SecurityException("candidate arrived after ICE_END");
                Set<UUID> known = candidates.get(sender);
                if (known.size() >= candidateLimit || !known.add(candidate.candidateId())) {
                    throw new SecurityException("candidate limit reached or candidate id repeated");
                }
            } else if (signal instanceof ControlSignal.IceEnd) {
                if (!iceEnded.add(sender)) throw new SecurityException("ICE_END was already received");
            } else if (signal instanceof ControlSignal.PathReady ready) {
                if (ready.path() == ControlSignal.Path.DIRECT) {
                    Set<UUID> local = candidates.get(sender);
                    Set<UUID> remote = candidates.get(sender == NodeRole.CLIENT ? NodeRole.AGENT : NodeRole.CLIENT);
                    if (!local.contains(ready.localCandidateId()) || !remote.contains(ready.remoteCandidateId())) {
                        throw new SecurityException("selected candidate pair was not exchanged in this session");
                    }
                }
                ControlSignal.PathReady previous = readyPaths.putIfAbsent(sender, ready);
                if (previous != null && (previous.path() != ready.path()
                        || !Objects.equals(previous.localCandidateId(), ready.localCandidateId())
                        || !Objects.equals(previous.remoteCandidateId(), ready.remoteCandidateId()))) {
                    throw new SecurityException("path selection cannot change within a generation");
                }
            }
        }
    }

    private record GenerationState(long value, Instant expiresAt) { }
}
