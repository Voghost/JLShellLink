package com.jlshell.link.server;

import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.model.NodeRole;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.model.LinkSessionId;
import io.netty.channel.Channel;
import com.jlshell.link.core.transport.TransportBufferBudget;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/** One-use A/C relay pairing. A ticket/tunnel tuple cannot be paired a second time. */
public final class RelayPairingService implements AutoCloseable {
    private final Object lock = new Object();
    private final Map<PairKey, PendingPair> pending = new HashMap<>();
    private final Map<PairKey, Instant> consumed = new HashMap<>();
    private final NodeConnectionRegistry nodes;
    private final ScheduledExecutorService scheduler;
    private final Clock clock;
    private final int maxPendingPairs;
    private final long maxPendingBytes;
    private boolean closed;

    public RelayPairingService(NodeConnectionRegistry nodes, ScheduledExecutorService scheduler,
                               Clock clock, int maxPendingPairs, long maxPendingBytes) {
        this.nodes = Objects.requireNonNull(nodes, "nodes");
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (maxPendingPairs < 1 || maxPendingPairs > 100_000) {
            throw new IllegalArgumentException("maxPendingPairs must be between 1 and 100000");
        }
        if (maxPendingBytes < 1 || maxPendingBytes > 16 * 1024 * 1024) {
            throw new IllegalArgumentException("maxPendingBytes must be between 1 byte and 16 MiB");
        }
        this.maxPendingPairs = maxPendingPairs;
        this.maxPendingBytes = maxPendingBytes;
    }

    public CompletionStage<PairedChannels> join(AuthorizedPeer peer, Channel channel) {
        Objects.requireNonNull(peer, "peer");
        Objects.requireNonNull(channel, "channel");
        CompletableFuture<PairedChannels> result = new CompletableFuture<>();
        PairKey key = new PairKey(peer.sessionId(), peer.tunnelId());
        PendingPair current;
        synchronized (lock) {
            pruneConsumed();
            if (closed) throw new IllegalStateException("pairing service is closed");
            if (peer.ticketExpiresAt().isBefore(clock.instant()) || !peer.ticketExpiresAt().isAfter(clock.instant())) {
                throw new RejectedExecutionException("relay authorization has expired");
            }
            if (consumed.containsKey(key)) throw new RejectedExecutionException("relay tunnel was already paired");
            current = pending.get(key);
            if (current == null) {
                if (pending.size() >= maxPendingPairs) throw new RejectedExecutionException("relay pairing is full");
                current = new PendingPair(key, peer.ticketExpiresAt());
                pending.put(key, current);
                PendingPair scheduled = current;
                current.timeout = scheduler.schedule(() -> expire(scheduled),
                        Math.max(1, Math.min(peer.ticketExpiresAt().toEpochMilli() - clock.millis(),
                                TimeUnit.MINUTES.toMillis(5))), TimeUnit.MILLISECONDS);
                current.firstPeer = peer;
                current.firstChannel = channel;
                current.firstResult = result;
                current.firstChannel.closeFuture().addListener(ignored -> failPending(scheduled,
                        new RejectedExecutionException("relay peer disconnected before pairing")));
                channel.config().setAutoRead(false);
                return result;
            }
            validatePair(current, peer);
            if (current.firstPeer.role() == peer.role()) {
                throw new RejectedExecutionException("duplicate relay role");
            }
            if (!current.expiresAt.isAfter(clock.instant())) {
                pending.remove(key);
                throw new RejectedExecutionException("relay pairing expired");
            }
            consumed.put(key, current.expiresAt);
            pending.remove(key);
            current.timeout.cancel(false);
            channel.config().setAutoRead(false);
            PairedChannels pair = current.firstPeer.role() == NodeRole.CLIENT
                    ? new PairedChannels(current.firstPeer, current.firstChannel, peer, channel,
                            current.expiresAt, new TransportBufferBudget(maxPendingBytes))
                    : new PairedChannels(peer, channel, current.firstPeer, current.firstChannel,
                            current.expiresAt, new TransportBufferBudget(maxPendingBytes));
            current.firstResult.complete(pair);
            result.complete(pair);
            pair.aChannel().closeFuture().addListener(ignored -> closePair(pair));
            pair.cChannel().closeFuture().addListener(ignored -> closePair(pair));
        }
        return result;
    }

    private void validatePair(PendingPair pair, AuthorizedPeer peer) {
        AuthorizedPeer first = pair.firstPeer;
        if (first.role() == peer.role()) return;
        if (!first.accountId().equals(peer.accountId()) || !first.agentId().equals(peer.agentId())
                || !first.sessionId().equals(peer.sessionId()) || !first.tunnelId().equals(peer.tunnelId())
                || !first.ticketExpiresAt().equals(peer.ticketExpiresAt())) {
            throw new RejectedExecutionException("relay peers do not share an authorized session");
        }
        AuthorizedPeer agent = first.role() == NodeRole.AGENT ? first : peer;
        var online = nodes.findOnline(agent.agentId()).orElseThrow(
                () -> new RejectedExecutionException("target Agent is offline"));
        if (online.identity().role() != NodeRole.AGENT || !online.accountId().equals(agent.accountId())
                || !online.identity().keyFingerprint().equals(agent.keyFingerprint())) {
            throw new RejectedExecutionException("target Agent identity is not online");
        }
        AuthorizedPeer client = first.role() == NodeRole.CLIENT ? first : peer;
        if (!client.keyFingerprint().equals(agent.expectedClientKeyFingerprint())) {
            throw new RejectedExecutionException("client identity does not match the issued access request");
        }
        if (!agent.keyFingerprint().equals(client.expectedAgentKeyFingerprint())) {
            throw new RejectedExecutionException("Agent identity does not match the issued access request");
        }
    }

    private void expire(PendingPair pair) {
        failPending(pair, new RejectedExecutionException("relay pairing timed out"));
    }

    private void failPending(PendingPair pair, Throwable error) {
        synchronized (lock) {
            if (!pending.remove(pair.key, pair)) return;
            pair.firstResult.completeExceptionally(error);
            pair.firstChannel.close();
        }
    }

    private void closePair(PairedChannels pair) {
        pair.aChannel().close();
        pair.cChannel().close();
    }

    private void pruneConsumed() {
        Instant now = clock.instant();
        consumed.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
    }

    @Override
    public void close() {
        synchronized (lock) {
            if (closed) return;
            closed = true;
            pending.values().forEach(pair -> {
                pair.timeout.cancel(false);
                pair.firstResult.completeExceptionally(new RejectedExecutionException("relay server is stopping"));
                pair.firstChannel.close();
            });
            pending.clear();
            consumed.clear();
        }
    }

    public record AuthorizedPeer(NodeRole role, UUID accountId, UUID agentId,
                                 LinkSessionId sessionId, TunnelId tunnelId,
                                 NodeKeyFingerprint keyFingerprint,
                                 NodeKeyFingerprint expectedClientKeyFingerprint,
                                 NodeKeyFingerprint expectedAgentKeyFingerprint,
                                 Instant ticketExpiresAt) {
        public AuthorizedPeer {
            if (role != NodeRole.CLIENT && role != NodeRole.AGENT) {
                throw new IllegalArgumentException("relay role must be CLIENT or AGENT");
            }
            Objects.requireNonNull(accountId, "accountId");
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(tunnelId, "tunnelId");
            Objects.requireNonNull(keyFingerprint, "keyFingerprint");
            Objects.requireNonNull(expectedClientKeyFingerprint, "expectedClientKeyFingerprint");
            Objects.requireNonNull(expectedAgentKeyFingerprint, "expectedAgentKeyFingerprint");
            Objects.requireNonNull(ticketExpiresAt, "ticketExpiresAt");
            if (role == NodeRole.CLIENT && !keyFingerprint.equals(expectedClientKeyFingerprint)) {
                throw new IllegalArgumentException("client key fingerprint does not match access request");
            }
            if (role == NodeRole.AGENT && !keyFingerprint.equals(expectedAgentKeyFingerprint)) {
                throw new IllegalArgumentException("Agent key fingerprint does not match access request");
            }
        }
    }

    public record PairedChannels(AuthorizedPeer client, Channel aChannel,
                                 AuthorizedPeer agent, Channel cChannel,
                                 Instant expiresAt, TransportBufferBudget bufferBudget) { }

    private record PairKey(LinkSessionId sessionId, TunnelId tunnelId) { }

    private static final class PendingPair {
        private final PairKey key;
        private final Instant expiresAt;
        private AuthorizedPeer firstPeer;
        private Channel firstChannel;
        private CompletableFuture<PairedChannels> firstResult;
        private ScheduledFuture<?> timeout;

        private PendingPair(PairKey key, Instant expiresAt) {
            this.key = key;
            this.expiresAt = expiresAt;
        }
    }
}
