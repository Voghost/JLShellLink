package com.jlshell.link.client;

import com.jlshell.link.core.model.LinkFailure;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.signal.ControlSignal;
import com.jlshell.link.transport.DatagramPath;
import com.jlshell.link.transport.Ice4jDirectSession;
import java.io.IOException;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Implements the A-side authenticated ICE signaling exchange for one Website
 * session. Candidate credentials and addresses stay in this transient handler.
 */
public final class SignaledIceDirectPathProvider implements IceKcpCarrierPlanFactory.DirectPathProvider {
    private final Signaling signaling;
    private final Executor worker;
    private final Ice4jDirectSession.Config config;

    public SignaledIceDirectPathProvider(Signaling signaling, Executor worker,
            Ice4jDirectSession.Config config) {
        this.signaling = Objects.requireNonNull(signaling, "signaling");
        this.worker = Objects.requireNonNull(worker, "worker");
        this.config = Objects.requireNonNull(config, "config");
    }

    @Override
    public CompletionStage<? extends IceKcpCarrierPlanFactory.DirectPathLease> establish(
            IceKcpCarrierPlanFactory.DirectSessionRequest request,
            ConnectionCoordinator.AttemptContext context) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(context, "context");
        CompletableFuture<IceKcpCarrierPlanFactory.DirectPathLease> result = new CompletableFuture<>();
        if (context.isCancelled()) {
            return CompletableFuture.failedFuture(new CancellationException("ICE setup was cancelled"));
        }
        CompletionStage<ControlSignal.SessionInvite> invitation;
        try {
            invitation = Objects.requireNonNull(signaling.awaitInvite(request.sessionId()),
                    "signaling returned no invitation stage");
        } catch (RuntimeException error) {
            return CompletableFuture.failedFuture(classifySignalingFailure(error));
        }
        context.cancelled().whenComplete((ignored, error) ->
                result.completeExceptionally(new CancellationException("ICE setup was cancelled")));
        invitation.whenComplete((invite, inviteError) -> {
            if (result.isDone()) return;
            if (inviteError != null) {
                result.completeExceptionally(classifySignalingFailure(unwrap(inviteError)));
                return;
            }
            try {
                validateInvitation(request, invite);
            } catch (LinkFailure | RuntimeException rejected) {
                result.completeExceptionally(rejected);
                return;
            }
            Ice4jDirectSession.Config bounded = new Ice4jDirectSession.Config(config.stunServers(),
                    Math.min(config.maxCandidates(), context.maxCandidates()), config.connectivityTimeout(),
                    config.maxDatagramBytes(), config.receiveTimeoutMillis());
            try {
                worker.execute(() -> startGeneration(request.sessionId(), invite.generation(), bounded,
                        context, result, invite.peerReflexiveSupported()));
            } catch (RuntimeException rejected) {
                result.completeExceptionally(new LinkFailure("direct.ice_worker_unavailable",
                        LinkFailure.Category.TRANSIENT_NETWORK, "ICE worker is unavailable"));
            }
        });
        return result;
    }

    private void startGeneration(LinkSessionId sessionId, long generation,
            Ice4jDirectSession.Config bounded, ConnectionCoordinator.AttemptContext context,
            CompletableFuture<IceKcpCarrierPlanFactory.DirectPathLease> result, boolean peerReflexive) {
        if (result.isDone() || context.isCancelled()) {
            result.completeExceptionally(new CancellationException("ICE setup was cancelled"));
            return;
        }
        Ice4jDirectSession ice;
        try {
            ice = new Ice4jDirectSession(sessionId, generation, true, bounded,
                    peerReflexive ? candidate -> signaling.send(candidate) : null);
        } catch (IOException | RuntimeException unavailable) {
            result.completeExceptionally(new LinkFailure("direct.ice_candidate_gathering",
                    LinkFailure.Category.TRANSIENT_NETWORK, "ICE candidate gathering failed"));
            return;
        }
        Negotiation negotiation = new Negotiation(ice, context, result);
        if (result.isDone() || context.isCancelled()) {
            negotiation.close();
            return;
        }
        negotiation.begin();
    }

    private void validateInvitation(IceKcpCarrierPlanFactory.DirectSessionRequest request,
            ControlSignal.SessionInvite invite) throws LinkFailure {
        Instant now = Instant.now();
        if (invite == null || !invite.sessionId().equals(request.sessionId())
                || !invite.clientDeviceId().equals(request.clientDeviceId())
                || !invite.clientKeyFingerprint().equals(request.clientKeyFingerprint())
                || !invite.agentId().equals(request.agentId())
                || !invite.agentKeyFingerprint().equals(request.agentKeyFingerprint())
                || invite.policyVersion() != request.policyVersion()
                || !invite.expiresAt().isAfter(now)) {
            throw new SecurityException("Website control invitation does not match the authorized session");
        }
        if (!invite.iceCredentialsSupported()) {
            throw new LinkFailure("direct.ice_not_negotiated", LinkFailure.Category.TRANSIENT_NETWORK,
                    "Peer does not support direct ICE signaling");
        }
        if (!request.authorizationLeaseExpiresAt().isAfter(now)) {
            throw new LinkFailure("direct.authorization_expired", LinkFailure.Category.AUTHORIZATION,
                    "Website authorization lease expired before ICE setup");
        }
    }

    private final class Negotiation implements AutoCloseable {
        private final Ice4jDirectSession ice;
        private final ConnectionCoordinator.AttemptContext context;
        private final CompletableFuture<IceKcpCarrierPlanFactory.DirectPathLease> result;
        private final CompletableFuture<ControlSignal.PathReady> peerReady = new CompletableFuture<>();
        private final AtomicReference<Ice4jDirectSession.SelectedPath> selected = new AtomicReference<>();
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicBoolean transferred = new AtomicBoolean();
        private volatile Subscription subscription;

        private Negotiation(Ice4jDirectSession ice, ConnectionCoordinator.AttemptContext context,
                CompletableFuture<IceKcpCarrierPlanFactory.DirectPathLease> result) {
            this.ice = ice;
            this.context = context;
            this.result = result;
        }

        private void begin() {
            try {
                subscription = Objects.requireNonNull(signaling.listen(ice.sessionId(), ice.generation(),
                        this::receive, this::fail), "signaling returned no subscription");
            } catch (RuntimeException error) {
                fail(new LinkFailure("direct.signaling_unavailable", LinkFailure.Category.TRANSIENT_NETWORK,
                        "ICE signaling subscription failed"));
                return;
            }
            // listen may synchronously replay an early peer offer and fail setup.
            if (closed.get() || result.isDone()) {
                closeSubscriptionOnly();
                return;
            }
            ice.selectedPath().whenComplete((path, error) -> {
                if (error != null) {
                    fail(new LinkFailure(iceFailureCode(error), LinkFailure.Category.TRANSIENT_NETWORK,
                            "ICE could not nominate a peer path"));
                    return;
                }
                selected.set(path);
                send(path.readySignal());
                maybeComplete();
            });
            CompletionStage<Void> sends = CompletableFuture.completedFuture(null);
            try {
                for (ControlSignal signal : ice.localOffer()) {
                    sends = sends.thenCompose(ignored -> signaling.send(signal));
                }
            } catch (RuntimeException error) {
                fail(new LinkFailure("direct.ice_offer_invalid", LinkFailure.Category.PROTOCOL,
                        "ICE offer could not be created"));
                return;
            }
            sends.whenComplete((ignored, error) -> {
                if (error != null) fail(classifySignalingFailure(unwrap(error)));
            });
            context.cancelled().whenComplete((ignored, error) ->
                    fail(new CancellationException("ICE setup was cancelled")));
            result.whenComplete((lease, error) -> {
                if (error != null || result.isCancelled()) close();
                else if (transferred.get()) closeSubscriptionOnly();
            });
        }

        private void receive(ControlSignal signal) {
            if (closed.get() || signal == null) return;
            try {
                if (signal instanceof ControlSignal.IceCredentials
                        || signal instanceof ControlSignal.IceCandidate || signal instanceof ControlSignal.IceEnd) {
                    ice.accept(signal);
                } else if (signal instanceof ControlSignal.PathReady ready) {
                    if (ready.path() != ControlSignal.Path.DIRECT
                            || !ice.sessionId().equals(ready.sessionId())
                            || ready.generation() != ice.generation()) {
                        throw new SecurityException("peer selected a different direct path generation");
                    }
                    if (!peerReady.complete(ready)) {
                        throw new SecurityException("peer repeated its direct path selection");
                    }
                    maybeComplete();
                } else if (signal instanceof ControlSignal.SessionRevoked) {
                    fail(new LinkFailure("direct.authorization_revoked", LinkFailure.Category.AUTHORIZATION,
                            "Website authorization was revoked"));
                }
            } catch (RuntimeException rejected) {
                fail(new LinkFailure("direct.ice_signal_rejected", LinkFailure.Category.PROTOCOL,
                        "ICE signaling message was rejected"));
            }
        }

        private void send(ControlSignal signal) {
            signaling.send(signal).whenComplete((ignored, error) -> {
                if (error != null) fail(classifySignalingFailure(unwrap(error)));
            });
        }

        private void maybeComplete() {
            Ice4jDirectSession.SelectedPath path = selected.get();
            ControlSignal.PathReady ready = peerReady.getNow(null);
            if (path == null || ready == null || result.isDone()) return;
            if (!path.remoteCandidateId().equals(ready.localCandidateId())
                    || !path.localCandidateId().equals(ready.remoteCandidateId())) {
                fail(new LinkFailure("direct.selected_pair_mismatch", LinkFailure.Category.PROTOCOL,
                        "Peer selected a different ICE candidate pair"));
                return;
            }
            IcePathLease lease = new IcePathLease(ice, path);
            if (result.complete(lease)) {
                transferred.set(true);
                closeSubscriptionOnly();
            } else {
                lease.close();
            }
        }

        private void fail(Throwable error) {
            if (result.completeExceptionally(error)) close();
        }

        @Override public void close() {
            if (!closed.compareAndSet(false, true)) return;
            closeSubscriptionOnly();
            Ice4jDirectSession.SelectedPath path = selected.get();
            if (path != null) path.close();
            else ice.close();
        }

        private void closeSubscriptionOnly() {
            Subscription current = subscription;
            subscription = null;
            if (current != null) {
                try { current.close(); } catch (RuntimeException ignored) { }
            }
        }
    }

    static String iceFailureCode(Throwable error) {
        Throwable cause = unwrap(error);
        if (cause instanceof IOException) {
            if ("ICE selected a candidate outside the authorized exchange".equals(cause.getMessage())) {
                return "direct.ice_selected_unknown";
            }
            if ("ICE connectivity checks did not nominate a candidate pair".equals(cause.getMessage())) {
                return "direct.ice_checks_failed";
            }
            if ("ICE connectivity deadline expired".equals(cause.getMessage())) {
                return "direct.ice_deadline";
            }
        }
        return "direct.ice_unreachable";
    }

    private final class IcePathLease implements IceKcpCarrierPlanFactory.DirectPathLease {
        private final Ice4jDirectSession ice;
        private final Ice4jDirectSession.SelectedPath selected;
        private final AtomicBoolean closed = new AtomicBoolean();

        private IcePathLease(Ice4jDirectSession ice, Ice4jDirectSession.SelectedPath selected) {
            this.ice = ice;
            this.selected = selected;
        }
        @Override public LinkSessionId sessionId() { return ice.sessionId(); }
        @Override public long generation() { return ice.generation(); }
        @Override public DatagramPath datagrams() { return selected.datagrams(); }
        @Override public void close() {
            if (!closed.compareAndSet(false, true)) return;
            selected.close();
        }
    }

    private static Throwable classifySignalingFailure(Throwable error) {
        if (error instanceof LinkFailure) return error;
        if (error instanceof CancellationException) return error;
        if (error instanceof IOException || error instanceof TimeoutException) {
            return new LinkFailure("direct.signaling_network", LinkFailure.Category.TRANSIENT_NETWORK,
                    "ICE signaling is temporarily unavailable");
        }
        return new LinkFailure("direct.signaling_protocol", LinkFailure.Category.PROTOCOL,
                "ICE signaling failed");
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while ((current instanceof CompletionException || current instanceof java.util.concurrent.ExecutionException)
                && current.getCause() != null) current = current.getCause();
        return current;
    }

    /** Authenticated WSS control exchange. Implementations must route only current-session messages. */
    public interface Signaling {
        CompletionStage<ControlSignal.SessionInvite> awaitInvite(LinkSessionId sessionId);
        Subscription listen(LinkSessionId sessionId, long generation,
                Consumer<ControlSignal> signals, Consumer<Throwable> failure);
        CompletionStage<Void> send(ControlSignal signal);
    }

    @FunctionalInterface
    public interface Subscription extends AutoCloseable {
        @Override void close();
    }
}
