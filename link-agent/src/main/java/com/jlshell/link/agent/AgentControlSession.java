package com.jlshell.link.agent;

import java.time.Duration;
import java.util.Objects;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;

/** Heartbeats C's Website lease, applies ordered revocations, and retries transient failures with bounded backoff. */
public final class AgentControlSession implements AutoCloseable {
    private final AgentControlPlaneClient api;
    private final String credential;
    private final UUID agentId;
    private final com.jlshell.link.core.model.NodeKeyFingerprint fingerprint;
    private final String version;
    private final Set<String> capabilities;
    private final UUID controlSessionId = UUID.randomUUID();
    private final ScheduledExecutorService scheduler;
    private final Duration heartbeatInterval;
    private final Consumer<AgentLeaseSnapshot> leaseUpdates;
    private final Runnable closeActiveStreams;
    private final Function<AgentControlPlaneClient.RelayOpenRequest, ? extends CompletionStage<Void>> relayOpenHandler;
    private final Consumer<UUID> relayCloseHandler;
    private final Runnable revokedAction;
    private final Consumer<String> statusCode;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean inFlight = new AtomicBoolean();
    private final AtomicLong revocationCursor = new AtomicLong();
    private final ConcurrentHashMap<UUID, java.time.Instant> handledRelayRequests = new ConcurrentHashMap<>();
    private volatile ScheduledFuture<?> scheduled;
    private volatile ScheduledFuture<?> leaseExpiryTask;
    private volatile AgentLeaseSnapshot latestLease;
    private volatile int consecutiveFailures;

    public AgentControlSession(AgentControlPlaneClient api, String credential, UUID agentId,
            com.jlshell.link.core.model.NodeKeyFingerprint fingerprint, String version,
            Set<String> capabilities, ScheduledExecutorService scheduler, Duration heartbeatInterval,
            Consumer<AgentLeaseSnapshot> leaseUpdates, Runnable closeActiveStreams,
            Function<AgentControlPlaneClient.RelayOpenRequest, ? extends CompletionStage<Void>> relayOpenHandler,
            Consumer<UUID> relayCloseHandler, Runnable revokedAction, Consumer<String> statusCode) {
        this.api = Objects.requireNonNull(api, "api");
        if (credential == null || credential.isBlank()) throw new IllegalArgumentException("credential is required");
        this.credential = credential;
        this.agentId = Objects.requireNonNull(agentId, "agentId");
        this.fingerprint = Objects.requireNonNull(fingerprint, "fingerprint");
        this.version = version == null ? "" : version;
        this.capabilities = Set.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
        this.heartbeatInterval = Objects.requireNonNull(heartbeatInterval, "heartbeatInterval");
        if (heartbeatInterval.compareTo(Duration.ofSeconds(10)) < 0
                || heartbeatInterval.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("heartbeatInterval must be between 10 seconds and 5 minutes");
        }
        this.leaseUpdates = Objects.requireNonNull(leaseUpdates, "leaseUpdates");
        this.closeActiveStreams = closeActiveStreams == null ? () -> { } : closeActiveStreams;
        this.relayOpenHandler = relayOpenHandler == null
                ? ignored -> java.util.concurrent.CompletableFuture.completedFuture(null) : relayOpenHandler;
        this.relayCloseHandler = relayCloseHandler == null ? ignored -> { } : relayCloseHandler;
        this.revokedAction = revokedAction == null ? () -> { } : revokedAction;
        this.statusCode = statusCode == null ? ignored -> { } : statusCode;
    }

    public void start() {
        if (closed.get()) throw new IllegalStateException("Agent control session is closed");
        schedule(Duration.ZERO);
    }

    public UUID controlSessionId() { return controlSessionId; }
    public long revocationCursor() { return revocationCursor.get(); }

    private void schedule(Duration delay) {
        if (closed.get()) return;
        scheduled = scheduler.schedule(this::cycle, Math.max(0, delay.toMillis()), TimeUnit.MILLISECONDS);
    }

    private void cycle() {
        if (closed.get() || !inFlight.compareAndSet(false, true)) return;
        try {
            AgentLeaseSnapshot heartbeat = api.heartbeat(credential, controlSessionId, agentId,
                    fingerprint, version, capabilities);
            AgentControlPlaneClient.RevocationBatch batch = api.pollRevocations(credential, revocationCursor.get());
            var relayRequests = api.pollRelayRequests(credential);
            revocationCursor.accumulateAndGet(batch.latestSequence(), Math::max);
            long policyVersion = Math.max(heartbeat.policyVersion(), batch.latestPolicyVersion());
            AgentLeaseSnapshot current = new AgentLeaseSnapshot(agentId, fingerprint, policyVersion,
                    heartbeat.leaseExpiresAt(), heartbeat.revoked());
            leaseUpdates.accept(current);
            scheduleLeaseExpiry(current);
            if (!batch.events().isEmpty()) {
                closeActiveStreams.run();
                safeStatus("authorization-revoked");
            }
            handleRelayRequests(relayRequests, current);
            if (heartbeat.revoked() || batch.events().stream()
                    .anyMatch(event -> "agent-revoked".equals(event.reason()))) {
                close();
                revokedAction.run();
                return;
            }
            consecutiveFailures = 0;
            safeStatus("online");
            schedule(heartbeatInterval);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            safeStatus("interrupted");
            close();
        } catch (AgentControlPlaneClient.ApiException rejected) {
            if (rejected.statusCode() == 401 || rejected.statusCode() == 403 || rejected.statusCode() == 404) {
                safeStatus("credential-rejected");
                close();
                revokedAction.run();
            } else {
                retry("website-unavailable");
            }
        } catch (Exception transientFailure) {
            retry("website-unavailable");
        } finally {
            inFlight.set(false);
        }
    }

    private void retry(String code) {
        safeStatus(code);
        consecutiveFailures = Math.min(10, consecutiveFailures + 1);
        long base = Math.min(60, 1L << Math.min(6, consecutiveFailures - 1));
        long jitter = java.util.concurrent.ThreadLocalRandom.current().nextLong(Math.max(1, base / 3 + 1));
        schedule(Duration.ofSeconds(base + jitter));
    }

    private void safeStatus(String code) {
        try { statusCode.accept(code); } catch (RuntimeException ignored) { }
    }

    private void scheduleLeaseExpiry(AgentLeaseSnapshot snapshot) {
        latestLease = snapshot;
        ScheduledFuture<?> previous = leaseExpiryTask;
        if (previous != null) previous.cancel(false);
        long delay = Math.max(0, snapshot.leaseExpiresAt().toEpochMilli() - System.currentTimeMillis());
        leaseExpiryTask = scheduler.schedule(() -> {
            if (latestLease == snapshot && !snapshot.leaseExpiresAt().isAfter(java.time.Instant.now())) {
                safeRun(closeActiveStreams);
                safeStatus("authorization-lease-expired");
            }
        }, delay, TimeUnit.MILLISECONDS);
    }

    private void handleRelayRequests(List<AgentControlPlaneClient.RelayOpenRequest> requests,
                                     AgentLeaseSnapshot snapshot) {
        java.time.Instant now = java.time.Instant.now();
        java.util.Set<UUID> listed = new java.util.HashSet<>();
        for (AgentControlPlaneClient.RelayOpenRequest request : requests) {
            if (!request.agentId().equals(agentId)
                    || !request.agentKeyFingerprint().equals(fingerprint.value())
                    || request.policyVersion() != snapshot.policyVersion()
                    || !request.authorizationLeaseExpiresAt().isAfter(now)) {
                continue;
            }
            listed.add(request.tunnelId());
            java.time.Instant previousExpiry = handledRelayRequests.get(request.tunnelId());
            if (previousExpiry == null && !request.ticketExpiresAt().isAfter(now)) {
                // A process restart cannot revive an old one-use ticket. A new A-side
                // access request must create a fresh tunnel before C opens another carrier.
                continue;
            }
            handledRelayRequests.put(request.tunnelId(), request.authorizationLeaseExpiresAt());
            // Refresh an existing relay after Website renews its user authorization lease.
            // If the one-use ticket is already expired, the runtime only accepts this update
            // for an already-open tunnel and will refuse to create a new carrier.
            if (previousExpiry != null && !request.authorizationLeaseExpiresAt().isAfter(previousExpiry)) continue;
            try {
                CompletionStage<Void> opening = Objects.requireNonNull(relayOpenHandler.apply(request),
                        "relay open handler returned null");
                opening.whenComplete((ignored, error) -> {
                    if (error != null) {
                        handledRelayRequests.remove(request.tunnelId(), request.ticketExpiresAt());
                        safeStatus("relay-open-failed");
                    }
                });
            } catch (RuntimeException error) {
                handledRelayRequests.remove(request.tunnelId(), request.ticketExpiresAt());
                safeStatus("relay-open-failed");
            }
        }
        for (UUID missingTunnel : new java.util.HashSet<>(handledRelayRequests.keySet())) {
            if (listed.contains(missingTunnel)) continue;
            handledRelayRequests.remove(missingTunnel);
            try { relayCloseHandler.accept(missingTunnel); }
            catch (RuntimeException ignored) { safeStatus("relay-close-failed"); }
        }
    }

    private static void safeRun(Runnable action) {
        try { action.run(); } catch (RuntimeException ignored) { }
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) return;
        ScheduledFuture<?> task = scheduled;
        if (task != null) task.cancel(true);
        ScheduledFuture<?> expiry = leaseExpiryTask;
        if (expiry != null) expiry.cancel(false);
    }
}
