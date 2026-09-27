package com.jlshell.link.client;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.signal.ControlSignal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;

/** Routes authenticated Client WSS control messages to one ICE generation at a time. */
public final class ClientIceSignalBroker implements SignaledIceDirectPathProvider.Signaling, AutoCloseable {
    private static final int MAX_INVITES = 128;
    private static final int MAX_LISTENERS = 512;

    private final Map<LinkSessionId, ControlSignal.SessionInvite> invites = new ConcurrentHashMap<>();
    private final Map<LinkSessionId, CompletableFuture<ControlSignal.SessionInvite>> inviteWaiters =
            new ConcurrentHashMap<>();
    private final Map<SessionGeneration, CopyOnWriteArrayList<Registration>> listeners = new ConcurrentHashMap<>();
    private final Object inviteLock = new Object();
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile Function<ControlSignal, ? extends CompletionStage<Void>> sender;
    private final AtomicInteger listenerCount = new AtomicInteger();

    /** Called once by the authenticated Client WSS connection. */
    public void attachSender(Function<ControlSignal, ? extends CompletionStage<Void>> sender) {
        Objects.requireNonNull(sender, "sender");
        if (closed.get()) throw new IllegalStateException("ICE signal broker is closed");
        if (this.sender != null) throw new IllegalStateException("ICE signal sender is already attached");
        this.sender = sender;
    }

    /** Called only after the WSS peer identity and READY frame have been validated. */
    public void accept(ControlSignal signal) {
        Objects.requireNonNull(signal, "signal");
        if (closed.get()) return;
        if (signal instanceof ControlSignal.SessionInvite invite) {
            if (!invite.expiresAt().isAfter(Instant.now())) return;
            synchronized (inviteLock) {
                if (closed.get()) return;
                invites.compute(invite.sessionId(), (ignored, previous) -> previous == null
                        || invite.generation() > previous.generation() ? invite : previous);
                CompletableFuture<ControlSignal.SessionInvite> waiter = inviteWaiters.remove(invite.sessionId());
                if (waiter != null) waiter.complete(invites.get(invite.sessionId()));
                trimInvites();
            }
            return;
        }
        if (signal instanceof ControlSignal.SessionRevoked) {
            notifySession(signal.sessionId(), signal);
            invites.remove(signal.sessionId());
            CompletableFuture<ControlSignal.SessionInvite> waiter = inviteWaiters.remove(signal.sessionId());
            if (waiter != null) waiter.completeExceptionally(new SecurityException("Website session was revoked"));
            return;
        }
        notifyGeneration(signal.sessionId(), signal.generation(), signal);
    }

    @Override
    public CompletionStage<ControlSignal.SessionInvite> awaitInvite(LinkSessionId sessionId) {
        Objects.requireNonNull(sessionId, "sessionId");
        if (closed.get()) return CompletableFuture.failedFuture(new IllegalStateException("ICE signal broker is closed"));
        synchronized (inviteLock) {
            if (closed.get()) return CompletableFuture.failedFuture(
                    new IllegalStateException("ICE signal broker is closed"));
            ControlSignal.SessionInvite current = invites.get(sessionId);
            if (current != null && current.expiresAt().isAfter(Instant.now())) {
                invites.remove(sessionId, current);
                return CompletableFuture.completedFuture(current);
            }
            if (current != null) invites.remove(sessionId, current);
            if (inviteWaiters.size() >= MAX_INVITES && !inviteWaiters.containsKey(sessionId)) {
                return CompletableFuture.failedFuture(new IllegalStateException("too many pending Link invitations"));
            }
            return inviteWaiters.computeIfAbsent(sessionId, ignored -> new CompletableFuture<>());
        }
    }

    @Override
    public SignaledIceDirectPathProvider.Subscription listen(LinkSessionId sessionId, long generation,
            Consumer<ControlSignal> signals, Consumer<Throwable> failure) {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(signals, "signals");
        Objects.requireNonNull(failure, "failure");
        if (generation < 1 || closed.get()) throw new IllegalStateException("ICE signal broker is unavailable");
        if (listenerCount.incrementAndGet() > MAX_LISTENERS) {
            listenerCount.decrementAndGet();
            throw new IllegalStateException("too many active ICE signal listeners");
        }
        SessionGeneration key = new SessionGeneration(sessionId, generation);
        Registration registration = new Registration(signals, failure);
        if (closed.get()) {
            listenerCount.decrementAndGet();
            throw new IllegalStateException("ICE signal broker is closed");
        }
        listeners.computeIfAbsent(key, ignored -> new CopyOnWriteArrayList<>()).add(registration);
        if (closed.get()) {
            remove(key, registration);
            throw new IllegalStateException("ICE signal broker is closed");
        }
        return () -> remove(key, registration);
    }

    @Override
    public CompletionStage<Void> send(ControlSignal signal) {
        Objects.requireNonNull(signal, "signal");
        if (closed.get()) return CompletableFuture.failedFuture(new IllegalStateException("ICE signal broker is closed"));
        if (signal instanceof ControlSignal.SessionInvite || signal instanceof ControlSignal.SessionRevoked) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("session state is Website-owned"));
        }
        Function<ControlSignal, ? extends CompletionStage<Void>> current = sender;
        if (current == null) return CompletableFuture.failedFuture(new IllegalStateException("Client WSS is not ready"));
        try { return Objects.requireNonNull(current.apply(signal), "control sender returned no stage"); }
        catch (RuntimeException error) { return CompletableFuture.failedFuture(error); }
    }

    /** Fails in-flight ICE generations while keeping the broker reusable after WSS reconnect. */
    public void connectionLost(Throwable cause) {
        Throwable failure = Objects.requireNonNull(cause, "cause");
        if (closed.get()) return;
        synchronized (inviteLock) {
            invites.clear();
            inviteWaiters.values().forEach(waiter -> waiter.completeExceptionally(failure));
            inviteWaiters.clear();
        }
        listeners.values().forEach(entries -> entries.forEach(entry -> safeFailure(entry, failure)));
        listeners.clear();
        listenerCount.set(0);
    }

    private void notifyGeneration(LinkSessionId sessionId, long generation, ControlSignal signal) {
        List<Registration> entries = listeners.get(new SessionGeneration(sessionId, generation));
        if (entries == null) return;
        for (Registration entry : entries) {
            try { entry.signals.accept(signal); }
            catch (RuntimeException failure) { safeFailure(entry, failure); }
        }
    }

    private void notifySession(LinkSessionId sessionId, ControlSignal signal) {
        for (Map.Entry<SessionGeneration, CopyOnWriteArrayList<Registration>> entry : listeners.entrySet()) {
            if (!entry.getKey().sessionId().equals(sessionId)) continue;
            for (Registration registration : entry.getValue()) {
                try { registration.signals.accept(signal); }
                catch (RuntimeException failure) { safeFailure(registration, failure); }
            }
        }
    }

    private static void safeFailure(Registration entry, Throwable failure) {
        try { entry.failure.accept(failure); } catch (RuntimeException ignored) { }
    }

    private void remove(SessionGeneration key, Registration registration) {
        CopyOnWriteArrayList<Registration> entries = listeners.get(key);
        if (entries == null || !entries.remove(registration)) return;
        listenerCount.decrementAndGet();
        if (entries.isEmpty()) listeners.remove(key, entries);
    }

    private void trimInvites() {
        if (invites.size() <= MAX_INVITES) return;
        invites.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(Instant.now()));
        if (invites.size() > MAX_INVITES) {
            List<Map.Entry<LinkSessionId, ControlSignal.SessionInvite>> oldest = new ArrayList<>(invites.entrySet());
            oldest.sort(java.util.Comparator.comparing(entry -> entry.getValue().expiresAt()));
            for (int i = 0; i < oldest.size() - MAX_INVITES; i++) {
                invites.remove(oldest.get(i).getKey(), oldest.get(i).getValue());
            }
        }
    }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        inviteWaiters.values().forEach(waiter -> waiter.completeExceptionally(
                new IllegalStateException("ICE signal broker is closed")));
        inviteWaiters.clear();
        synchronized (inviteLock) { invites.clear(); }
        IllegalStateException failure = new IllegalStateException("Client WSS control connection was lost");
        listeners.values().forEach(entries -> entries.forEach(entry -> safeFailure(entry, failure)));
        listeners.clear();
        listenerCount.set(0);
        sender = null;
    }

    private record SessionGeneration(LinkSessionId sessionId, long generation) { }
    private record Registration(Consumer<ControlSignal> signals, Consumer<Throwable> failure) { }
}
