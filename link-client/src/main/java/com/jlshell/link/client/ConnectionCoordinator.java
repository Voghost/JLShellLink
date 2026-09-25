package com.jlshell.link.client;

import com.jlshell.link.core.model.ConnectPolicy;
import com.jlshell.link.core.model.LinkFailure;
import com.jlshell.link.core.model.LinkPath;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.CancellationSignal;
import com.jlshell.link.core.transport.ReliableDuplexChannel;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Selects one secure carrier, then opens exactly one authorized target stream. */
public final class ConnectionCoordinator implements AutoCloseable {
    private final ScheduledExecutorService scheduler;
    private final AtomicLong networkGeneration;
    private final Set<Operation> pending = ConcurrentHashMap.newKeySet();
    private final Object lifecycleLock = new Object();
    private volatile boolean closed;

    public ConnectionCoordinator(ScheduledExecutorService scheduler) {
        this(scheduler, 0);
    }

    public ConnectionCoordinator(ScheduledExecutorService scheduler, long initialNetworkGeneration) {
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
        if (initialNetworkGeneration < 0) throw new IllegalArgumentException("network generation cannot be negative");
        this.networkGeneration = new AtomicLong(initialNetworkGeneration);
    }

    /**
     * Starts path setup for a previously authorized request. Connectors must finish
     * candidate checks and the TLS identity handshake before returning a carrier.
     * The access ticket is passed only to the single target-open operation.
     */
    public ConnectionAttempt connect(Config config, ConnectPolicy policy, long generation,
            TargetRequest targetRequest, CarrierConnector direct, CarrierConnector relay,
            TargetOpener targetOpener, Observer observer) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(targetRequest, "targetRequest");
        Objects.requireNonNull(targetOpener, "targetOpener");
        if (policy != ConnectPolicy.RELAY_ONLY && direct == null) {
            throw new IllegalArgumentException("direct connector is required by the selected policy");
        }
        if (policy != ConnectPolicy.DIRECT_ONLY && relay == null) {
            throw new IllegalArgumentException("relay connector is required by the selected policy");
        }
        Operation operation = new Operation(config, policy, generation, targetRequest,
                direct, relay, targetOpener, observer == null ? Observer.NOOP : observer);
        synchronized (lifecycleLock) {
            if (closed) throw new IllegalStateException("coordinator is closed");
            if (generation != networkGeneration.get()) {
                throw new IllegalArgumentException("attempt uses a stale network generation");
            }
            pending.add(operation);
        }
        operation.start();
        return operation;
    }

    /** Invalidates pending path setup; already-open tunnels remain on their selected path. */
    public void updateNetworkGeneration(long nextGeneration) {
        synchronized (lifecycleLock) {
            long previous = networkGeneration.get();
            if (nextGeneration <= previous) {
                throw new IllegalArgumentException("network generation must increase monotonically");
            }
            networkGeneration.set(nextGeneration);
        }
        pending.stream().filter(operation -> operation.generation < nextGeneration)
                .forEach(operation -> operation.cancel("Network generation changed"));
    }

    @Override
    public void close() {
        synchronized (lifecycleLock) {
            if (closed) return;
            closed = true;
        }
        pending.forEach(operation -> operation.cancel("Coordinator closed"));
    }

    public record Config(Duration directTimeout, Duration relayTimeout, int maxCandidates) {
        public Config {
            positive(directTimeout, "directTimeout");
            positive(relayTimeout, "relayTimeout");
            if (maxCandidates < 1 || maxCandidates > 256) {
                throw new IllegalArgumentException("maxCandidates must be between 1 and 256");
            }
        }

        private static void positive(Duration value, String name) {
            Objects.requireNonNull(value, name);
            try {
                if (value.isZero() || value.isNegative() || value.toMillis() < 1) {
                    throw new IllegalArgumentException(name + " must be at least one millisecond");
                }
                value.toNanos();
            } catch (ArithmeticException overflow) {
                throw new IllegalArgumentException(name + " is too large", overflow);
            }
        }
    }

    /** Secrets are intentionally omitted from the printable representation. */
    public static final class TargetRequest {
        private final TargetEndpoint target;
        private final TunnelId tunnelId;
        private final String accessTicket;

        public TargetRequest(TargetEndpoint target, TunnelId tunnelId, String accessTicket) {
            this.target = Objects.requireNonNull(target, "target");
            this.tunnelId = Objects.requireNonNull(tunnelId, "tunnelId");
            if (accessTicket == null || accessTicket.isBlank()) {
                throw new IllegalArgumentException("access ticket is required");
            }
            this.accessTicket = accessTicket;
        }

        public TargetEndpoint target() { return target; }
        public TunnelId tunnelId() { return tunnelId; }
        public String accessTicket() { return accessTicket; }

        @Override public String toString() { return "TargetRequest[<redacted>]"; }
    }

    /** A connector returns only after this carrier is secure and ready for CONNECT. */
    public interface SecureCarrier extends AutoCloseable {
        LinkPath path();
        /** Releases this carrier lease; implementations must make repeated close safe. */
        @Override void close();
    }

    @FunctionalInterface
    public interface CarrierConnector {
        CompletionStage<? extends SecureCarrier> connect(AttemptContext context);
    }

    @FunctionalInterface
    public interface TargetOpener {
        CompletionStage<? extends ReliableDuplexChannel> open(
                SecureCarrier carrier, TargetRequest request, AttemptContext context);
    }

    public interface AttemptContext extends CancellationSignal {
        long networkGeneration();
        int maxCandidates();
        default CancellationSignal cancellation() { return this; }
    }

    public interface Observer {
        Observer NOOP = event -> { };
        void onPathAttempt(PathAttemptEvent event);
    }

    public enum PathOutcome { READY, FAILED, TIMED_OUT, CANCELLED, TARGET_OPENED, TARGET_FAILED }

    /** Contains no candidate address, credential, ticket, or target details. */
    public record PathAttemptEvent(LinkPath path, PathOutcome outcome, Duration elapsed,
            Optional<LinkFailure.Category> failureCategory) {
        public PathAttemptEvent {
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(outcome, "outcome");
            Objects.requireNonNull(elapsed, "elapsed");
            failureCategory = Objects.requireNonNull(failureCategory, "failureCategory");
        }
    }

    public interface ConnectionAttempt extends AutoCloseable {
        CompletionStage<Connection> result();
        long networkGeneration();
        void cancel();
        @Override default void close() { cancel(); }
    }

    /** Selected path plus live, secret-free byte counters for the opened target stream. */
    public static final class Connection implements AutoCloseable {
        private final LinkPath path;
        private final long networkGeneration;
        private final SecureCarrier carrier;
        private final CountingChannel channel;
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicBoolean carrierReleased = new AtomicBoolean();

        private Connection(LinkPath path, long networkGeneration, SecureCarrier carrier,
                ReliableDuplexChannel channel) {
            this.path = path;
            this.networkGeneration = networkGeneration;
            this.carrier = carrier;
            this.channel = new CountingChannel(channel, this::releaseCarrier);
            channel.closed().whenComplete((ignored, error) -> releaseCarrier());
        }

        public LinkPath path() { return path; }
        public long networkGeneration() { return networkGeneration; }
        public ReliableDuplexChannel channel() { return channel; }
        public long bytesSent() { return channel.bytesSent.get(); }
        public long bytesReceived() { return channel.bytesReceived.get(); }

        @Override public void close() {
            if (closed.compareAndSet(false, true)) {
                channel.close();
            }
        }

        private void releaseCarrier() {
            if (carrierReleased.compareAndSet(false, true)) carrier.close();
        }
    }

    private final class Operation implements ConnectionAttempt {
        private final Config config;
        private final ConnectPolicy policy;
        private final long generation;
        private final TargetRequest targetRequest;
        private final CarrierConnector direct;
        private final CarrierConnector relay;
        private final TargetOpener targetOpener;
        private final Observer observer;
        private final CompletableFuture<Connection> result = new CompletableFuture<>();
        private final AtomicReference<AttemptContextImpl> activeContext = new AtomicReference<>();
        private final AtomicReference<SecureCarrier> selectedCarrier = new AtomicReference<>();
        private final AtomicBoolean targetOpenStarted = new AtomicBoolean();
        private final Object targetOpenLock = new Object();
        private volatile LinkFailure directFailure;
        private volatile LinkPath activePath;
        private volatile long activeStartedAt;

        private Operation(Config config, ConnectPolicy policy, long generation,
                TargetRequest targetRequest, CarrierConnector direct, CarrierConnector relay,
                TargetOpener targetOpener, Observer observer) {
            this.config = config;
            this.policy = policy;
            this.generation = generation;
            this.targetRequest = targetRequest;
            this.direct = direct;
            this.relay = relay;
            this.targetOpener = targetOpener;
            this.observer = observer;
        }

        private void start() {
            LinkPath first = policy == ConnectPolicy.RELAY_ONLY ? LinkPath.RELAY : LinkPath.DIRECT;
            tryPath(first);
        }

        private void tryPath(LinkPath path) {
            if (result.isDone()) return;
            if (generation != networkGeneration.get()) {
                cancel("Network generation changed");
                return;
            }
            CarrierConnector connector = path == LinkPath.DIRECT ? direct : relay;
            Duration timeout = path == LinkPath.DIRECT ? config.directTimeout() : config.relayTimeout();
            AttemptContextImpl context = new AttemptContextImpl(generation, config.maxCandidates());
            activeContext.set(context);
            long started = System.nanoTime();
            activePath = path;
            activeStartedAt = started;
            CompletionStage<? extends SecureCarrier> connection;
            try {
                connection = Objects.requireNonNull(connector.connect(context), "connector returned null stage");
            } catch (RuntimeException error) {
                pathFailed(path, started, context, error, false);
                return;
            }

            CompletableFuture<SecureCarrier> bounded = new CompletableFuture<>();
            ScheduledFuture<?> timer;
            try {
                timer = scheduler.schedule(() -> {
                    bounded.completeExceptionally(new LinkFailure(
                            path == LinkPath.DIRECT ? "direct.timeout" : "relay.timeout",
                            path == LinkPath.DIRECT ? LinkFailure.Category.DIRECT_TIMEOUT
                                    : LinkFailure.Category.TRANSIENT_NETWORK,
                            "Secure carrier setup timed out"));
                    context.cancel();
                }, timeout.toNanos(), TimeUnit.NANOSECONDS);
            } catch (RuntimeException schedulerFailure) {
                context.cancel();
                pathFailed(path, started, context, new LinkFailure("coordinator.timeout_unavailable",
                        LinkFailure.Category.PROTOCOL, "Carrier timeout could not be scheduled"), false);
                return;
            }
            connection.whenComplete((carrier, error) -> {
                if (error != null) {
                    bounded.completeExceptionally(unwrap(error));
                } else if (carrier == null) {
                    bounded.completeExceptionally(new LinkFailure("carrier.empty",
                            LinkFailure.Category.PROTOCOL, "Carrier connector returned no carrier"));
                } else {
                    LinkPath actualPath;
                    try {
                        actualPath = carrier.path();
                    } catch (RuntimeException invalidCarrier) {
                        closeQuietly(carrier);
                        bounded.completeExceptionally(new LinkFailure("carrier.invalid",
                                LinkFailure.Category.PROTOCOL, "Carrier metadata could not be read"));
                        return;
                    }
                    if (actualPath != path) {
                        closeQuietly(carrier);
                        bounded.completeExceptionally(new LinkFailure("carrier.path_mismatch",
                                LinkFailure.Category.PROTOCOL, "Carrier path did not match the connector"));
                    } else if (!bounded.complete(carrier)) {
                        closeQuietly(carrier);
                    }
                }
            });
            bounded.whenComplete((carrier, error) -> {
                timer.cancel(false);
                if (result.isDone()) {
                    if (carrier != null) closeQuietly(carrier);
                    return;
                }
                if (error != null) {
                    pathFailed(path, started, context, unwrap(error), isSetupTimeout(error));
                } else {
                    selectedCarrier.set(carrier);
                    notifyObserver(path, PathOutcome.READY, started, null);
                    openTarget(path, carrier, context);
                }
            });
        }

        private void pathFailed(LinkPath path, long started, AttemptContextImpl context,
                Throwable error, boolean timedOut) {
            if (result.isDone()) return;
            Throwable cause = unwrap(error);
            LinkFailure failure = asLinkFailure(path, cause, timedOut);
            PathOutcome outcome = cause instanceof CancellationException
                    || failure.category() == LinkFailure.Category.CANCELLED
                    ? PathOutcome.CANCELLED : timedOut ? PathOutcome.TIMED_OUT : PathOutcome.FAILED;
            context.cancel();
            notifyObserver(path, outcome, started, failure);
            if (result.isDone()) return;
            if (path == LinkPath.DIRECT && policy == ConnectPolicy.AUTO && failure.retryableAcrossPath()) {
                directFailure = failure;
                activePath = null;
                tryPath(LinkPath.RELAY);
                return;
            }
            if (directFailure != null && path == LinkPath.RELAY) {
                failure.addSuppressed(directFailure);
            }
            finishFailure(failure);
        }

        private void openTarget(LinkPath path, SecureCarrier carrier, AttemptContextImpl context) {
            long targetStarted = System.nanoTime();
            CompletionStage<? extends ReliableDuplexChannel> opening;
            synchronized (targetOpenLock) {
                if (!targetOpenStarted.compareAndSet(false, true)) {
                    closeQuietly(carrier);
                    finishFailure(new LinkFailure("target.duplicate_open", LinkFailure.Category.PROTOCOL,
                            "Target stream open was requested more than once"));
                    return;
                }
                if (result.isDone() || context.isCancelled() || generation != networkGeneration.get()) {
                    closeQuietly(carrier);
                    cancel("Attempt invalidated before target open");
                    return;
                }
                try {
                    opening = Objects.requireNonNull(targetOpener.open(carrier, targetRequest, context),
                            "target opener returned null stage");
                } catch (RuntimeException error) {
                    notifyObserver(path, PathOutcome.TARGET_FAILED, targetStarted,
                            asLinkFailure(path, unwrap(error), false));
                    closeQuietly(carrier);
                    finishFailure(unwrap(error));
                    return;
                }
            }
            opening.whenComplete((channel, error) -> {
                if (result.isDone()) {
                    if (channel != null) channel.close();
                    closeQuietly(carrier);
                    return;
                }
                if (error != null) {
                    notifyObserver(path, PathOutcome.TARGET_FAILED, targetStarted,
                            asLinkFailure(path, unwrap(error), false));
                    closeQuietly(carrier);
                    finishFailure(unwrap(error));
                    return;
                }
                if (channel == null) {
                    notifyObserver(path, PathOutcome.TARGET_FAILED, targetStarted,
                            new LinkFailure("target.empty", LinkFailure.Category.PROTOCOL,
                                    "Target opener returned no tunnel"));
                    closeQuietly(carrier);
                    finishFailure(new LinkFailure("target.empty", LinkFailure.Category.PROTOCOL,
                            "Target opener returned no tunnel"));
                    return;
                }
                notifyObserver(path, PathOutcome.TARGET_OPENED, targetStarted, null);
                Connection opened = new Connection(path, generation, carrier, channel);
                if (!result.complete(opened)) opened.close();
                pending.remove(this);
                AttemptContextImpl completedContext = activeContext.getAndSet(null);
                if (completedContext != null) completedContext.cancel();
                selectedCarrier.set(null);
                activePath = null;
            });
        }

        private void notifyObserver(LinkPath path, PathOutcome outcome, long started, LinkFailure failure) {
            Optional<LinkFailure.Category> category = failure == null
                    ? Optional.empty() : Optional.of(failure.category());
            try {
                observer.onPathAttempt(new PathAttemptEvent(path, outcome,
                        Duration.ofNanos(Math.max(0, System.nanoTime() - started)), category));
            } catch (RuntimeException ignored) {
                // Diagnostics must never change authorization or connection behavior.
            }
        }

        private void finishFailure(Throwable failure) {
            SecureCarrier carrier = selectedCarrier.getAndSet(null);
            if (carrier != null) closeQuietly(carrier);
            result.completeExceptionally(failure);
            pending.remove(this);
            AttemptContextImpl context = activeContext.getAndSet(null);
            if (context != null) context.cancel();
            activePath = null;
        }

        @Override public CompletionStage<Connection> result() { return result.minimalCompletionStage(); }
        @Override public long networkGeneration() { return generation; }

        @Override public void cancel() { cancel("Connection attempt cancelled"); }

        private void cancel(String reason) {
            if (result.isDone()) return;
            synchronized (targetOpenLock) {
                if (result.isDone()) return;
                LinkPath path = activePath;
                if (path != null) {
                    notifyObserver(path, PathOutcome.CANCELLED, activeStartedAt,
                            new LinkFailure("connection.cancelled", LinkFailure.Category.CANCELLED, reason));
                }
                AttemptContextImpl context = activeContext.getAndSet(null);
                if (context != null) context.cancel();
                SecureCarrier carrier = selectedCarrier.getAndSet(null);
                if (carrier != null) closeQuietly(carrier);
                result.completeExceptionally(new LinkFailure("connection.cancelled",
                        LinkFailure.Category.CANCELLED, reason));
                pending.remove(this);
                activePath = null;
            }
        }
    }

    private static final class AttemptContextImpl implements AttemptContext {
        private final long generation;
        private final int maxCandidates;
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final CompletableFuture<Void> cancellation = new CompletableFuture<>();

        private AttemptContextImpl(long generation, int maxCandidates) {
            this.generation = generation;
            this.maxCandidates = maxCandidates;
        }

        @Override public long networkGeneration() { return generation; }
        @Override public int maxCandidates() { return maxCandidates; }
        @Override public CancellationSignal cancellation() { return this; }
        @Override public boolean isCancelled() { return cancelled.get(); }
        @Override public CompletionStage<Void> cancelled() { return cancellation.minimalCompletionStage(); }

        private void cancel() {
            if (cancelled.compareAndSet(false, true)) cancellation.complete(null);
        }
    }

    private static final class CountingChannel implements ReliableDuplexChannel {
        private final ReliableDuplexChannel delegate;
        private final Runnable releaseCarrier;
        private final AtomicLong bytesSent = new AtomicLong();
        private final AtomicLong bytesReceived = new AtomicLong();

        private CountingChannel(ReliableDuplexChannel delegate, Runnable releaseCarrier) {
            this.delegate = delegate;
            this.releaseCarrier = releaseCarrier;
        }

        @Override public CompletionStage<ByteBuffer> read(int maxBytes) {
            return delegate.read(maxBytes).thenApply(bytes -> {
                bytesReceived.addAndGet(bytes.remaining());
                return bytes;
            });
        }

        @Override public CompletionStage<Void> write(ByteBuffer data) {
            int count = data.remaining();
            return delegate.write(data).thenRun(() -> bytesSent.addAndGet(count));
        }

        @Override public CompletionStage<Void> whenWritable() { return delegate.whenWritable(); }
        @Override public CompletionStage<Void> shutdownOutput() { return delegate.shutdownOutput(); }
        @Override public CompletionStage<Void> closed() { return delegate.closed(); }
        @Override public void abort(Throwable cause) {
            try { delegate.abort(cause); } finally { releaseCarrier.run(); }
        }
        @Override public void close() {
            try { delegate.close(); } finally { releaseCarrier.run(); }
        }
    }

    private static boolean isSetupTimeout(Throwable error) {
        Throwable cause = unwrap(error);
        return cause instanceof LinkFailure failure
                && (failure.category() == LinkFailure.Category.DIRECT_TIMEOUT
                        || failure.code().equals("relay.timeout"));
    }

    private static LinkFailure asLinkFailure(LinkPath path, Throwable error, boolean timedOut) {
        Throwable cause = unwrap(error);
        if (cause instanceof LinkFailure failure) return failure;
        if (cause instanceof CancellationException) {
            return new LinkFailure("connection.cancelled", LinkFailure.Category.CANCELLED,
                    "Carrier setup was cancelled");
        }
        if (timedOut) {
            return new LinkFailure(path == LinkPath.DIRECT ? "direct.timeout" : "relay.timeout",
                    path == LinkPath.DIRECT ? LinkFailure.Category.DIRECT_TIMEOUT
                            : LinkFailure.Category.TRANSIENT_NETWORK,
                    "Secure carrier setup timed out");
        }
        // Unknown errors fail closed; only explicitly classified network errors may use B.
        return new LinkFailure("carrier.failure", LinkFailure.Category.PROTOCOL,
                "Carrier setup failed without a retryable network classification");
    }

    private static Throwable unwrap(Throwable error) {
        Throwable current = error;
        while ((current instanceof CompletionException || current instanceof java.util.concurrent.ExecutionException)
                && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static void closeQuietly(SecureCarrier carrier) {
        try { carrier.close(); } catch (RuntimeException ignored) { }
    }
}
