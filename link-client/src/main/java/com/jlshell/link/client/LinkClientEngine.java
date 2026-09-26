package com.jlshell.link.client;

import com.jlshell.link.core.model.ConnectPolicy;
import com.jlshell.link.core.model.LinkPath;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.ReliableDuplexChannel;
import com.jlshell.link.core.transport.TunnelLease;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/** Process-local A engine: fresh authorization, one-shot loopback SSH entry and bounded leases. */
public final class LinkClientEngine implements AutoCloseable {
    private final Scope scope;
    private final Supplier<Scope> currentScope;
    private final ReauthorizingConnectionFlow.AccessRequestProvider access;
    private final ReauthorizingConnectionFlow.CarrierPlanFactory plans;
    private final ConnectionCoordinator.Config config;
    private final ConnectionCoordinator.Observer observer;
    private final java.util.concurrent.ScheduledExecutorService scheduler;
    private final ConnectionCoordinator coordinator;
    private final ConcurrentHashMap<UUID, ReauthorizingConnectionFlow> flows = new ConcurrentHashMap<>();
    private final Set<CompletableFuture<LocalTunnelLease>> pending = ConcurrentHashMap.newKeySet();
    private final Set<LocalTunnelLease> leases = ConcurrentHashMap.newKeySet();
    private final Semaphore permits;
    private final Duration acceptTimeout;
    private final AtomicBoolean closed = new AtomicBoolean();

    public LinkClientEngine(Scope scope, Supplier<Scope> currentScope,
            ReauthorizingConnectionFlow.AccessRequestProvider access,
            ReauthorizingConnectionFlow.CarrierPlanFactory plans,
            ConnectionCoordinator.Config config, ConnectionCoordinator.Observer observer,
            int maxTunnels, Duration acceptTimeout) {
        this.scope = Objects.requireNonNull(scope, "scope");
        this.currentScope = Objects.requireNonNull(currentScope, "currentScope");
        this.access = Objects.requireNonNull(access, "access");
        this.plans = Objects.requireNonNull(plans, "plans");
        this.config = Objects.requireNonNull(config, "config");
        this.observer = observer == null ? ConnectionCoordinator.Observer.NOOP : observer;
        if (maxTunnels < 1 || maxTunnels > 64) throw new IllegalArgumentException("maxTunnels is out of range");
        if (acceptTimeout == null || acceptTimeout.isZero() || acceptTimeout.isNegative()
                || acceptTimeout.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("acceptTimeout is out of range");
        }
        this.acceptTimeout = acceptTimeout;
        this.permits = new Semaphore(maxTunnels);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(
                Thread.ofPlatform().name("jlshell-link-client-timer").daemon().factory());
        this.coordinator = new ConnectionCoordinator(scheduler);
        scheduler.scheduleAtFixedRate(() -> {
            try {
                if (!scope.equals(currentScope.get())) close();
            } catch (RuntimeException unavailableSession) {
                close();
            }
        }, 1, 1, java.util.concurrent.TimeUnit.SECONDS);
    }

    public CompletionStage<LocalTunnelLease> openTunnel(TunnelRequest request) {
        Objects.requireNonNull(request, "request");
        if (closed.get()) return CompletableFuture.failedFuture(new IllegalStateException("Link engine is closed"));
        if (!scope.equals(request.scope())) {
            return CompletableFuture.failedFuture(new SecurityException("Tunnel request uses another Link scope"));
        }
        if (!scope.equals(currentScope.get())) {
            close();
            return CompletableFuture.failedFuture(new SecurityException("Link account or node identity changed"));
        }
        if (!permits.tryAcquire()) {
            return CompletableFuture.failedFuture(new IllegalStateException("Link tunnel limit reached"));
        }
        if (closed.get()) {
            permits.release();
            return CompletableFuture.failedFuture(new IllegalStateException("Link engine is closed"));
        }
        CompletableFuture<LocalTunnelLease> result = new CompletableFuture<>();
        pending.add(result);
        ReauthorizingConnectionFlow flow = flows.computeIfAbsent(request.agentId(),
                ignored -> new ReauthorizingConnectionFlow(coordinator, Clock.systemUTC()));
        CompletionStage<ConnectionCoordinator.Connection> connecting;
        try {
            connecting = flow.connect(config, request.policy(), 0, request.agentId(), request.target(),
                    access, plans, observer);
        } catch (RuntimeException error) {
            pending.remove(result);
            permits.release();
            return CompletableFuture.failedFuture(error);
        }
        result.whenComplete((lease, error) -> {
            if (result.isCancelled()) connecting.toCompletableFuture().cancel(true);
        });
        connecting.whenComplete((connection, error) -> {
            pending.remove(result);
            if (error != null || result.isDone() || closed.get() || !scope.equals(currentScope.get())) {
                if (!scope.equals(currentScope.get())) close();
                if (connection != null) connection.close();
                permits.release();
                if (!result.isDone()) result.completeExceptionally(error == null
                        ? new SecurityException("Link engine or account scope changed") : error);
                return;
            }
            try {
                ServerSocket listener = new ServerSocket();
                try {
                    listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 1);
                    LocalTunnelLease lease = new LocalTunnelLease(flow.sessionId().orElseThrow(),
                            connection, listener, permits::release);
                    leases.add(lease);
                    lease.closed().whenComplete((ignored, failure) -> leases.remove(lease));
                    if (result.complete(lease)) {
                        try { lease.start(); }
                        catch (RuntimeException startFailure) { lease.close(); }
                        connection.channel().closed().whenComplete((ignored, failure) -> lease.close());
                    } else {
                        lease.close();
                    }
                } catch (Throwable failure) {
                    listener.close();
                    throw failure;
                }
            } catch (Throwable failure) {
                connection.close();
                permits.release();
                result.completeExceptionally(failure);
            }
        });
        return result;
    }

    public CompletionStage<RuntimeSnapshot> status() {
        return CompletableFuture.completedFuture(new RuntimeSnapshot(!closed.get(), leases.size(), pending.size()));
    }

    public CompletionStage<Void> shutdown() {
        close();
        return CompletableFuture.completedFuture(null);
    }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        pending.forEach(result -> result.cancel(true));
        leases.forEach(LocalTunnelLease::close);
        coordinator.close();
        scheduler.shutdownNow();
        flows.clear();
    }

    /** A scope is bound to one Website, account, A identity and protocol generation. */
    public record Scope(String server, String accountId, String clientNodeId, String protocolVersion) {
        public Scope {
            if (blank(server) || blank(accountId) || blank(clientNodeId) || blank(protocolVersion)) {
                throw new IllegalArgumentException("Link scope fields are required");
            }
        }
        private static boolean blank(String value) { return value == null || value.isBlank(); }
    }

    public record TunnelRequest(Scope scope, UUID agentId, TargetEndpoint target, ConnectPolicy policy) {
        public TunnelRequest {
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(agentId, "agentId");
            Objects.requireNonNull(target, "target");
            Objects.requireNonNull(policy, "policy");
        }
    }

    public record RuntimeSnapshot(boolean running, int openTunnels, int pendingTunnels) { }

    /** A single accepted local TCP connection owns this authorized target stream. */
    public final class LocalTunnelLease implements TunnelLease {
        private final LinkSessionId sessionId;
        private final ConnectionCoordinator.Connection connection;
        private final ServerSocket listener;
        private final Runnable releasePermit;
        private final CompletableFuture<Void> closedFuture = new CompletableFuture<>();
        private final AtomicBoolean stopped = new AtomicBoolean();
        private final AtomicInteger directionsFinished = new AtomicInteger();
        private volatile Socket socket;

        private LocalTunnelLease(LinkSessionId sessionId, ConnectionCoordinator.Connection connection,
                ServerSocket listener, Runnable releasePermit) {
            this.sessionId = sessionId;
            this.connection = connection;
            this.listener = listener;
            this.releasePermit = releasePermit;
        }

        public String host() { return "127.0.0.1"; }
        public int port() { return listener.getLocalPort(); }
        @Override public LinkSessionId sessionId() { return sessionId; }
        @Override public TunnelId tunnelId() { return connection.tunnelId(); }
        @Override public LinkPath path() { return connection.path(); }
        @Override public CompletionStage<Void> closed() { return closedFuture; }

        private void start() {
            Thread.ofVirtual().name("jlshell-link-loopback-accept").start(() -> {
                try {
                    listener.setSoTimeout(Math.toIntExact(acceptTimeout.toMillis()));
                    Socket accepted = listener.accept();
                    if (stopped.get()) { accepted.close(); return; }
                    socket = accepted;
                    listener.close();
                    Thread.ofVirtual().name("jlshell-link-loopback-upload").start(() -> upload(accepted));
                    Thread.ofVirtual().name("jlshell-link-loopback-download").start(() -> download(accepted));
                } catch (SocketTimeoutException timeout) {
                    close();
                } catch (IOException error) {
                    if (!stopped.get()) close();
                }
            });
        }

        private void upload(Socket accepted) {
            try {
                byte[] buffer = new byte[16_384];
                int count;
                while (!stopped.get() && (count = accepted.getInputStream().read(buffer)) >= 0) {
                    if (count > 0) connection.channel().write(ByteBuffer.wrap(buffer, 0, count))
                            .toCompletableFuture().get();
                }
                connection.channel().shutdownOutput().toCompletableFuture().get();
                directionFinished();
            } catch (IOException | InterruptedException | ExecutionException | RuntimeException error) {
                if (error instanceof InterruptedException) Thread.currentThread().interrupt();
                close();
            }
        }

        private void download(Socket accepted) {
            try {
                ReliableDuplexChannel channel = connection.channel();
                while (!stopped.get()) {
                    ByteBuffer bytes = channel.read(16_384).toCompletableFuture().get();
                    if (!bytes.hasRemaining()) break;
                    byte[] copy = new byte[bytes.remaining()];
                    bytes.get(copy);
                    accepted.getOutputStream().write(copy);
                }
                accepted.shutdownOutput();
                directionFinished();
            } catch (IOException | InterruptedException | ExecutionException | RuntimeException error) {
                if (error instanceof InterruptedException) Thread.currentThread().interrupt();
                close();
            }
        }

        private void directionFinished() {
            if (directionsFinished.incrementAndGet() == 2) close();
        }

        @Override public void close() {
            if (!stopped.compareAndSet(false, true)) return;
            try { listener.close(); } catch (IOException ignored) { }
            Socket accepted = socket;
            if (accepted != null) try { accepted.close(); } catch (IOException ignored) { }
            connection.close();
            releasePermit.run();
            closedFuture.complete(null);
        }
    }
}
