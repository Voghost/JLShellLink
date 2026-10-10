package com.jlshell.link.transport;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.signal.ControlSignal;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.Agent;
import org.ice4j.ice.CandidateType;
import org.ice4j.ice.Component;
import org.ice4j.ice.IceMediaStream;
import org.ice4j.ice.KeepAliveStrategy;
import org.ice4j.ice.RemoteCandidate;
import org.ice4j.ice.harvest.StunCandidateHarvester;

/**
 * One bounded ICE generation for an authorized A-C session. The caller owns
 * signaling, authorization and the returned session; this class never logs
 * candidate addresses or ICE credentials.
 */
public final class Ice4jDirectSession implements AutoCloseable {
    private static final String STREAM_NAME = "jlshell-link";
    private static final long POLL_MILLIS = 20;
    private static final Object ICE4J_INIT_LOCK = new Object();
    private static volatile boolean ice4jPrepared;

    private final LinkSessionId sessionId;
    private final long generation;
    private final Config config;
    private final java.util.function.Function<ControlSignal.IceCandidate, CompletionStage<Void>> candidatePublisher;
    private CompletableFuture<Void> candidatePublished = CompletableFuture.completedFuture(null);
    private int lateRemoteCandidates;
    private int lateLocalCandidates;
    private final Agent agent;
    private final Component component;
    private final Map<UUID, org.ice4j.ice.LocalCandidate> localById;
    private final Map<UUID, RemoteCandidate> remoteById = new HashMap<>();
    private final Map<CandidateKey, UUID> localIdsByCandidate = new HashMap<>();
    private final Map<CandidateKey, UUID> remoteIdsByCandidate = new HashMap<>();
    private final ScheduledExecutorService timer;
    private final CompletableFuture<SelectedPath> selectedPath = new CompletableFuture<>();
    private final AtomicBoolean closed = new AtomicBoolean();
    private boolean remoteCredentialsReceived;
    private boolean remoteEnd;
    private boolean started;
    private boolean localOfferCreated;
    private ScheduledFuture<?> pollTask;
    private ScheduledFuture<?> deadlineTask;
    private volatile SelectedPath selected;

    /**
     * Creates a session and synchronously gathers local UDP candidates. Call
     * this on a worker thread because a configured STUN server may delay
     * candidate gathering.
     */
    public Ice4jDirectSession(LinkSessionId sessionId, long generation,
            boolean controlling, Config config) throws IOException {
        this(sessionId, generation, controlling, config, null);
    }

    /** Late candidates are enabled only when both authenticated peers negotiated the extension. */
    public Ice4jDirectSession(LinkSessionId sessionId, long generation, boolean controlling, Config config,
            java.util.function.Function<ControlSignal.IceCandidate, CompletionStage<Void>> candidatePublisher)
            throws IOException {
        this.candidatePublisher = candidatePublisher;
        this.sessionId = Objects.requireNonNull(sessionId, "sessionId");
        if (generation < 1) throw new IllegalArgumentException("generation must be positive");
        this.generation = generation;
        this.config = Objects.requireNonNull(config, "config");
        prepareIce4j();
        Agent createdAgent = new Agent();
        Component createdComponent = null;
        try {
            createdAgent.setControlling(controlling);
            for (InetSocketAddress server : config.stunServers()) {
                createdAgent.addCandidateHarvester(new StunCandidateHarvester(
                        new TransportAddress(server, Transport.UDP)));
            }
            IceMediaStream stream = createdAgent.createMediaStream(STREAM_NAME);
            createdComponent = createdAgent.createComponent(stream, 0, 0, 0,
                    KeepAliveStrategy.SELECTED_ONLY, true);
            GatheredCandidates gathered = collectLocalCandidates(createdComponent, candidatePublisher == null
                    ? config.maxCandidates() : Math.max(1, config.maxCandidates() - 2));
            this.localById = new LinkedHashMap<>(gathered.byId());
            this.localIdsByCandidate.putAll(gathered.idsByCandidate());
            if (localById.isEmpty()) throw new IOException("ICE gathered no usable UDP candidates");
            if (createdComponent.getSocket() == null) throw new IOException("ICE application socket is unavailable");
        } catch (IOException | RuntimeException failure) {
            createdAgent.free();
            throw failure;
        }
        this.agent = createdAgent;
        this.component = createdComponent;
        this.timer = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "jlshell-link-ice-session");
            thread.setDaemon(true);
            return thread;
        });
    }

    /** Creates the once-only ordered signaling offer: credentials, candidates, then ICE_END. */
    public synchronized List<ControlSignal> localOffer() {
        ensureOpen();
        if (localOfferCreated) throw new IllegalStateException("local ICE offer was already created");
        localOfferCreated = true;
        List<ControlSignal> result = new ArrayList<>(localById.size() + 2);
        result.add(new ControlSignal.IceCredentials(UUID.randomUUID(), sessionId, generation,
                agent.getLocalUfrag(), agent.getLocalPassword()));
        localById.forEach((id, candidate) -> result.add(toSignal(id, candidate)));
        result.add(new ControlSignal.IceEnd(UUID.randomUUID(), sessionId, generation));
        return List.copyOf(result);
    }

    /** Accepts a peer ICE message after the caller has authenticated its WSS session. */
    public synchronized void accept(ControlSignal signal) {
        Objects.requireNonNull(signal, "signal");
        ensureOpen();
        if (!sessionId.equals(signal.sessionId()) || generation != signal.generation()) {
            throw new SecurityException("ICE message belongs to another session generation");
        }
        if (signal instanceof ControlSignal.IceCredentials credentials) {
            acceptCredentials(credentials);
        } else if (signal instanceof ControlSignal.IceCandidate candidate) {
            acceptCandidate(candidate);
        } else if (signal instanceof ControlSignal.IceEnd) {
            if (remoteEnd) throw new IllegalArgumentException("remote ICE_END was already received");
            remoteEnd = true;
            startIfReady();
        } else {
            throw new IllegalArgumentException("signal is not an ICE setup message");
        }
    }

    /** Completes when ICE nominates a candidate pair within the configured deadline. */
    public CompletionStage<SelectedPath> selectedPath() {
        return selectedPath;
    }

    public LinkSessionId sessionId() { return sessionId; }

    public long generation() { return generation; }

    private void acceptCredentials(ControlSignal.IceCredentials credentials) {
        if (remoteCredentialsReceived || remoteEnd) {
            throw new IllegalArgumentException("remote ICE credentials must be published once before ICE_END");
        }
        IceMediaStream stream = agent.getStream(STREAM_NAME);
        stream.setRemoteUfrag(credentials.usernameFragment());
        stream.setRemotePassword(credentials.password());
        remoteCredentialsReceived = true;
    }

    private void acceptCandidate(ControlSignal.IceCandidate candidate) {
        if (!remoteCredentialsReceived || (remoteEnd && (candidatePublisher == null || !started
                || selectedPath.isDone() || candidate.candidateType() != ControlSignal.CandidateType.PEER_REFLEXIVE
                || lateRemoteCandidates >= 2))) {
            throw new IllegalArgumentException("remote ICE credentials must precede candidates and ICE_END");
        }
        if (candidate.transport() != ControlSignal.Transport.UDP) {
            throw new IllegalArgumentException("direct ICE currently accepts UDP candidates only");
        }
        if (!usable(candidate.address())) {
            throw new IllegalArgumentException("remote ICE candidate address is not routable");
        }
        if (remoteById.size() >= config.maxCandidates()) {
            throw new IllegalArgumentException("remote ICE candidate limit reached");
        }
        CandidateType type = fromSignal(candidate.candidateType());
        TransportAddress address = new TransportAddress(candidate.address(), candidate.port(), Transport.UDP);
        CandidateKey key = CandidateKey.of(address, type);
        if (remoteById.containsKey(candidate.candidateId()) || remoteIdsByCandidate.containsKey(key)) {
            throw new IllegalArgumentException("remote ICE candidate was duplicated");
        }
        var nominated = component.getSelectedPair();
        if (remoteEnd && nominated != null
                && !address.equals(nominated.getRemoteCandidate().getTransportAddress())) {
            throw new SecurityException("late candidate does not match the nominated ICE peer");
        }
        RemoteCandidate remote = new RemoteCandidate(address, component, type, candidate.foundation(),
                candidate.priority(), null);
        // A late candidate is an authenticated name for an endpoint already discovered by ICE.
        // It must not create new connectivity checks after the initial offer has ended.
        if (!remoteEnd) component.addRemoteCandidate(remote);
        else lateRemoteCandidates++;
        remoteById.put(candidate.candidateId(), remote);
        remoteIdsByCandidate.put(key, candidate.candidateId());
        startIfReady();
    }

    private void startIfReady() {
        if (started || !remoteCredentialsReceived || !remoteEnd || closed.get()) return;
        if (remoteById.isEmpty()) {
            fail(new IOException("peer published no usable ICE candidates"));
            return;
        }
        started = true;
        deadlineTask = timer.schedule(() -> fail(new IOException("ICE connectivity deadline expired")),
                config.connectivityTimeout().toMillis(), TimeUnit.MILLISECONDS);
        pollTask = timer.scheduleWithFixedDelay(this::pollSelection, 0, POLL_MILLIS, TimeUnit.MILLISECONDS);
        try {
            agent.startConnectivityEstablishment();
        } catch (RuntimeException failure) {
            fail(failure);
        }
    }

    private synchronized void pollSelection() {
        if (closed.get() || selectedPath.isDone()) return;
        try {
            var pair = component.getSelectedPair();
            if (pair != null) {
                var localCandidate = pair.getLocalCandidate();
                var remoteCandidate = pair.getRemoteCandidate();
                UUID localId = candidateIdAt(localIdsByCandidate, localCandidate.getTransportAddress());
                if (localId == null && candidatePublisher != null
                        && localCandidate.getType() == CandidateType.PEER_REFLEXIVE_CANDIDATE
                        && lateLocalCandidates < 2 && localById.size() < config.maxCandidates()) {
                    localId = UUID.randomUUID();
                    localById.put(localId, localCandidate);
                    localIdsByCandidate.put(CandidateKey.of(localCandidate.getTransportAddress(),
                            localCandidate.getType()), localId);
                    lateLocalCandidates++;
                    candidatePublished = Objects.requireNonNull(candidatePublisher.apply(
                            toSignal(localId, localCandidate)), "candidate publisher returned no stage")
                            .toCompletableFuture();
                }
                UUID remoteId = candidateIdAt(remoteIdsByCandidate, remoteCandidate.getTransportAddress());
                if (localId == null || remoteId == null) {
                    if (candidatePublisher != null && localId != null
                            && remoteCandidate.getType() == CandidateType.PEER_REFLEXIVE_CANDIDATE) return;
                    throw new IOException("ICE selected a candidate outside the authorized exchange");
                }
                if (!candidatePublished.isDone()) return;
                candidatePublished.join();
                IceSelectedDatagramPath datagrams = new IceSelectedDatagramPath(component.getSocket(),
                        pair.getRemoteCandidate().getTransportAddress(), config.maxDatagramBytes(),
                        config.receiveTimeoutMillis());
                SelectedPath path = new SelectedPath(datagrams, localId, remoteId);
                selected = path;
                if (!selectedPath.complete(path)) path.close();
                cancelTimers();
                return;
            }
            if (agent.getState().isOver()) {
                throw new IOException("ICE connectivity checks did not nominate a candidate pair");
            }
        } catch (IOException | RuntimeException failure) {
            fail(failure);
        }
    }

    private static UUID candidateIdAt(Map<CandidateKey, UUID> candidates, TransportAddress address)
            throws IOException {
        UUID found = null;
        for (var entry : candidates.entrySet()) {
            CandidateKey key = entry.getKey();
            if (key.address().equals(address.getAddress()) && key.port() == address.getPort()) {
                if (found != null && !found.equals(entry.getValue())) {
                    throw new IOException("ICE candidate endpoint is ambiguous");
                }
                found = entry.getValue();
            }
        }
        return found;
    }

    private void fail(Throwable failure) {
        if (selectedPath.completeExceptionally(failure)) close();
    }

    private void cancelTimers() {
        ScheduledFuture<?> poll = pollTask;
        if (poll != null) poll.cancel(false);
        ScheduledFuture<?> deadline = deadlineTask;
        if (deadline != null) deadline.cancel(false);
    }

    private void ensureOpen() {
        if (closed.get()) throw new IllegalStateException("ICE session is closed");
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) return;
        cancelTimers();
        SelectedPath path = selected;
        if (path != null) path.closeDatagrams();
        timer.shutdownNow();
        agent.free();
        if (!selectedPath.isDone()) selectedPath.completeExceptionally(
                new java.util.concurrent.CancellationException("ICE session closed"));
    }

    private static GatheredCandidates collectLocalCandidates(
            Component component, int maxCandidates) {
        List<org.ice4j.ice.LocalCandidate> candidates = component.getLocalCandidates().stream()
                .filter(candidate -> candidate.getTransport() == Transport.UDP)
                .filter(candidate -> supportedType(candidate.getType()))
                .filter(candidate -> candidate.getTransportAddress() instanceof InetSocketAddress socket
                        && !socket.isUnresolved() && usable(socket.getAddress()) && socket.getPort() > 0)
                .sorted(Comparator.comparingLong(org.ice4j.ice.LocalCandidate::getPriority).reversed())
                .limit(maxCandidates)
                .toList();
        Map<UUID, org.ice4j.ice.LocalCandidate> byId = new LinkedHashMap<>();
        Map<CandidateKey, UUID> byCandidate = new HashMap<>();
        for (org.ice4j.ice.LocalCandidate candidate : candidates) {
            CandidateKey key = CandidateKey.of(candidate.getTransportAddress(), candidate.getType());
            if (byCandidate.containsKey(key)) continue;
            if (byCandidate.containsKey(key)) continue;
            UUID id = UUID.randomUUID();
            byId.put(id, candidate);
            byCandidate.put(key, id);
        }
        return new GatheredCandidates(Collections.unmodifiableMap(new LinkedHashMap<>(byId)),
                Map.copyOf(byCandidate));
    }

    private ControlSignal.IceCandidate toSignal(UUID id, org.ice4j.ice.LocalCandidate candidate) {
        InetSocketAddress address = candidate.getTransportAddress();
        return new ControlSignal.IceCandidate(UUID.randomUUID(), sessionId, generation, id,
                toSignal(candidate.getType()), ControlSignal.Transport.UDP, address.getAddress(),
                address.getPort(), candidate.getPriority(), boundedFoundation(candidate.getFoundation()));
    }

    private static boolean supportedType(CandidateType type) {
        return type == CandidateType.HOST_CANDIDATE || type == CandidateType.SERVER_REFLEXIVE_CANDIDATE
                || type == CandidateType.PEER_REFLEXIVE_CANDIDATE;
    }

    private static boolean usable(InetAddress address) {
        return address != null && !address.isAnyLocalAddress() && !address.isLoopbackAddress()
                && !address.isLinkLocalAddress() && !address.isMulticastAddress();
    }

    private static ControlSignal.CandidateType toSignal(CandidateType type) {
        if (type == CandidateType.HOST_CANDIDATE) return ControlSignal.CandidateType.HOST;
        if (type == CandidateType.SERVER_REFLEXIVE_CANDIDATE) return ControlSignal.CandidateType.SERVER_REFLEXIVE;
        if (type == CandidateType.PEER_REFLEXIVE_CANDIDATE) return ControlSignal.CandidateType.PEER_REFLEXIVE;
        throw new IllegalArgumentException("unsupported local ICE candidate type");
    }

    private static CandidateType fromSignal(ControlSignal.CandidateType type) {
        return switch (type) {
            case HOST -> CandidateType.HOST_CANDIDATE;
            case SERVER_REFLEXIVE -> CandidateType.SERVER_REFLEXIVE_CANDIDATE;
            case PEER_REFLEXIVE -> CandidateType.PEER_REFLEXIVE_CANDIDATE;
            case RELAY -> throw new IllegalArgumentException("ICE relay candidates are not used on direct path");
        };
    }

    private static String boundedFoundation(String foundation) {
        if (foundation == null) return "link";
        String safe = foundation.replaceAll("[^A-Za-z0-9+/]", "");
        if (safe.isEmpty()) return "link";
        return safe.length() <= 32 ? safe : safe.substring(0, 32);
    }

    private static void prepareIce4j() {
        if (ice4jPrepared) return;
        synchronized (ICE4J_INIT_LOCK) {
            if (ice4jPrepared) return;
            // Link uses explicitly configured STUN servers; do not probe cloud
            // instance metadata while ice4j initializes its optional AWS mapper.
            System.setProperty("ice4j.harvest.mapping.aws.enabled", "false");
            // ice4j INFO records include raw candidate addresses and ICE credentials.
            // Keep those library details out of desktop/server logs; Link exposes only
            // bounded outcome codes through its own diagnostics surface.
            java.util.logging.Logger.getLogger("org.ice4j").setLevel(java.util.logging.Level.WARNING);
            java.util.logging.Logger.getLogger("org.jitsi").setLevel(java.util.logging.Level.WARNING);
            ice4jPrepared = true;
        }
    }

    public record Config(List<InetSocketAddress> stunServers, int maxCandidates,
                         Duration connectivityTimeout, int maxDatagramBytes,
                         int receiveTimeoutMillis) {
        public Config {
            stunServers = List.copyOf(Objects.requireNonNull(stunServers, "stunServers"));
            if (stunServers.size() > 4) throw new IllegalArgumentException("at most four STUN servers are allowed");
            for (InetSocketAddress server : stunServers) {
                if (server == null || server.isUnresolved() || server.getAddress() == null
                        || server.getPort() < 1 || server.getPort() > 65_535) {
                    throw new IllegalArgumentException("STUN servers must be resolved IP socket addresses");
                }
            }
            if (maxCandidates < 1 || maxCandidates > 32) {
                throw new IllegalArgumentException("maxCandidates must be between 1 and 32");
            }
            if (connectivityTimeout == null || connectivityTimeout.compareTo(Duration.ofMillis(100)) < 0
                    || connectivityTimeout.compareTo(Duration.ofSeconds(30)) > 0) {
                throw new IllegalArgumentException("connectivityTimeout must be between 100ms and 30s");
            }
            if (maxDatagramBytes < 256 || maxDatagramBytes > 65_507) {
                throw new IllegalArgumentException("maxDatagramBytes must be between 256 and 65507");
            }
            if (receiveTimeoutMillis < 10 || receiveTimeoutMillis > 500) {
                throw new IllegalArgumentException("receiveTimeoutMillis must be between 10 and 500");
            }
        }

        @Override public String toString() {
            return "Config[stunServerCount=" + stunServers.size() + ", maxCandidates=" + maxCandidates
                    + ", connectivityTimeout=" + connectivityTimeout + ", maxDatagramBytes=" + maxDatagramBytes
                    + ", receiveTimeoutMillis=" + receiveTimeoutMillis + "]";
        }
    }

    public final class SelectedPath implements AutoCloseable {
        private final IceSelectedDatagramPath datagrams;
        private final UUID localCandidateId;
        private final UUID remoteCandidateId;
        private final AtomicBoolean pathClosed = new AtomicBoolean();

        private SelectedPath(IceSelectedDatagramPath datagrams, UUID localCandidateId, UUID remoteCandidateId) {
            this.datagrams = datagrams;
            this.localCandidateId = localCandidateId;
            this.remoteCandidateId = remoteCandidateId;
        }

        public DatagramPath datagrams() { return datagrams; }

        public ControlSignal.PathReady readySignal() {
            ensureOpen();
            return new ControlSignal.PathReady(UUID.randomUUID(), sessionId, generation,
                    ControlSignal.Path.DIRECT, localCandidateId, remoteCandidateId);
        }

        public UUID localCandidateId() { return localCandidateId; }
        public UUID remoteCandidateId() { return remoteCandidateId; }

        @Override public void close() { Ice4jDirectSession.this.close(); }

        private void closeDatagrams() {
            if (pathClosed.compareAndSet(false, true)) datagrams.close();
        }
    }

    private record CandidateKey(InetAddress address, int port) {
        static CandidateKey of(InetSocketAddress address, CandidateType type) {
            return new CandidateKey(address.getAddress(), address.getPort());
        }
    }

    private record GatheredCandidates(Map<UUID, org.ice4j.ice.LocalCandidate> byId,
                                      Map<CandidateKey, UUID> idsByCandidate) { }
}
