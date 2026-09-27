package com.jlshell.link.agent;

import com.jlshell.link.transport.RelayProofClient;

import com.jlshell.link.core.auth.AccessGrantJwsService;
import com.jlshell.link.core.auth.AccessPolicyEvaluator;
import com.jlshell.link.core.auth.InMemoryReplayStore;
import com.jlshell.link.core.identity.Ed25519NodeKey;
import com.jlshell.link.core.identity.NodeProofService;
import com.jlshell.link.core.model.AccessPolicy;
import com.jlshell.link.core.model.AccessRule;
import com.jlshell.link.core.model.CidrBlock;
import com.jlshell.link.core.model.TargetEndpoint;
import com.jlshell.link.core.model.TunnelId;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.TlsHandshakeGate;
import io.netty.channel.nio.NioEventLoopGroup;
import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.URI;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;

/** Foreground C service: owns heartbeat, WSS control, and outbound relay-only carriers. */
final class AgentRuntimeService {
    private AgentRuntimeService() { }

    static void diagnose(AgentIdentityStore identity, URI linkWss, Path tlsIdentity,
                         Path tlsPasswordFile, Path allowedTargetsFile) throws Exception {
        AgentIdentityStore.Registration registration = identity.loadRegistration()
                .orElseThrow(() -> new IllegalStateException("Agent must be enrolled before diagnose"));
        Ed25519NodeKey nodeKey = identity.loadKey()
                .orElseThrow(() -> new IllegalStateException("Agent node key is missing"));
        controlUri(linkWss);
        loadLocalPolicy(allowedTargetsFile);
        char[] password = readOwnerOnly(tlsPasswordFile);
        try { AgentTlsIdentity.load(tlsIdentity, password, nodeKey); }
        finally { Arrays.fill(password, '\0'); }
        try (AgentAuthorityKeys authority = new AgentAuthorityKeys(registration.website())) {
            authority.refresh();
        }
    }

    static void run(AgentIdentityStore identity, Path stateDirectory, URI linkWss,
                    Path tlsIdentity, Path tlsPasswordFile, Path allowedTargetsFile,
                    URI ticketIssuer) throws Exception {
        AgentIdentityStore.Registration registration = identity.loadRegistration()
                .orElseThrow(() -> new IllegalStateException("Agent must be enrolled before run"));
        Ed25519NodeKey nodeKey = identity.loadKey()
                .orElseThrow(() -> new IllegalStateException("Agent node key is missing"));
        AccessPolicy localPolicy = loadLocalPolicy(allowedTargetsFile);
        char[] tlsPassword = readOwnerOnly(tlsPasswordFile);
        AgentTlsIdentity innerIdentity;
        try { innerIdentity = AgentTlsIdentity.load(tlsIdentity, tlsPassword, nodeKey); }
        finally { Arrays.fill(tlsPassword, '\0'); }
        URI controlUri = controlUri(linkWss);
        URI relayUri = controlUri.resolve("/link/v2/relay");
        SSLContext outerTls = SSLContext.getDefault();
        Clock clock = Clock.systemUTC();
        TransportBudget budget = new TransportBudget(65_536, 8_192, 64, 1_048_576,
                131_072, 4_194_304, 16, Duration.ofSeconds(30));
        var scheduler = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "jlshell-link-agent-control");
            thread.setDaemon(true);
            return thread;
        });
        var diagnosticExecutor = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "jlshell-link-agent-diagnostic");
            thread.setDaemon(true);
            return thread;
        });
        var activeDiagnostics = java.util.concurrent.ConcurrentHashMap.<java.util.UUID>newKeySet();
        var eventLoops = new NioEventLoopGroup(2);
        var relay = new AtomicReference<AgentRelayRuntime>();
        var control = new AtomicReference<AgentControlSession>();
        var stopping = new AtomicBoolean();
        var stopped = new java.util.concurrent.CountDownLatch(1);
        Thread shutdownHook = new Thread(() -> {
            stopping.set(true);
            try { stopped.await(10, java.util.concurrent.TimeUnit.SECONDS); }
            catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
        }, "jlshell-link-agent-shutdown");
        Runtime.getRuntime().addShutdownHook(shutdownHook);
        try (AgentServiceControl service = AgentServiceControl.acquire(stateDirectory);
                AgentAuthorityKeys authority = new AgentAuthorityKeys(registration.website());
                RelayProofClient proof = new RelayProofClient(Duration.ofSeconds(10), Duration.ofSeconds(15),
                        new NodeProofService(), java.util.concurrent.ForkJoinPool.commonPool());
                AgentControlPlaneClient api = new AgentControlPlaneClient(registration.website(),
                        Duration.ofSeconds(10), Duration.ofSeconds(15))) {
            authority.refresh();
            var grants = new AccessGrantJwsService(clock, Duration.ofSeconds(30), new InMemoryReplayStore());
            AgentControlSession session = new AgentControlSession(
                    api, registration.credential(), registration.agentId(),
                    nodeKey.fingerprint(), "0.1.0-SNAPSHOT", Set.of("tcp-connect", "target-diagnostic"), scheduler,
                    Duration.ofSeconds(10), lease -> {
                        AgentRelayRuntime current = relay.get();
                        if (current == null) {
                            AgentRelayRuntime created = new AgentRelayRuntime(relayUri,
                                    registration.credential(), registration.agentId(), nodeKey,
                                    outerTls, innerIdentity::forClient, ignored -> localPolicy,
                                    eventLoops, grants, authority, ticketIssuer, lease, proof,
                                    budget, new TlsHandshakeGate(budget.maxConcurrentHandshakes()), clock);
                            if (!relay.compareAndSet(null, created)) created.close();
                        } else {
                            current.updateLease(lease);
                        }
                    }, () -> {
                        AgentRelayRuntime current = relay.get();
                        if (current != null) current.closeAll();
                    }, request -> {
                        AgentRelayRuntime current = relay.get();
                        return current == null
                                ? java.util.concurrent.CompletableFuture.failedFuture(
                                        new IllegalStateException("Agent relay is not ready"))
                                : current.open(request);
                    }, tunnelId -> {
                        AgentRelayRuntime current = relay.get();
                        if (current != null) current.closeTunnel(TunnelId.parse(tunnelId.toString()));
                    }, () -> stopping.set(true), AgentRuntimeService::reportStatus,
                    disconnected -> new AgentControlSignalClient(controlUri, registration.agentId(),
                            nodeKey, registration.credential(), outerTls,
                            ignored -> { }, signal -> {
                                AgentControlSession live = control.get();
                                if (live != null) live.acceptSignal(signal);
                            }, disconnected), revokedSession -> {
                        AgentRelayRuntime current = relay.get();
                        if (current != null) current.closeSession(revokedSession);
                    }, (requests, lease) -> requests.forEach(request -> {
                        if (!activeDiagnostics.add(request.id())) return;
                        try {
                            diagnosticExecutor.execute(() -> {
                                try {
                                    ProbeOutcome outcome = probeTarget(localPolicy, request, lease);
                                    AgentControlSession live = control.get();
                                    if (live != null) {
                                        api.completeConnectivityDiagnostic(registration.credential(),
                                                live.controlSessionId(), request.id(), outcome.result(),
                                                outcome.roundTripMillis());
                                    }
                                } catch (Exception reportFailure) {
                                    reportStatus("connectivity-diagnostic-report-failed");
                                } finally {
                                    activeDiagnostics.remove(request.id());
                                }
                            });
                        } catch (java.util.concurrent.RejectedExecutionException rejected) {
                            activeDiagnostics.remove(request.id());
                            reportStatus("connectivity-diagnostic-queue-full");
                        }
                    }));
            control.set(session);
            try {
                session.start();
                while (!stopping.get() && !service.stopRequested()) {
                    Thread.sleep(250);
                }
            } finally {
                session.close();
            }
        } finally {
            AgentRelayRuntime current = relay.getAndSet(null);
            if (current != null) current.close();
            eventLoops.shutdownGracefully(0, 5, java.util.concurrent.TimeUnit.SECONDS).syncUninterruptibly();
            diagnosticExecutor.shutdownNow();
            scheduler.shutdownNow();
            stopped.countDown();
            try { Runtime.getRuntime().removeShutdownHook(shutdownHook); }
            catch (IllegalStateException shuttingDown) { }
        }
    }

    private static URI controlUri(URI uri) {
        if (uri == null || !"wss".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !"/link/v2/control".equals(uri.getPath())) {
            throw new IllegalArgumentException("--link-wss must be a WSS /link/v2/control URI");
        }
        return uri;
    }

    private static AccessPolicy loadLocalPolicy(Path file) throws IOException {
        verifyOwnerOnlyFile(file);
        List<String> lines = Files.readAllLines(file);
        if (lines.isEmpty() || lines.size() > 256) {
            throw new IOException("local target allowlist must contain 1 to 256 exact targets");
        }
        List<AccessRule> rules = new ArrayList<>();
        for (String raw : lines) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int separator = line.lastIndexOf(':');
            if (separator <= 0 || separator == line.length() - 1) {
                throw new IOException("local target must be a numeric IP and port");
            }
            String address = line.substring(0, separator);
            if (address.startsWith("[") && address.endsWith("]")) {
                address = address.substring(1, address.length() - 1);
            }
            TargetEndpoint target;
            try { target = new TargetEndpoint(address, Integer.parseInt(line.substring(separator + 1))); }
            catch (RuntimeException invalid) { throw new IOException("local target is invalid", invalid); }
            rules.add(new AccessRule(AccessRule.Effect.ALLOW,
                    CidrBlock.exact(target.address()), Set.of(target.port())));
        }
        if (rules.isEmpty()) throw new IOException("local target allowlist denies every target");
        return new AccessPolicy(true, false, 1, rules);
    }

    private static ProbeOutcome probeTarget(AccessPolicy localPolicy,
            AgentControlPlaneClient.ConnectivityDiagnosticRequest request, AgentLeaseSnapshot lease) {
        long started = System.nanoTime();
        if (!request.expiresAt().isAfter(java.time.Instant.now())) {
            return new ProbeOutcome(AgentControlPlaneClient.ConnectivityDiagnosticResult.REQUEST_EXPIRED, 0);
        }
        if (request.policyVersion() != lease.policyVersion()) {
            return new ProbeOutcome(AgentControlPlaneClient.ConnectivityDiagnosticResult.POLICY_CHANGED, 0);
        }
        if (!new AccessPolicyEvaluator().isAllowed(localPolicy, request.target())) {
            return new ProbeOutcome(AgentControlPlaneClient.ConnectivityDiagnosticResult.LOCAL_POLICY_DENIED, 0);
        }
        try (Socket socket = new Socket()) {
            socket.connect(request.target().socketAddress(), 1_500);
            return new ProbeOutcome(AgentControlPlaneClient.ConnectivityDiagnosticResult.CONNECTED,
                    elapsedMillis(started));
        } catch (SocketTimeoutException timeout) {
            return new ProbeOutcome(AgentControlPlaneClient.ConnectivityDiagnosticResult.TIMEOUT,
                    elapsedMillis(started));
        } catch (NoRouteToHostException unreachable) {
            return new ProbeOutcome(AgentControlPlaneClient.ConnectivityDiagnosticResult.NETWORK_UNREACHABLE,
                    elapsedMillis(started));
        } catch (ConnectException refused) {
            return new ProbeOutcome(AgentControlPlaneClient.ConnectivityDiagnosticResult.CONNECTION_REFUSED,
                    elapsedMillis(started));
        } catch (IOException failed) {
            return new ProbeOutcome(AgentControlPlaneClient.ConnectivityDiagnosticResult.CONNECT_FAILED,
                    elapsedMillis(started));
        }
    }

    private static long elapsedMillis(long started) {
        return Math.min(5_000, Math.max(0,
                java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)));
    }

    private record ProbeOutcome(AgentControlPlaneClient.ConnectivityDiagnosticResult result,
                                long roundTripMillis) { }

    static char[] readOwnerOnly(Path file) throws IOException {
        verifyOwnerOnlyFile(file);
        if (Files.size(file) > 4096) throw new IOException("Agent TLS password file is too large");
        char[] value = Files.readString(file).trim().toCharArray();
        if (value.length == 0) throw new IOException("Agent TLS password file is empty");
        return value;
    }

    private static void verifyOwnerOnlyFile(Path file) throws IOException {
        if (file == null || Files.isSymbolicLink(file)
                || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Agent runtime file must be a regular file");
        }
        if (Files.getFileAttributeView(file, java.nio.file.attribute.PosixFileAttributeView.class) != null) {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(file, LinkOption.NOFOLLOW_LINKS);
            if (permissions.stream().anyMatch(permission -> permission.name().startsWith("GROUP_")
                    || permission.name().startsWith("OTHERS_"))) {
                throw new IOException("Agent runtime files must be owner-only (chmod 600)");
            }
        }
    }

    private static void reportStatus(String code) {
        System.out.println("Agent 状态：" + code);
    }
}
