package com.jlshell.link.transport;

import static org.junit.jupiter.api.Assertions.*;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.signal.ControlSignal;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.ice4j.Transport;
import org.ice4j.TransportAddress;
import org.ice4j.ice.*;
import org.junit.jupiter.api.Test;

/** Deterministic binding fixtures; these do not replace real authenticated ICE acceptance. */
class IcePeerReflexiveBindingTest {
    @Test
    void oldCapabilityRejectsLateCandidatesAndCrossGenerationIsAlwaysRejected() throws Exception {
        try (Fixture f = new Fixture(false)) {
            assertThrows(IllegalArgumentException.class, () -> f.ice.accept(f.late("198.51.100.11", 23000)));
        }
        try (Fixture f = new Fixture(true)) {
            var late = f.late("198.51.100.11", 23000);
            assertThrows(SecurityException.class, () -> f.ice.accept(new ControlSignal.IceCandidate(
                    UUID.randomUUID(), f.id, 2, late.candidateId(), late.candidateType(), late.transport(),
                    late.address(), late.port(), late.priority(), late.foundation())));
            assertThrows(IllegalArgumentException.class, () -> f.ice.accept(new ControlSignal.IceCandidate(
                    UUID.randomUUID(), f.id, 1, late.candidateId(), ControlSignal.CandidateType.HOST,
                    late.transport(), late.address(), late.port(), late.priority(), late.foundation())));
            assertThrows(IllegalArgumentException.class, () -> f.ice.accept(new ControlSignal.IceCandidate(
                    UUID.randomUUID(), f.id, 1, late.candidateId(), late.candidateType(), ControlSignal.Transport.TCP,
                    late.address(), late.port(), late.priority(), late.foundation())));
        }
    }

    @Test
    void lateSignalsAreBoundedAndDoNotAddConnectivityChecks() throws Exception {
        try (Fixture f = new Fixture(true)) {
            int before = f.component.getRemoteCandidateCount();
            f.ice.accept(f.late("198.51.100.11", 23000));
            f.ice.accept(f.late("198.51.100.12", 23000));
            assertEquals(before, f.component.getRemoteCandidateCount());
            assertThrows(IllegalArgumentException.class, () -> f.ice.accept(f.late("198.51.100.13", 23000)));
        }
    }

    @Test
    void nominationMustMatchAndPublishingMustCompleteBeforeDataPathOpens() throws Exception {
        try (Fixture f = new Fixture(true)) {
            f.nominate("192.0.2.20", 53000, "198.51.100.30", 24000);
            f.poll();
            assertEquals(1, f.published.size());
            assertEquals(ControlSignal.CandidateType.PEER_REFLEXIVE, f.published.getFirst().candidateType());
            assertFalse(f.ice.selectedPath().toCompletableFuture().isDone());
            assertThrows(SecurityException.class, () -> f.ice.accept(f.late("198.51.100.31", 24000)));
            var remote = f.late("198.51.100.30", 24000);
            f.ice.accept(remote);f.poll();
            assertFalse(f.ice.selectedPath().toCompletableFuture().isDone());
            f.ack.complete(null);f.poll();
            var selected = f.ice.selectedPath().toCompletableFuture().join();
            assertEquals(f.published.getFirst().candidateId(), selected.localCandidateId());
            assertEquals(remote.candidateId(), selected.remoteCandidateId());
            assertThrows(IllegalArgumentException.class, () -> f.ice.accept(f.late("198.51.100.30", 25000)));
        }
    }

    @Test
    void unmatchedEarlyLateSignalCannotOpenTheNominatedPath() throws Exception {
        try (Fixture f = new Fixture(true)) {
            f.ice.accept(f.late("198.51.100.31", 24000));
            f.nominate("192.0.2.20", 53000, "198.51.100.30", 24000);
            f.ack.complete(null);f.poll();
            assertFalse(f.ice.selectedPath().toCompletableFuture().isDone());
        }
    }

    @Test
    void exactEndpointCanKeepItsAuthorizedIdWhenIceDiscoversItsTypeAsPeerReflexive() throws Exception {
        try (Fixture f = new Fixture(true)) {
            var local = f.offeredHost;
            var remote = new RemoteCandidate(new TransportAddress("198.51.100.10", 19000, Transport.UDP),
                    f.component, CandidateType.PEER_REFLEXIVE_CANDIDATE, "f1", 100, null);
            f.setPair(new CandidatePair(local, remote));f.poll();
            var selected = f.ice.selectedPath().toCompletableFuture().join();
            assertEquals(f.initialRemote.candidateId(), selected.remoteCandidateId());
            assertEquals(0, f.published.size());
        }
    }

    @Test
    void controlledHostNominationUsesOnlyItsValidatedMappedEndpoint() throws Exception {
        try (Fixture f = new Fixture(true, false)) {
            var host = f.offeredHost;
            var remote = f.component.getRemoteCandidates().getFirst();
            var checked = new CandidatePair(host, remote);
            f.setPair(checked);f.poll();
            assertFalse(f.ice.selectedPath().toCompletableFuture().isDone());
            var mapped = new PeerReflexiveCandidate(new TransportAddress("192.0.2.30", 53000, Transport.UDP),
                    f.component, host, 100);
            f.validate(new CandidatePair(mapped, remote));f.poll();
            assertEquals(1, f.published.size());
            assertEquals(InetAddress.getByName("192.0.2.30"), f.published.getFirst().address());
            f.ack.complete(null);f.poll();
            assertEquals(f.published.getFirst().candidateId(),
                    f.ice.selectedPath().toCompletableFuture().join().localCandidateId());
        }
    }

    @Test
    void mappingValidatedForAnotherRemoteCannotBindTheNominatedPair() throws Exception {
        try (Fixture f = new Fixture(true, false)) {
            var host = f.offeredHost;
            var mapped = new PeerReflexiveCandidate(new TransportAddress("192.0.2.30", 53000, Transport.UDP),
                    f.component, host, 100);
            var other = new RemoteCandidate(new TransportAddress("198.51.100.20", 19000, Transport.UDP),
                    f.component, CandidateType.SERVER_REFLEXIVE_CANDIDATE, "f2", 100, null);
            f.validate(new CandidatePair(mapped, other));
            f.setPair(new CandidatePair(host, f.component.getRemoteCandidates().getFirst()));f.poll();
            assertFalse(f.ice.selectedPath().toCompletableFuture().isDone());
            assertTrue(f.published.isEmpty());
        }
    }

    private static final class Fixture implements AutoCloseable {
        final LinkSessionId id = LinkSessionId.random();
        final CompletableFuture<Void> ack = new CompletableFuture<>();
        final List<ControlSignal.IceCandidate> published = new ArrayList<>();
        final Ice4jDirectSession ice;
        final Component component;
        final LocalCandidate offeredHost;
        final ControlSignal.IceCandidate initialRemote;
        Fixture(boolean extension) throws Exception { this(extension, true); }
        Fixture(boolean extension, boolean controlling) throws Exception {
            ice = new Ice4jDirectSession(id, 1, controlling, new Ice4jDirectSession.Config(
                    List.of(), 8, Duration.ofSeconds(2), 1200, 100), extension ? c -> {
                        published.add(c);return ack;
                    } : null);
            var field = Ice4jDirectSession.class.getDeclaredField("component");field.setAccessible(true);
            component = (Component) field.get(ice);
            var offered = ice.localOffer().stream().filter(ControlSignal.IceCandidate.class::isInstance)
                    .map(ControlSignal.IceCandidate.class::cast)
                    .filter(c -> c.candidateType() == ControlSignal.CandidateType.HOST).findFirst().orElseThrow();
            offeredHost = component.getLocalCandidates().stream().filter(c ->
                    c.getTransportAddress().getAddress().equals(offered.address())
                    && c.getTransportAddress().getPort() == offered.port()).findFirst().orElseThrow();
            ice.accept(new ControlSignal.IceCredentials(UUID.randomUUID(), id, 1, "abcd", "a".repeat(22)));
            initialRemote = new ControlSignal.IceCandidate(UUID.randomUUID(), id, 1, UUID.randomUUID(),
                    ControlSignal.CandidateType.SERVER_REFLEXIVE, ControlSignal.Transport.UDP,
                    InetAddress.getByName("198.51.100.10"), 19000, 100, "f1");
            ice.accept(initialRemote);
            // Model the end-of-offer state without running unrelated network checks in unit fixtures.
            for (String name : List.of("remoteEnd", "started")) {
                var flag = Ice4jDirectSession.class.getDeclaredField(name);flag.setAccessible(true);flag.set(ice, true);
            }
        }
        ControlSignal.IceCandidate late(String address, int port) throws Exception {
            return new ControlSignal.IceCandidate(UUID.randomUUID(), id, 1, UUID.randomUUID(),
                    ControlSignal.CandidateType.PEER_REFLEXIVE, ControlSignal.Transport.UDP,
                    InetAddress.getByName(address), port, 100, "f1");
        }
        void nominate(String localIp, int localPort, String remoteIp, int remotePort) throws Exception {
            var local = new PeerReflexiveCandidate(new TransportAddress(localIp, localPort, Transport.UDP),
                    component, offeredHost, 100);
            var remote = new RemoteCandidate(new TransportAddress(remoteIp, remotePort, Transport.UDP),
                    component, CandidateType.PEER_REFLEXIVE_CANDIDATE, "f1", 100, null);
            setPair(new CandidatePair(local, remote));
        }
        void setPair(CandidatePair pair) throws Exception {
            var setter = Component.class.getDeclaredMethod("setSelectedPair", CandidatePair.class);
            setter.setAccessible(true);setter.invoke(component, pair);
        }
        void validate(CandidatePair pair) throws Exception {
            var method = IceMediaStream.class.getDeclaredMethod("addToValidList", CandidatePair.class);
            method.setAccessible(true);method.invoke(component.getParentStream(), pair);
        }
        void poll() throws Exception {
            var method = Ice4jDirectSession.class.getDeclaredMethod("pollSelection");method.setAccessible(true);
            method.invoke(ice);
        }
        public void close() { ice.close(); }
    }
}
