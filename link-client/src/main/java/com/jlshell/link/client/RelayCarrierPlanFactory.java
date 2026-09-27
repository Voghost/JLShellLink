package com.jlshell.link.client;

import com.jlshell.link.core.identity.LocalNodeKey;
import com.jlshell.link.core.model.LinkPath;
import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.model.NodeKeyFingerprint;
import com.jlshell.link.core.transport.TransportBufferBudget;
import com.jlshell.link.core.transport.TransportBudget;
import com.jlshell.link.transport.ConnectClientMultiplexer;
import com.jlshell.link.transport.RelayProofClient;
import com.jlshell.link.transport.TlsHandshakeGate;
import io.netty.channel.Channel;
import io.netty.channel.EventLoopGroup;
import java.net.URI;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;

/** B challenge + pinned inner mTLS + one HTTP/2 CONNECT for an authorized relay-only grant. */
public final class RelayCarrierPlanFactory implements ReauthorizingConnectionFlow.CarrierPlanFactory {
    private final EventLoopGroup group;
    private final URI relayUri;
    private final UUID deviceId;
    private final LocalNodeKey nodeKey;
    private final Supplier<? extends CompletionStage<String>> controlCredential;
    private final SSLContext outerTls;
    private final Function<NodeKeyFingerprint, SSLContext> innerTlsForAgent;
    private final TransportBudget budget;
    private final TlsHandshakeGate gate;
    private final RelayProofClient proof;
    private final Function<LinkSessionId, ? extends CompletionStage<Void>> activateRelay;

    public RelayCarrierPlanFactory(EventLoopGroup group, URI relayUri, UUID deviceId,
            LocalNodeKey nodeKey, Supplier<? extends CompletionStage<String>> controlCredential,
            SSLContext outerTls, Function<NodeKeyFingerprint, SSLContext> innerTlsForAgent,
            TransportBudget budget, TlsHandshakeGate gate, RelayProofClient proof,
            Function<LinkSessionId, ? extends CompletionStage<Void>> activateRelay) {
        this.group = Objects.requireNonNull(group, "group");
        this.relayUri = Objects.requireNonNull(relayUri, "relayUri");
        this.deviceId = Objects.requireNonNull(deviceId, "deviceId");
        this.nodeKey = Objects.requireNonNull(nodeKey, "nodeKey");
        this.controlCredential = Objects.requireNonNull(controlCredential, "controlCredential");
        this.outerTls = Objects.requireNonNull(outerTls, "outerTls");
        this.innerTlsForAgent = Objects.requireNonNull(innerTlsForAgent, "innerTlsForAgent");
        this.budget = Objects.requireNonNull(budget, "budget");
        this.gate = Objects.requireNonNull(gate, "gate");
        this.proof = Objects.requireNonNull(proof, "proof");
        this.activateRelay = Objects.requireNonNull(activateRelay, "activateRelay");
        if (!"wss".equalsIgnoreCase(relayUri.getScheme()) || !"/link/v2/relay".equals(relayUri.getPath())
                || relayUri.getHost() == null || relayUri.getUserInfo() != null
                || relayUri.getRawQuery() != null || relayUri.getRawFragment() != null) {
            throw new IllegalArgumentException("relayUri must be the dedicated WSS Link relay endpoint");
        }
    }

    @Override
    public ReauthorizingConnectionFlow.PathPlan create(ReauthorizingConnectionFlow.AuthorizedTunnel grant) {
        Objects.requireNonNull(grant, "grant");
        NodeKeyFingerprint expectedAgent = Objects.requireNonNull(grant.agentKeyFingerprint(),
                "Website grant must bind an Agent key fingerprint");
        // A fresh context per grant prevents one tunnel's inner TLS session from resuming on another.
        SSLContext innerTls = Objects.requireNonNull(innerTlsForAgent.apply(expectedAgent),
                "inner TLS context must pin the Website-bound Agent key");
        ConnectionCoordinator.CarrierConnector relay = context -> {
            CompletionStage<Void> activated;
            try {
                activated = Objects.requireNonNull(activateRelay.apply(grant.sessionId()),
                        "Relay activation returned no stage");
            } catch (RuntimeException failure) {
                return CompletableFuture.failedFuture(failure);
            }
            return activated.thenCompose(ignored -> {
                if (context.isCancelled()) {
                    return CompletableFuture.failedFuture(new CancellationException("Relay setup was cancelled"));
                }
                return controlCredential.get().thenCompose(credential -> proof.connectClient(group, relayUri,
                        credential, deviceId, grant.agentId(), grant.sessionId(), grant.tunnelId(), nodeKey,
                        expectedAgent, outerTls, innerTls, relayUri.getHost(),
                        relayUri.getPort() < 0 ? 443 : relayUri.getPort(), budget, gate));
            }).thenApply(channel -> (ConnectionCoordinator.SecureCarrier) new Carrier(channel));
        };
        ConnectionCoordinator.TargetOpener open = (carrier, request, context) -> {
            if (!(carrier instanceof Carrier selected)) {
                throw new IllegalArgumentException("relay target opener requires a relay carrier");
            }
            return new ConnectClientMultiplexer(selected.channel, budget,
                    new TransportBufferBudget(budget.maxBufferedBytesTotal()))
                    .open(request.target(), request.tunnelId(), request.accessTicket());
        };
        return new ReauthorizingConnectionFlow.PathPlan(null, relay, open);
    }

    private static final class Carrier implements ConnectionCoordinator.SecureCarrier {
        private final Channel channel;

        private Carrier(Channel channel) { this.channel = Objects.requireNonNull(channel, "channel"); }
        @Override public LinkPath path() { return LinkPath.RELAY; }
        @Override public void close() { channel.close(); }
    }
}
