package com.jlshell.link.server;

import com.jlshell.link.core.model.LinkSessionId;
import java.net.InetSocketAddress;
import java.util.Objects;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;

/** Owns B's WSS relay and optional Binding-only STUN listener as one lifecycle unit. */
public final class LinkServer implements AutoCloseable {
    private final WssRelayServer relay;
    private final StunBindingServer stun;
    private final RelayPairingService pairings;
    private final AtomicBoolean running = new AtomicBoolean();

    public LinkServer(WssRelayServer relay, StunBindingServer stun, RelayPairingService pairings) {
        this.relay = Objects.requireNonNull(relay, "relay");
        this.stun = stun;
        this.pairings = Objects.requireNonNull(pairings, "pairings");
    }

    public CompletionStage<BoundEndpoints> start() {
        if (!running.compareAndSet(false, true)) throw new IllegalStateException("Link server already started");
        CompletionStage<InetSocketAddress> relayBound = relay.start();
        CompletionStage<InetSocketAddress> stunBound = stun == null
                ? CompletableFuture.completedFuture(null) : stun.start();
        return relayBound.thenCombine(stunBound, BoundEndpoints::new).whenComplete((ignored, error) -> {
            if (error != null) close();
        });
    }

    public boolean isRunning() {
        return running.get() && relay.isRunning();
    }

    public void closeSession(LinkSessionId sessionId) {
        relay.closeSession(sessionId);
    }

    /** Stop admission first, allow established carriers five seconds to drain, then close them. */
    @Override
    public void close() {
        if (!running.getAndSet(false)) return;
        relay.stopAccepting();
        pairings.close();
        relay.awaitRelayDrain(Duration.ofSeconds(5));
        relay.close();
        if (stun != null) stun.close();
    }

    public record BoundEndpoints(InetSocketAddress relay, InetSocketAddress stun) { }
}
