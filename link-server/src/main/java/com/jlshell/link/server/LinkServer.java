package com.jlshell.link.server;

import java.net.InetSocketAddress;
import java.util.Objects;
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

    /** Stop accepting work, discard half-open pairs, then close listeners and their event loops. */
    @Override
    public void close() {
        if (!running.getAndSet(false)) return;
        pairings.close();
        relay.close();
        if (stun != null) stun.close();
    }

    public record BoundEndpoints(InetSocketAddress relay, InetSocketAddress stun) { }
}
