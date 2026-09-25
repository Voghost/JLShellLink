package com.jlshell.link.server.spring;

import com.jlshell.link.server.LinkServer;
import com.jlshell.link.server.LinkServer.BoundEndpoints;
import java.util.Objects;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.context.SmartLifecycle;

/** Spring lifecycle bridge; Website configuration supplies the Website-backed auth and audit adapters. */
public final class LinkServerSmartLifecycle implements SmartLifecycle {
    private final LinkServer server;
    private final AtomicBoolean running = new AtomicBoolean();
    private volatile BoundEndpoints endpoints;

    public LinkServerSmartLifecycle(LinkServer server) {
        this.server = Objects.requireNonNull(server, "server");
    }

    @Override
    public void start() {
        if (!running.compareAndSet(false, true)) return;
        try {
            CompletionStage<BoundEndpoints> starting = server.start();
            endpoints = starting.toCompletableFuture().join();
        } catch (RuntimeException error) {
            running.set(false);
            server.close();
            throw error;
        }
    }

    @Override
    public void stop() {
        if (running.compareAndSet(true, false)) server.close();
    }

    @Override
    public void stop(Runnable callback) {
        try {
            stop();
        } finally {
            callback.run();
        }
    }

    @Override public boolean isRunning() { return running.get() && server.isRunning(); }
    @Override public boolean isAutoStartup() { return true; }
    @Override public int getPhase() { return Integer.MAX_VALUE - 100; }

    public BoundEndpoints endpoints() { return endpoints; }
}
