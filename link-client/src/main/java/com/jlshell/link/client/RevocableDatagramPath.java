package com.jlshell.link.client;

import com.jlshell.link.transport.DatagramPath;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/** Propagates an authorized path's closure to its reliable carrier exactly once. */
final class RevocableDatagramPath implements DatagramPath {
    private final DatagramPath delegate;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private Consumer<Throwable> failure;

    RevocableDatagramPath(DatagramPath delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    @Override public synchronized void setReceiver(Consumer<ByteBuffer> receiver,
            Consumer<Throwable> failure) throws IOException {
        if (!open.get()) throw new IOException("authorized direct path is closed");
        if (this.failure != null) throw new IllegalStateException("receiver already installed");
        Objects.requireNonNull(receiver, "receiver");
        this.failure = Objects.requireNonNull(failure, "failure");
        delegate.setReceiver(packet -> { if (open.get()) receiver.accept(packet); }, this::terminate);
    }

    @Override public void send(ByteBuffer packet) throws IOException {
        if (!open.get()) throw new IOException("authorized direct path is closed");
        delegate.send(packet);
    }

    @Override public boolean isOpen() { return open.get() && delegate.isOpen(); }

    @Override public void close() {
        terminate(new CancellationException("authorized direct path closed"));
    }

    private void terminate(Throwable reason) {
        Consumer<Throwable> notify;
        synchronized (this) {
            if (!open.compareAndSet(true, false)) return;
            notify = failure;
        }
        try { delegate.close(); } finally {
            if (notify != null) notify.accept(reason);
        }
    }
}
