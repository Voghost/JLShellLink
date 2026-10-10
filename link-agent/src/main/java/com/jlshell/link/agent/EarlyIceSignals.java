package com.jlshell.link.agent;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.signal.ControlSignal;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/** Bounded, ordered offer delivery while the authorized ICE session gathers candidates. */
final class EarlyIceSignals implements AutoCloseable {
    private final LinkSessionId session;
    private final long generation;
    private final List<ControlSignal> pending = new ArrayList<>();
    private Consumer<ControlSignal> destination;
    private boolean closed;

    EarlyIceSignals(LinkSessionId session, long generation) {
        this.session = session;
        this.generation = generation;
    }

    synchronized void accept(ControlSignal signal) {
        if (closed) return;
        if (!session.equals(signal.sessionId()) || generation != signal.generation()) {
            throw new SecurityException("ICE offer belongs to another authorized generation");
        }
        if (!(signal instanceof ControlSignal.IceCredentials || signal instanceof ControlSignal.IceCandidate
                || signal instanceof ControlSignal.IceEnd)) throw new IllegalArgumentException("not an ICE offer");
        if (destination != null) destination.accept(signal);
        else {
            if (pending.size() >= 34) {
                close();
                throw new IllegalStateException("early ICE offer limit exceeded");
            }
            pending.add(signal);
        }
    }

    synchronized void attach(Consumer<ControlSignal> receiver) {
        if (closed) return;
        if (destination != null) throw new IllegalStateException("ICE receiver already attached");
        destination = java.util.Objects.requireNonNull(receiver);
        var replay = List.copyOf(pending);
        pending.clear();
        for (var signal : replay) {
            if (closed) break;
            receiver.accept(signal);
        }
    }

    @Override public synchronized void close() {
        closed = true;
        pending.clear();
        destination = null;
    }
}
