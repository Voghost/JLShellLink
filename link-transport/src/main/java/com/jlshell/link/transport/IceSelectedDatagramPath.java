package com.jlshell.link.transport;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Adapts an ICE component's application socket after a pair has been nominated.
 * The socket itself remains owned by ice4j; this adapter only owns its receiver
 * thread and restores the socket's previous receive timeout when closed.
 */
public final class IceSelectedDatagramPath implements DatagramPath {
    private final DatagramSocket componentSocket;
    private final SocketAddress selectedRemote;
    private final int maxDatagramBytes;
    private final int receiveTimeoutMillis;
    private final int previousTimeoutMillis;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private volatile Consumer<ByteBuffer> receiver;
    private volatile Consumer<Throwable> failure;
    private Thread receiverThread;

    public IceSelectedDatagramPath(DatagramSocket componentSocket, SocketAddress selectedRemote,
            int maxDatagramBytes, int receiveTimeoutMillis) throws SocketException {
        this.componentSocket = Objects.requireNonNull(componentSocket, "componentSocket");
        this.selectedRemote = Objects.requireNonNull(selectedRemote, "selectedRemote");
        if (!(selectedRemote instanceof InetSocketAddress)) {
            throw new IllegalArgumentException("selected ICE peer must be an IP socket address");
        }
        if (maxDatagramBytes < 256 || maxDatagramBytes > 65_507) {
            throw new IllegalArgumentException("maxDatagramBytes must be between 256 and 65507");
        }
        if (receiveTimeoutMillis < 10 || receiveTimeoutMillis > 500) {
            throw new IllegalArgumentException("receiveTimeoutMillis must be between 10 and 500");
        }
        this.maxDatagramBytes = maxDatagramBytes;
        this.receiveTimeoutMillis = receiveTimeoutMillis;
        this.previousTimeoutMillis = componentSocket.getSoTimeout();
        componentSocket.setSoTimeout(receiveTimeoutMillis);
    }

    @Override
    public synchronized void setReceiver(Consumer<ByteBuffer> receiver, Consumer<Throwable> failure)
            throws IOException {
        Objects.requireNonNull(receiver, "receiver");
        Objects.requireNonNull(failure, "failure");
        if (!open.get()) {
            throw new SocketException("selected ICE path is closed");
        }
        if (receiverThread != null) {
            throw new IllegalStateException("datagram receiver already installed");
        }
        this.receiver = receiver;
        this.failure = failure;
        receiverThread = Thread.ofVirtual().name("jlshell-ice-selected-rx").start(this::receiveLoop);
    }

    @Override
    public void send(ByteBuffer datagram) throws IOException {
        Objects.requireNonNull(datagram, "datagram");
        if (!open.get() || componentSocket.isClosed()) {
            throw new SocketException("selected ICE path is closed");
        }
        int length = datagram.remaining();
        if (length == 0 || length > maxDatagramBytes) {
            throw new IOException("datagram length is outside the configured path limit");
        }
        byte[] bytes = new byte[length];
        datagram.asReadOnlyBuffer().get(bytes);
        synchronized (componentSocket) {
            componentSocket.send(new DatagramPacket(bytes, bytes.length, selectedRemote));
        }
    }

    @Override
    public boolean isOpen() {
        return open.get() && !componentSocket.isClosed();
    }

    private void receiveLoop() {
        byte[] storage = new byte[maxDatagramBytes];
        while (open.get() && !componentSocket.isClosed()) {
            DatagramPacket packet = new DatagramPacket(storage, storage.length);
            try {
                componentSocket.receive(packet);
                if (!selectedRemote.equals(packet.getSocketAddress())) {
                    continue;
                }
                byte[] copy = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), copy, 0, packet.getLength());
                receiver.accept(ByteBuffer.wrap(copy).asReadOnlyBuffer());
            } catch (SocketTimeoutException ignored) {
                // A bounded timeout lets this adapter stop without closing the ICE-owned socket.
            } catch (IOException | RuntimeException error) {
                if (open.get()) {
                    failure.accept(error);
                }
                return;
            }
        }
    }

    @Override
    public void close() {
        if (!open.compareAndSet(true, false)) {
            return;
        }
        Thread current;
        synchronized (this) {
            current = receiverThread;
        }
        if (current != null && current != Thread.currentThread()) {
            current.interrupt();
            try {
                current.join(Math.max(250, receiveTimeoutMillis * 2L));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        }
        if (!componentSocket.isClosed()) {
            try {
                componentSocket.setSoTimeout(previousTimeoutMillis);
            } catch (SocketException ignored) {
                // The ICE owner may already be shutting down its socket.
            }
        }
    }
}
