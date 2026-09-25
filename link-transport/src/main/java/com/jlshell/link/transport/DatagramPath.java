package com.jlshell.link.transport;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.function.Consumer;

/** A nominated peer-to-peer datagram path. It does not provide reliability or encryption. */
public interface DatagramPath extends AutoCloseable {
    /** Installs the sole receiver. Implementations must pass immutable packet bytes. */
    void setReceiver(Consumer<ByteBuffer> receiver, Consumer<Throwable> failure) throws IOException;

    /** Sends one complete datagram to the nominated peer. */
    void send(ByteBuffer datagram) throws IOException;

    boolean isOpen();

    /** Releases this adapter; ownership of an ICE component socket remains with the ICE agent. */
    @Override
    void close();
}
