package com.jlshell.link.client;

import static org.junit.jupiter.api.Assertions.*;
import com.jlshell.link.transport.DatagramPath;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

class RevocableDatagramPathTest {
    @Test void authorizedClosureNotifiesTheCarrierOnceAndRejectsFurtherTraffic() throws Exception {
        var delegate = new FakePath();var path = new RevocableDatagramPath(delegate);
        var failures = new AtomicInteger();var received = new AtomicInteger();
        path.setReceiver(packet -> received.incrementAndGet(), error -> failures.incrementAndGet());
        path.close();path.close();delegate.failure.accept(new IOException("late failure"));
        delegate.receiver.accept(ByteBuffer.wrap(new byte[] {1}));
        assertEquals(1, failures.get());assertEquals(1, delegate.closes);assertEquals(0, received.get());
        assertFalse(path.isOpen());
        assertThrows(IOException.class, () -> path.send(ByteBuffer.wrap(new byte[] {1})));
    }

    @Test void closureBeforeReceiverRegistrationCannotReopenThePath() {
        var delegate = new FakePath();var path = new RevocableDatagramPath(delegate);path.close();
        assertThrows(IOException.class, () -> path.setReceiver(packet -> { }, error -> { }));
        assertEquals(1, delegate.closes);
    }

    @Test void transportFailureAndLocalCleanupShareOneTerminalNotification() throws Exception {
        var delegate = new FakePath();var path = new RevocableDatagramPath(delegate);
        var failures = new AtomicInteger();path.setReceiver(packet -> { }, error -> failures.incrementAndGet());
        delegate.failure.accept(new IOException("transport unavailable"));path.close();
        assertEquals(1, failures.get());assertEquals(1, delegate.closes);
    }

    private static final class FakePath implements DatagramPath {
        Consumer<ByteBuffer> receiver;Consumer<Throwable> failure;int closes;
        public void setReceiver(Consumer<ByteBuffer> receiver, Consumer<Throwable> failure) {
            this.receiver=receiver;this.failure=failure;
        }
        public void send(ByteBuffer packet) { }
        public boolean isOpen() { return closes==0; }
        public void close() { closes++; }
    }
}
