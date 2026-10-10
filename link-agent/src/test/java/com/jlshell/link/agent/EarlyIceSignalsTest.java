package com.jlshell.link.agent;

import static org.junit.jupiter.api.Assertions.*;

import com.jlshell.link.core.model.LinkSessionId;
import com.jlshell.link.core.signal.ControlSignal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class EarlyIceSignalsTest {
    @Test
    void preservesEarlyCredentialsAndLaterSignalsInOrder() {
        var session = LinkSessionId.random();
        var queue = new EarlyIceSignals(session, 1);
        var credentials = new ControlSignal.IceCredentials(UUID.randomUUID(), session, 1,
                "testfragment", "testpasswordwithsufficientlength");
        var end = new ControlSignal.IceEnd(UUID.randomUUID(), session, 1);
        queue.accept(credentials);
        var received = new ArrayList<ControlSignal>();
        queue.attach(received::add);
        queue.accept(end);
        assertEquals(List.of(credentials, end), received);
        queue.close();
        queue.accept(end);
        assertEquals(2, received.size());
    }

    @Test
    void rejectsWrongBindingAndExcessiveEarlyMessages() {
        var session = LinkSessionId.random();
        var queue = new EarlyIceSignals(session, 1);
        assertThrows(SecurityException.class, () -> queue.accept(
                new ControlSignal.IceEnd(UUID.randomUUID(), LinkSessionId.random(), 1)));
        for (int i = 0; i < 34; i++) queue.accept(new ControlSignal.IceEnd(UUID.randomUUID(), session, 1));
        assertThrows(IllegalStateException.class, () -> queue.accept(
                new ControlSignal.IceEnd(UUID.randomUUID(), session, 1)));
        var received = new ArrayList<ControlSignal>();
        queue.attach(received::add);
        assertTrue(received.isEmpty());
    }
}
