package com.jlshell.link.client;

import static org.junit.jupiter.api.Assertions.*;

import com.jlshell.link.core.model.LinkSessionId;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RelayActivationResponseTest {
    @Test
    void acceptsMatchingJsonStringSessionAndActiveReservation() throws Exception {
        var session = LinkSessionId.random();
        WebsiteAccessRequestProvider.validateRelayActivation(session,
                Map.of("sessionId", session.toString(), "state", "ACTIVE"));
    }

    @Test
    void rejectsAnotherSessionOrInactiveReservation() {
        var session = LinkSessionId.random();
        assertThrows(SecurityException.class, () -> WebsiteAccessRequestProvider.validateRelayActivation(
                session, Map.of("sessionId", LinkSessionId.random().toString(), "state", "ACTIVE")));
        assertThrows(SecurityException.class, () -> WebsiteAccessRequestProvider.validateRelayActivation(
                session, Map.of("sessionId", session.toString(), "state", "RELEASED")));
    }
}
