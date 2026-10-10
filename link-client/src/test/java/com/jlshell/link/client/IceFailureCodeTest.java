package com.jlshell.link.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.io.IOException;
import org.junit.jupiter.api.Test;

class IceFailureCodeTest {
    @Test
    void reportsOnlyFixedCodesWithoutExceptionDetails() {
        assertEquals("direct.ice_selected_unknown", SignaledIceDirectPathProvider.iceFailureCode(
                new IOException("ICE selected a candidate outside the authorized exchange")));
        assertEquals("direct.ice_checks_failed", SignaledIceDirectPathProvider.iceFailureCode(
                new IOException("ICE connectivity checks did not nominate a candidate pair")));
        assertEquals("direct.ice_deadline", SignaledIceDirectPathProvider.iceFailureCode(
                new IOException("ICE connectivity deadline expired")));
        assertEquals("direct.ice_unreachable", SignaledIceDirectPathProvider.iceFailureCode(
                new IOException("unrecognized private detail")));
    }
}
