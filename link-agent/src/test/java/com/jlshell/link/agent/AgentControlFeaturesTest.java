package com.jlshell.link.agent;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentControlFeaturesTest {
    @Test
    void oldWebsiteWithoutAdvertisementDoesNotEnableOptionalDiagnostics() throws Exception {
        assertFalse(AgentControlPlaneClient.supportsDiagnostics(Map.of()));
        assertFalse(AgentControlPlaneClient.supportsDiagnostics(Map.of("controlFeatures", List.of())));
        assertFalse(AgentControlPlaneClient.supportsDiagnostics(Map.of("controlFeatures", List.of("future-feature"))));
    }

    @Test
    void explicitAdvertisementEnablesDiagnostics() throws Exception {
        assertTrue(AgentControlPlaneClient.supportsDiagnostics(Map.of("controlFeatures", List.of("target-diagnostic-v1"))));
    }

    @Test
    void malformedOrUnboundedAdvertisementFailsClosed() {
        assertThrows(IOException.class, () -> AgentControlPlaneClient.supportsDiagnostics(Map.of("controlFeatures", "target-diagnostic-v1")));
        assertThrows(IOException.class, () -> AgentControlPlaneClient.supportsDiagnostics(Map.of("controlFeatures", List.of(1))));
        assertThrows(IOException.class, () -> AgentControlPlaneClient.supportsDiagnostics(Map.of("controlFeatures", List.of("invalid feature"))));
        assertThrows(IOException.class, () -> AgentControlPlaneClient.supportsDiagnostics(Map.of("controlFeatures", java.util.Collections.nCopies(17, "future-feature"))));
    }
}
