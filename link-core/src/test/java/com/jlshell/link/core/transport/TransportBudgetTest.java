package com.jlshell.link.core.transport;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class TransportBudgetTest {
    @Test
    void acceptsConsistentFiniteLimits() {
        assertDoesNotThrow(() -> new TransportBudget(16_384, 8_192, 64, 1_048_576,
                262_144, 4_194_304, 8, Duration.ofSeconds(10)));
    }

    @Test
    void rejectsUnboundedOrContradictoryLimits() {
        assertThrows(IllegalArgumentException.class, () -> new TransportBudget(0, 1, 1, 1,
                1, 1, 1, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new TransportBudget(1_024, 2_048, 1, 1,
                1, 1, 1, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new TransportBudget(1_024, 512, 1, 2_048,
                1, 1_024, 1, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> new TransportBudget(1_024, 512, 1, 1,
                2_048, 1_024, 1, Duration.ZERO));
    }
}
