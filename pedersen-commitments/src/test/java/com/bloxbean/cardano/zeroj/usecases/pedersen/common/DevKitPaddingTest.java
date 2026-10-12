package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** The evaluator's headroom share must not overflow for transactions near the step limit. */
class DevKitPaddingTest {

    @Test
    @DisplayName("Headroom is shared without long overflow (2.2e9 · 7.8e9 > Long.MAX_VALUE)")
    void shareDoesNotOverflow() {
        assertEquals(2_220_000_000L, DevKit.share(2_220_000_000L, 7_780_000_000L, 7_780_000_000L));
        assertEquals(1_110_000_000L, DevKit.share(2_220_000_000L, 3_890_000_000L, 7_780_000_000L));
        assertEquals(0, DevKit.share(5, 5, 0));
    }
}
