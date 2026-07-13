package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end validation of the {@link Flows} facade the JavaFX UI drives: generate a local key
 * bundle, prove ownership for a known mnemonic, and off-chain-verify the proof — the same path the
 * UI's Setup → Prove → Verify screens run. Heavy (~7 min, ~8 GB heap), so gated behind
 * {@code -Daor.e2e=true}; run with {@code ./gradlew :cli:test --tests '*FlowsE2ETest' -Daor.e2e=true}.
 */
class FlowsE2ETest {

    // BIP-39 test vector (all "abandon" + "art") — derives a deterministic address on any bundle.
    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
            + "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    @Test
    @EnabledIfSystemProperty(named = "aor.e2e", matches = "true")
    void generateProveVerify_endToEnd(@TempDir Path dir) throws Exception {
        Path keys = dir.resolve("keys");
        Path proofs = dir.resolve("proofs");

        Flows.generateLocalKeys(keys, System.out::println);
        assertTrue(Flows.hasKeys(keys), "bundle generated");
        assertNotNull(Flows.keyFingerprint(keys), "bundle has a fingerprint");

        char[] mnemonic = TEST_MNEMONIC.toCharArray();
        Flows.ProveResult result = Flows.prove(keys, mnemonic, 0, /*role*/ 0, /*index*/ 0,
                /*mainnet*/ false, proofs, System.out::println);

        assertNotNull(result.address(), "derived address");
        assertEquals(56, result.pkhHex().length(), "28-byte pkh in hex");
        assertTrue(Flows.hasProof(proofs), "proof written");
        assertEquals('\0', mnemonic[0], "prove zeroed the mnemonic");

        assertTrue(Flows.verifyOffChain(keys, proofs), "off-chain verification must pass");

        // a different role must derive a different address (path is a real input)
        char[] m2 = TEST_MNEMONIC.toCharArray();
        Path proofs2 = dir.resolve("proofs-role1");
        var r2 = Flows.prove(keys, m2, 0, /*role*/ 1, /*index*/ 0, false, proofs2, s -> {});
        assertNotEquals(result.address(), r2.address(), "role 1 is a different address");
        assertTrue(Flows.verifyOffChain(keys, proofs2), "role-1 proof verifies too");
    }
}
