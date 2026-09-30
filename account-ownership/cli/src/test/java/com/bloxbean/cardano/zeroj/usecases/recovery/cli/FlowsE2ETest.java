package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import org.zeroj.crypto.groth16.Groth16Pipeline;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end validation of the {@link Flows} facade the JavaFX UI drives: generate a local key
 * bundle, prove ownership for a known mnemonic, and off-chain-verify the proof — the same path the
 * UI's Setup → Prove → Verify screens run. Heavy (~7 min, ~8 GB heap), so gated behind
 * {@code -Daor.e2e=true}; run with {@code ./gradlew :cli:test --tests '*FlowsE2ETest' -Daor.e2e=true}.
 * To reuse an existing exact-bound bundle and exercise proving without another setup, use
 * {@code -Daor.e2e.keys=/path/to/keys} instead.
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
        Flows.generateLocalKeys(keys, System.out::println);
        proveAndVerify(keys, dir);
    }

    @Test
    @EnabledIfSystemProperty(named = "aor.e2e.keys", matches = ".+")
    void existingBundle_proveVerify(@TempDir Path dir) throws Exception {
        proveAndVerify(Path.of(System.getProperty("aor.e2e.keys")), dir);
    }

    private static void proveAndVerify(Path keys, Path dir) throws Exception {
        Path proofs = dir.resolve("proofs");
        assertTrue(Flows.hasKeys(keys), "bundle exists");
        assertTrue(Groth16Pipeline.isExactFingerprint(Flows.keyFingerprint(keys)),
                "bundle preserves the exact relation fingerprint");

        // v3: the recipient (payout address) is bound into the proof
        String recipient = "addr_test1vqqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7cetfzyu";

        char[] mnemonic = TEST_MNEMONIC.toCharArray();
        Flows.ProveResult result = Flows.prove(keys, mnemonic, 0, /*role*/ 0, /*index*/ 0,
                recipient, /*mainnet*/ false, proofs, System.out::println);

        assertNotNull(result.address(), "derived address");
        assertEquals(56, result.pkhHex().length(), "28-byte pkh in hex");
        assertEquals(recipient, result.recipient(), "recipient echoed");
        assertTrue(Flows.hasProof(proofs), "proof written");
        assertEquals(Flows.keyFingerprint(keys), ProofIO.readFingerprint(proofs.resolve(ProofIO.PUBLIC_FILE)),
                "proof metadata carries the same exact fingerprint");
        assertEquals('\0', mnemonic[0], "prove zeroed the mnemonic");

        assertTrue(Flows.verifyOffChain(keys, proofs), "off-chain verification must pass");

        // Hardening: the off-chain check recomputes the public inputs from the address + recipient,
        // so verifying against a DIFFERENT recipient (or a wrong address) must fail, while the exact
        // pair still passes.
        assertTrue(Flows.verifyOffChain(keys, proofs, result.address(), recipient),
                "correct expected address + recipient verifies");
        // The test mnemonic derives the same address as the recipient fixture above. Use an
        // independent devnet address and assert its payment credential really differs.
        String wrongAddress = "addr_test1qryvgass5dsrf2kxl3vgfz76uhp83kv5lagzcp29tcana68"
                + "ca5aqa6swlq6llfamln09tal7n5kvt4275ckwedpt4v7q48uhex";
        assertFalse(Arrays.equals(Flows.paymentKeyHashOf(wrongAddress), Flows.paymentKeyHashOf(recipient)));
        assertFalse(Arrays.equals(Flows.paymentKeyHashOf(wrongAddress), Flows.paymentKeyHashOf(result.address())));
        assertFalse(Flows.verifyOffChain(keys, proofs, null, wrongAddress),
                "a wrong expected recipient must not verify");
        assertFalse(Flows.verifyOffChain(keys, proofs, wrongAddress, recipient),
                "a wrong expected address must not verify");

        // a different role must derive a different address (path is a real input)
        char[] m2 = TEST_MNEMONIC.toCharArray();
        Path proofs2 = dir.resolve("proofs-role1");
        var r2 = Flows.prove(keys, m2, 0, /*role*/ 1, /*index*/ 0, recipient, false, proofs2, System.out::println);
        assertNotEquals(result.address(), r2.address(), "role 1 is a different address");
        assertTrue(Flows.verifyOffChain(keys, proofs2), "role-1 proof verifies too");
    }
}
