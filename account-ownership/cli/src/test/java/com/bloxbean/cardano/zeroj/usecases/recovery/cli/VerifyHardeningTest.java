package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The off-chain verify hardening ({@link Flows#resolvePublicInputs} / {@link Flows#resolveTargets}):
 * the public inputs are recomputed from the pkh/recipient rather than trusted from the stored array,
 * so an edited {@code pkh}, {@code recipient}, or {@code publicInputs} is caught — and an
 * {@code --expect-*} override verifies against a caller-supplied value. No proving needed.
 */
class VerifyHardeningTest {

    // A valid testnet address whose payment credential is a real 28-byte key hash (for the override).
    private static final String OTHER_ADDRESS =
            "addr_test1vqqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7cetfzyu";

    private static final byte[] PKH = filled(0x11);
    private static final byte[] RPKH = filled(0x22);
    private static final BigInteger P0 = new BigInteger(1, PKH);   // big-endian pack, matches the circuit
    private static final BigInteger P1 = new BigInteger(1, RPKH);

    private static byte[] filled(int b) {
        byte[] a = new byte[28];
        Arrays.fill(a, (byte) b);
        return a;
    }

    /** Write a synthetic public-inputs.json with the given publicInputs array. */
    private static Path writePub(Path dir, String pkhHex, String recipientPkhHex, String... publicInputs)
            throws Exception {
        Path f = dir.resolve(ProofIO.PUBLIC_FILE);
        StringBuilder arr = new StringBuilder("[");
        for (int i = 0; i < publicInputs.length; i++)
            arr.append(i == 0 ? "" : ",").append('"').append(publicInputs[i]).append('"');
        arr.append(']');
        Files.writeString(f, "{\n"
                + "  \"pkh\": \"" + pkhHex + "\",\n"
                + "  \"address\": \"addr_test_addr\",\n"
                + "  \"recipient\": \"addr_test_recipient\",\n"
                + "  \"recipientPkh\": \"" + recipientPkhHex + "\",\n"
                + "  \"fingerprint\": \"c1-w1-p2\",\n"
                + "  \"publicInputs\": " + arr + "\n}");
        return f;
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    @Test
    void consistentFile_recomputesTheStoredInputs(@TempDir Path dir) throws Exception {
        Path pub = writePub(dir, hex(PKH), hex(RPKH), P0.toString(), P1.toString());
        BigInteger[] got = Flows.resolvePublicInputs(pub, null, null);
        assertArrayEquals(new BigInteger[]{P0, P1}, got, "packs pkh then recipient, big-endian");
    }

    @Test
    void tamperedPublicInputsArray_isRejected(@TempDir Path dir) throws Exception {
        // pkh/recipient untouched, but the array no longer matches their packing.
        Path pub = writePub(dir, hex(PKH), hex(RPKH), P0.add(BigInteger.ONE).toString(), P1.toString());
        assertThrows(IllegalStateException.class, () -> Flows.resolvePublicInputs(pub, null, null));
    }

    @Test
    void tamperedPkhField_isRejected(@TempDir Path dir) throws Exception {
        // pkh field changed (0x33…) but the array still holds the old packing → inconsistent.
        Path pub = writePub(dir, hex(filled(0x33)), hex(RPKH), P0.toString(), P1.toString());
        assertThrows(IllegalStateException.class, () -> Flows.resolvePublicInputs(pub, null, null));
    }

    @Test
    void expectRecipientOverride_ignoresTheArrayAndUsesTheGivenValue(@TempDir Path dir) throws Exception {
        // Deliberately inconsistent array — the override must bypass the consistency check and
        // recompute the recipient scalar from the supplied bech32 address.
        Path pub = writePub(dir, hex(PKH), hex(RPKH), P0.toString(), "999");
        var targets = Flows.resolveTargets(pub, null, OTHER_ADDRESS);
        assertTrue(targets.overridden(), "supplying a recipient is an override");
        assertEquals(28, targets.recipientPkh().length);
        assertEquals(OTHER_ADDRESS, targets.recipient());

        BigInteger[] got = Flows.resolvePublicInputs(pub, null, OTHER_ADDRESS);
        assertEquals(P0, got[0], "pkh still from the file");
        assertEquals(new BigInteger(1, Flows.paymentKeyHashOf(OTHER_ADDRESS)), got[1], "recipient from the override");
    }
}
