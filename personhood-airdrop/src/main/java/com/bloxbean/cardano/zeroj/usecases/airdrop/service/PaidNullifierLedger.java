package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The faucet's durable record of paid nullifiers (ADR-0009 D3.5).
 *
 * <p>A nullifier is recorded, atomically and owner-only, <em>before</em> the faucet signs its
 * payout ({@link #reserve}), and refused once recorded, also after a restart. A reservation is
 * released only if no signed transaction ever left the faucet (the build or signing failed);
 * once a payout has been submitted, or its submission failed in an unknown state, the record
 * stays, so a nullifier is paid at most once (fail closed).
 */
@Component
public class PaidNullifierLedger {

    /** The nullifier's payout was signed and submitted, or may have been. */
    static final String RESERVED = "reserved";
    /** The payout was accepted by the node. */
    static final String PAID = "paid";

    private final Path file;
    private final Map<String, Entry> entries = new LinkedHashMap<>();

    public PaidNullifierLedger(AirdropDataDir data) {
        this.file = data.paidNullifiers();
        JsonNode node = DemoFiles.read(file);
        if (node != null) {
            JsonNode list = node.get("nullifiers");
            if (list == null || !list.isArray()) {
                throw new IllegalStateException(file + " is corrupt: missing nullifiers");
            }
            for (JsonNode n : list) {
                String status = DemoFiles.text(n, "status", file);
                if (!status.equals(RESERVED) && !status.equals(PAID)) {
                    throw new IllegalStateException(file + " is corrupt: unknown status " + status);
                }
                String tx = n.hasNonNull("txHash") ? n.get("txHash").asText() : null;
                entries.put(DemoFiles.text(n, "nullifier", file), new Entry(status, tx));
            }
        }
    }

    /** Whether {@code nullifier} is recorded (reserved or paid). */
    public synchronized boolean isRecorded(BigInteger nullifier) {
        return entries.containsKey(key(nullifier));
    }

    /**
     * Records {@code nullifier} durably before its payout is signed.
     *
     * @throws AlreadyPaidException if it is already recorded
     */
    public synchronized void reserve(BigInteger nullifier) {
        String k = key(nullifier);
        if (entries.containsKey(k)) {
            throw new AlreadyPaidException(nullifier);
        }
        entries.put(k, new Entry(RESERVED, null));
        try {
            persist();
        } catch (RuntimeException e) {
            entries.remove(k);
            throw e;
        }
    }

    /** Releases a reservation whose payout was never signed or never left the faucet. */
    public synchronized void release(BigInteger nullifier) {
        String k = key(nullifier);
        Entry e = entries.get(k);
        if (e != null && e.status().equals(RESERVED)) {
            entries.remove(k);
            persist();
        }
    }

    /** Marks a reserved nullifier as paid by {@code txHash}. */
    public synchronized void markPaid(BigInteger nullifier, String txHash) {
        entries.put(key(nullifier), new Entry(PAID, txHash));
        persist();
    }

    public synchronized int size() {
        return entries.size();
    }

    private void persist() {
        var out = DemoFiles.object();
        var list = out.putArray("nullifiers");
        entries.forEach((k, e) -> {
            var n = list.addObject().put("nullifier", k).put("status", e.status());
            if (e.txHash() != null) n.put("txHash", e.txHash());
        });
        DemoFiles.writeAtomic(file, out);
    }

    /** Canonical key: 32-byte big-endian hex, the receipt token name. */
    static String key(BigInteger nullifier) {
        if (nullifier == null || nullifier.signum() < 0 || nullifier.bitLength() > 256) {
            throw new IllegalArgumentException("nullifier is not a 32-byte value");
        }
        return String.format("%064x", nullifier);
    }

    private record Entry(String status, String txHash) {}

    /** A second payout for a nullifier the faucet has already recorded or receipted. */
    public static final class AlreadyPaidException extends IllegalStateException {
        public AlreadyPaidException(BigInteger nullifier) {
            super("Nullifier 0x" + key(nullifier).substring(0, 16) + "... was already paid");
        }
    }
}
