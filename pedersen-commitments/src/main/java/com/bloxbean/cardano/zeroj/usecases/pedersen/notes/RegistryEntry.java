package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;

import java.math.BigInteger;
import java.util.List;

/**
 * An auditor registry entry (ADR-0007 N1), as {@code AuditorRegistry} stores it:
 * {@code Entry(auditor, generation, pkU, pkV, pkEnc, viewU, viewV, viewKey, pkProof, viewProof)}.
 *
 * <p>{@link #fromPlutusData} checks the shape and lengths only. Whether the keys are valid and
 * possessed is {@link AdmittedAuditor#admit}'s job (and, for entries on chain, the registry's).
 */
public record RegistryEntry(byte[] auditor, long generation, BigInteger pkU, BigInteger pkV, byte[] pkEnc,
                            BigInteger viewU, BigInteger viewV, byte[] viewKey, byte[] pkProof, byte[] viewProof) {

    public ConstrPlutusData toPlutusData() {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(auditor),
                BigIntPlutusData.of(generation),
                BigIntPlutusData.of(pkU),
                BigIntPlutusData.of(pkV),
                new BytesPlutusData(pkEnc),
                BigIntPlutusData.of(viewU),
                BigIntPlutusData.of(viewV),
                new BytesPlutusData(viewKey),
                new BytesPlutusData(pkProof),
                new BytesPlutusData(viewProof))).build();
    }

    /** @throws IllegalArgumentException if {@code data} is not exactly an entry */
    public static RegistryEntry fromPlutusData(PlutusData data) {
        if (!(data instanceof ConstrPlutusData c) || c.getAlternative() != 0) {
            throw new IllegalArgumentException("not a registry entry");
        }
        List<PlutusData> f = c.getData().getPlutusDataList();
        if (f.size() != 10) throw new IllegalArgumentException("a registry entry has 10 fields");
        var entry = new RegistryEntry(bytes(f.get(0), 28), integer(f.get(1)).longValueExact(),
                integer(f.get(2)), integer(f.get(3)), bytes(f.get(4), 32),
                integer(f.get(5)), integer(f.get(6)), bytes(f.get(7), 32),
                bytes(f.get(8), 192), bytes(f.get(9), 192));
        if (entry.generation < 0 || !canonical(entry.pkU) || !canonical(entry.pkV)
                || !canonical(entry.viewU) || !canonical(entry.viewV)) {
            throw new IllegalArgumentException("registry entry out of range");
        }
        return entry;
    }

    /** The same entry with another possession proof for the ElGamal key (tests and cheats). */
    public RegistryEntry withPkProof(byte[] proof) {
        return new RegistryEntry(auditor, generation, pkU, pkV, pkEnc, viewU, viewV, viewKey, proof, viewProof);
    }

    private static boolean canonical(BigInteger x) {
        return x.signum() >= 0 && x.compareTo(Fields.FR) < 0;
    }

    private static byte[] bytes(PlutusData d, int length) {
        if (!(d instanceof BytesPlutusData b) || b.getValue().length != length) {
            throw new IllegalArgumentException("expected " + length + " bytes");
        }
        return b.getValue();
    }

    private static BigInteger integer(PlutusData d) {
        if (!(d instanceof BigIntPlutusData i)) throw new IllegalArgumentException("expected an integer");
        return i.getValue();
    }
}
