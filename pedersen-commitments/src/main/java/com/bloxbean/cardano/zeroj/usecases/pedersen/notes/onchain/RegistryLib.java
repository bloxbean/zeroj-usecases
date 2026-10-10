package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.OnchainLibrary;
import org.julclang.stdlib.lib.ValuesLib;

import java.math.BigInteger;

/**
 * The auditor registry entry (ADR-0007 N1) as validators read it: its shape, its fields, and the
 * one entry a transaction supplies as a reference input.
 */
@OnchainLibrary
public class RegistryLib {

    /**
     * Exactly {@code Constr 0 [auditor B28, generation I ≥ 0, pkU, pkV, pkEnc B32, viewU, viewV,
     * viewKey B32, pkProof B192, viewProof B192]}, where both keys' coordinates are canonical with
     * {@code u ≠ 0}, each encoding is exactly its coordinates' {@code pedersen-jubjub-v1} §4
     * encoding ({@link #encode}), and the two keys differ. A wrong field type makes a builtin fail
     * (fail closed).
     *
     * <p>{@code u ≠ 0} excludes the identity {@code (0, 1)} and the order-2 point {@code (0, −1)}:
     * a possession proof with secret 0 is valid for the identity, so the proof alone would not.
     */
    public static boolean isEntry(PlutusData value) {
        if (Builtins.constrTag(value) != 0) return false;
        PlutusData f0 = Builtins.constrFields(value);
        PlutusData f1 = Builtins.tailList(f0);
        PlutusData f2 = Builtins.tailList(f1);
        PlutusData f3 = Builtins.tailList(f2);
        PlutusData f4 = Builtins.tailList(f3);
        PlutusData f5 = Builtins.tailList(f4);
        PlutusData f6 = Builtins.tailList(f5);
        PlutusData f7 = Builtins.tailList(f6);
        PlutusData f8 = Builtins.tailList(f7);
        PlutusData f9 = Builtins.tailList(f8);
        if (!Builtins.nullList(Builtins.tailList(f9))) return false;
        BigInteger pkU = Builtins.unIData(Builtins.headList(f2));
        BigInteger pkV = Builtins.unIData(Builtins.headList(f3));
        byte[] pkEnc = Builtins.unBData(Builtins.headList(f4));
        BigInteger viewU = Builtins.unIData(Builtins.headList(f5));
        BigInteger viewV = Builtins.unIData(Builtins.headList(f6));
        byte[] viewKey = Builtins.unBData(Builtins.headList(f7));
        return Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(f0))) == 28
                && Builtins.unIData(Builtins.headList(f1)).compareTo(BigInteger.ZERO) >= 0
                && validKeyCoordinates(pkU, pkV)
                && validKeyCoordinates(viewU, viewV)
                && Builtins.equalsByteString(pkEnc, encode(pkU, pkV))
                && Builtins.equalsByteString(viewKey, encode(viewU, viewV))
                && !Builtins.equalsByteString(pkEnc, viewKey)
                && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(f8))) == 192
                && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(f9))) == 192;
    }

    private static boolean validKeyCoordinates(BigInteger u, BigInteger v) {
        return ChainLib.canonicalField(u) && ChainLib.canonicalField(v) && u.compareTo(BigInteger.ZERO) != 0;
    }

    /**
     * The 32-byte {@code pedersen-jubjub-v1} §4 encoding of the affine point {@code (u, v)}:
     * {@code v} little-endian with the top bit set iff {@code u} is odd. For canonical
     * coordinates of a curve point this is the unique encoding.
     */
    public static byte[] encode(BigInteger u, BigInteger v) {
        BigInteger sign = u.mod(BigInteger.valueOf(2));
        return Builtins.integerToByteString(false, 32, v.add(sign.multiply(twoTo255())));
    }

    private static BigInteger twoTo255() {
        BigInteger b62 = BigInteger.valueOf(4611686018427387904L);
        return b62.multiply(b62).multiply(b62).multiply(b62).multiply(BigInteger.valueOf(128));
    }

    public static byte[] entryAuditor(PlutusData entry) {
        return Builtins.unBData(Builtins.headList(Builtins.constrFields(entry)));
    }

    public static BigInteger entryGeneration(PlutusData entry) {
        return Builtins.unIData(field(entry, 1));
    }

    public static BigInteger entryPkU(PlutusData entry) {
        return Builtins.unIData(field(entry, 2));
    }

    public static BigInteger entryPkV(PlutusData entry) {
        return Builtins.unIData(field(entry, 3));
    }

    public static BigInteger entryViewU(PlutusData entry) {
        return Builtins.unIData(field(entry, 5));
    }

    public static BigInteger entryViewV(PlutusData entry) {
        return Builtins.unIData(field(entry, 6));
    }

    public static byte[] entryPkProof(PlutusData entry) {
        return Builtins.unBData(field(entry, 8));
    }

    public static byte[] entryViewProof(PlutusData entry) {
        return Builtins.unBData(field(entry, 9));
    }

    /** Field {@code index} of a constructor. */
    private static PlutusData field(PlutusData entry, int index) {
        PlutusData rest = Builtins.constrFields(entry);
        int i = 0;
        while (i < index) {
            rest = Builtins.tailList(rest);
            i = i + 1;
        }
        return Builtins.headList(rest);
    }

    /**
     * The entry of the <b>exactly one</b> reference input that holds the registry token
     * ({@code registryPolicy}/{@code registryToken}): quantity exactly 1 and a well-formed entry
     * datum (spec §8.1). No entry, a second entry, another quantity or another shape fails the
     * script. The registry's own script keeps the token a singleton, so this is the current
     * generation.
     */
    public static PlutusData currentEntry(TxInfo txInfo, byte[] registryPolicy, byte[] registryToken) {
        int entries = 0;
        boolean single = true;
        PlutusData found = Builtins.iData(BigInteger.ZERO);
        for (TxInInfo reference : txInfo.referenceInputs()) {
            TxOut resolved = reference.resolved();
            BigInteger quantity = ValuesLib.assetOf(resolved.value(), registryPolicy, registryToken);
            if (quantity.compareTo(BigInteger.ZERO) > 0) {
                entries = entries + 1;
                single = single && quantity.compareTo(BigInteger.ONE) == 0;
                found = ChainLib.inlineDatum(resolved);
            } else {
                entries = entries;
                single = single;
                found = found;
            }
        }
        if (entries != 1 || !single || !isEntry(found)) Builtins.error();
        return found;
    }
}
