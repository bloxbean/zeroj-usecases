package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.TxOut;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.OnchainLibrary;
import org.julclang.stdlib.lib.ValuesLib;

import java.math.BigInteger;

/**
 * The note datum and note outputs as {@code NoteLedger} reads them (ADR-0007 N2):
 * {@code Note(owner B28, u, v, generation, audit [8], deliveries [B89 × 2])}.
 */
@OnchainLibrary
public class NoteLib {

    /**
     * A note output: at exactly {@code exact}, holding exactly lovelace and one {@code token}, with
     * a well-formed datum of generation {@code generation}.
     */
    public static boolean isNoteOutput(TxOut output, Address exact, byte[] policy, byte[] token,
                                       BigInteger generation) {
        return Builtins.equalsData(output.address(), exact)
                && ChainLib.outerEntryCount(output.value()) == 2
                && ChainLib.policyEntryCount(output.value(), policy) == 1
                && ValuesLib.assetOf(output.value(), policy, token).compareTo(BigInteger.ONE) == 0
                && isNoteDatum(ChainLib.inlineDatum(output), generation);
    }

    /** Every output under the payment credential {@code own} is a note output (N2's address policy). */
    public static boolean allNoteOutputs(JulcList<TxOut> outputs, Credential own, Address exact, byte[] policy,
                                         byte[] token, BigInteger generation) {
        boolean ok = true;
        for (TxOut output : outputs) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                ok = ok && isNoteOutput(output, exact, policy, token, generation);
            } else {
                ok = ok;
            }
        }
        return ok;
    }

    /**
     * Exactly {@code Constr 0 [B28, I < p, I < p, I = generation, [8 × I < p], [2 × B89]]}. Any
     * other shape returns false or makes a builtin fail (fail closed).
     */
    public static boolean isNoteDatum(PlutusData value, BigInteger generation) {
        if (Builtins.constrTag(value) != 0) return false;
        PlutusData f0 = Builtins.constrFields(value);
        PlutusData f1 = Builtins.tailList(f0);
        PlutusData f2 = Builtins.tailList(f1);
        PlutusData f3 = Builtins.tailList(f2);
        PlutusData f4 = Builtins.tailList(f3);
        PlutusData f5 = Builtins.tailList(f4);
        if (!Builtins.nullList(Builtins.tailList(f5))) return false;
        if (Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(f0))) != 28) return false;
        if (!ChainLib.canonicalField(Builtins.unIData(Builtins.headList(f1)))) return false;
        if (!ChainLib.canonicalField(Builtins.unIData(Builtins.headList(f2)))) return false;
        if (Builtins.unIData(Builtins.headList(f3)).compareTo(generation) != 0) return false;
        // Exactly 8 canonical audit integers and exactly 2 deliveries of 89 bytes. Unrolled: the
        // lengths are fixed, and a Julc loop costs far more per element than the checks themselves.
        PlutusData a0 = Builtins.unListData(Builtins.headList(f4));
        PlutusData a1 = Builtins.tailList(a0);
        PlutusData a2 = Builtins.tailList(a1);
        PlutusData a3 = Builtins.tailList(a2);
        PlutusData a4 = Builtins.tailList(a3);
        PlutusData a5 = Builtins.tailList(a4);
        PlutusData a6 = Builtins.tailList(a5);
        PlutusData a7 = Builtins.tailList(a6);
        if (!Builtins.nullList(Builtins.tailList(a7))) return false;
        if (!ChainLib.canonicalField(Builtins.unIData(Builtins.headList(a0)))
                || !ChainLib.canonicalField(Builtins.unIData(Builtins.headList(a1)))
                || !ChainLib.canonicalField(Builtins.unIData(Builtins.headList(a2)))
                || !ChainLib.canonicalField(Builtins.unIData(Builtins.headList(a3)))
                || !ChainLib.canonicalField(Builtins.unIData(Builtins.headList(a4)))
                || !ChainLib.canonicalField(Builtins.unIData(Builtins.headList(a5)))
                || !ChainLib.canonicalField(Builtins.unIData(Builtins.headList(a6)))
                || !ChainLib.canonicalField(Builtins.unIData(Builtins.headList(a7)))) {
            return false;
        }
        PlutusData d0 = Builtins.unListData(Builtins.headList(f5));
        PlutusData d1 = Builtins.tailList(d0);
        return Builtins.nullList(Builtins.tailList(d1))
                && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(d0))) == 89
                && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(d1))) == 89;
    }

    public static BigInteger noteU(PlutusData note) {
        return Builtins.unIData(Builtins.headList(Builtins.tailList(Builtins.constrFields(note))));
    }

    public static BigInteger noteV(PlutusData note) {
        return Builtins.unIData(Builtins.headList(Builtins.tailList(Builtins.tailList(Builtins.constrFields(note)))));
    }

    public static PlutusData noteAudit(PlutusData note) {
        return Builtins.headList(Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.tailList(
                Builtins.constrFields(note))))));
    }

    /** {@code audit}'s 8 entries prepended to the list {@code rest}. */
    public static PlutusData prependAudit(PlutusData audit, PlutusData rest) {
        PlutusData a0 = Builtins.unListData(audit);
        PlutusData a1 = Builtins.tailList(a0);
        PlutusData a2 = Builtins.tailList(a1);
        PlutusData a3 = Builtins.tailList(a2);
        PlutusData a4 = Builtins.tailList(a3);
        PlutusData a5 = Builtins.tailList(a4);
        PlutusData a6 = Builtins.tailList(a5);
        PlutusData a7 = Builtins.tailList(a6);
        return Builtins.mkCons(Builtins.headList(a0),
                Builtins.mkCons(Builtins.headList(a1),
                Builtins.mkCons(Builtins.headList(a2),
                Builtins.mkCons(Builtins.headList(a3),
                Builtins.mkCons(Builtins.headList(a4),
                Builtins.mkCons(Builtins.headList(a5),
                Builtins.mkCons(Builtins.headList(a6),
                Builtins.mkCons(Builtins.headList(a7),
                        rest))))))));
    }

    /** The two limb handles of one note's audit data differ (spec §8.1). */
    public static boolean ownHandlesDistinct(PlutusData audit) {
        PlutusData x = Builtins.unListData(audit);
        PlutusData x4 = Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.tailList(x))));
        return !(Builtins.equalsData(Builtins.headList(x), Builtins.headList(x4))
                && Builtins.equalsData(Builtins.headList(Builtins.tailList(x)), Builtins.headList(Builtins.tailList(x4))));
    }

    /** No limb handle of {@code a} equals a limb handle of {@code b}. A handle is the point {@code (A.u, A.v)}. */
    public static boolean handlesDisjoint(PlutusData a, PlutusData b) {
        PlutusData x = Builtins.unListData(a);
        PlutusData x4 = Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.tailList(x))));
        PlutusData y = Builtins.unListData(b);
        PlutusData y4 = Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.tailList(y))));
        return !samePoint(x, y) && !samePoint(x, y4) && !samePoint(x4, y) && !samePoint(x4, y4);
    }

    /** The points at the heads of two coordinate lists ({@code u} then {@code v}) are equal. */
    private static boolean samePoint(PlutusData p, PlutusData q) {
        return Builtins.equalsData(Builtins.headList(p), Builtins.headList(q))
                && Builtins.equalsData(Builtins.headList(Builtins.tailList(p)), Builtins.headList(Builtins.tailList(q)));
    }
}
