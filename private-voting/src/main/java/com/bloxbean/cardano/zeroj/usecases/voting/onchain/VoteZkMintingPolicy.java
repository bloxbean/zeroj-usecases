package com.bloxbean.cardano.zeroj.usecases.voting.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MintingValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.lib.IntervalLib;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * Verifies a private ballot on-chain (ADR-0005) and mints its nullifier token.
 *
 * <p>The redeemer carries only the Groth16 proof. Every public input of {@code R_ballot} comes
 * from this script's parameters or from the ledger:
 * {@code [electionId, voterRoot, PK.u, PK.v, N, A.u, A.v, B.u, B.v]}.
 * <ul>
 *   <li>{@code electionId}, {@code voterRoot} and the election key {@code PK} are parameters, so a
 *       proof against any other voter tree or key is rejected (V1).</li>
 *   <li>{@code N} is the name of the single token minted here (V2). The vote list keys the new
 *       node by the same {@code N}.</li>
 *   <li>{@code (A, B)} is read from the inline datum of the single output that holds the token:
 *       the new vote-list node. The stored ballot is therefore the proved ballot (V3). Exactly one
 *       unit of the token may exist across all outputs, so an earlier copy of the token cannot
 *       stand in for the node.</li>
 *   <li>The transaction's validity range must end at or before {@code votingDeadline} (V6).</li>
 *   <li>Every integer is checked to be a canonical field element (V10).</li>
 * </ul>
 */
@MintingValidator
public class VoteZkMintingPolicy {

    @Param static BigInteger electionId;
    @Param static BigInteger voterRoot;
    @Param static BigInteger electionKeyU;
    @Param static BigInteger electionKeyV;
    @Param static BigInteger votingDeadline;   // POSIX time, milliseconds
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record BallotProof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(BallotProof proof, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);

        if (!VoteListLib.canonicalField(electionId) || !VoteListLib.canonicalField(voterRoot)
                || !VoteListLib.canonicalField(electionKeyU) || !VoteListLib.canonicalField(electionKeyV)) {
            return false;
        }

        // The nullifier token: the only entry minted under this policy, quantity 1, 32 bytes.
        if (VoteListLib.policyEntryCount(txInfo.mint(), policy) != 1) return false;
        byte[] name = ValuesLib.findTokenName(txInfo.mint(), policy, BigInteger.ONE);
        if (Builtins.lengthOfByteString(name) != 32) return false;
        BigInteger nullifier = Builtins.byteStringToInteger(true, name);
        if (!VoteListLib.canonicalField(nullifier)) return false;

        // Cast no later than the deadline.
        BigInteger upper = IntervalLib.finiteUpperBound(txInfo.validRange());
        if (upper.compareTo(BigInteger.ZERO) < 0 || upper.compareTo(votingDeadline) > 0) return false;

        // The ballot: the inline datum of the one output that holds the token.
        BigInteger held = BigInteger.ZERO;
        PlutusData node = Builtins.iData(BigInteger.ZERO);
        for (TxOut output : txInfo.outputs()) {
            BigInteger qty = ValuesLib.assetOf(output.value(), policy, name);
            if (qty.compareTo(BigInteger.ZERO) > 0) {
                held = held.add(qty);
                node = inlineDatum(output);
            } else {
                held = held;
                node = node;
            }
        }
        if (held.compareTo(BigInteger.ONE) != 0 || !isBallotNode(node)) return false;

        PlutusData ballot = Builtins.headList(Builtins.constrFields(node));
        BigInteger au = coordinate(ballot, 0);
        BigInteger av = coordinate(ballot, 1);
        BigInteger bu = coordinate(ballot, 2);
        BigInteger bv = coordinate(ballot, 3);
        if (!VoteListLib.canonicalField(au) || !VoteListLib.canonicalField(av)
                || !VoteListLib.canonicalField(bu) || !VoteListLib.canonicalField(bv)) {
            return false;
        }

        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(electionId),
                Builtins.mkCons(Builtins.iData(voterRoot),
                Builtins.mkCons(Builtins.iData(electionKeyU),
                Builtins.mkCons(Builtins.iData(electionKeyV),
                Builtins.mkCons(Builtins.iData(nullifier),
                Builtins.mkCons(Builtins.iData(au),
                Builtins.mkCons(Builtins.iData(av),
                Builtins.mkCons(Builtins.iData(bu),
                Builtins.mkCons(Builtins.iData(bv),
                        Builtins.mkNilData()))))))))));
        return Groth16BLS12381Lib.verify(
                publicInputs,
                proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    /**
     * {@code ListElement(Ballot(Au, Av, Bu, Bv), nextKey)}:
     * {@code Constr 0 [Constr 0 [I, I, I, I], B]}. Any other shape returns false or makes a builtin
     * fail (fail closed).
     */
    private static boolean isBallotNode(PlutusData node) {
        if (Builtins.constrTag(node) != 0) return false;
        PlutusData fields = Builtins.constrFields(node);
        if (Builtins.nullList(fields)) return false;
        PlutusData rest = Builtins.tailList(fields);
        if (Builtins.nullList(rest) || !Builtins.nullList(Builtins.tailList(rest))) return false;
        if (Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(rest))) < 0) return false;
        PlutusData ballot = Builtins.headList(fields);
        if (Builtins.constrTag(ballot) != 0) return false;
        PlutusData c0 = Builtins.constrFields(ballot);
        if (Builtins.nullList(c0)) return false;
        PlutusData c1 = Builtins.tailList(c0);
        if (Builtins.nullList(c1)) return false;
        PlutusData c2 = Builtins.tailList(c1);
        if (Builtins.nullList(c2)) return false;
        PlutusData c3 = Builtins.tailList(c2);
        if (Builtins.nullList(c3)) return false;
        return Builtins.nullList(Builtins.tailList(c3));
    }

    private static BigInteger coordinate(PlutusData ballot, int index) {
        PlutusData fields = Builtins.constrFields(ballot);
        int i = 0;
        while (i < index) {
            fields = Builtins.tailList(fields);
            i = i + 1;
        }
        return Builtins.unIData(Builtins.headList(fields));
    }

    /** The inline datum; a missing or hashed datum yields an integer, which never parses. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }
}
