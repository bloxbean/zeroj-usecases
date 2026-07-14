package com.bloxbean.cardano.zeroj.usecases.recovery.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.PubKeyHash;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.ledger.TxOutRef;
import com.bloxbean.cardano.julc.ledger.Value;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.julc.vm.EvalResult;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Runs the compiled {@link OwnershipProofValidator} (circuit v3) in the Julc UPLC evaluator — no
 * node, no DevKit. It exercises the two things the validator adds over a bare Groth16 verify:
 *
 * <ol>
 *   <li><b>recipient binding</b> — the proof's 56 public inputs are reconstructed on-chain as
 *       {@code pkh ++ recipient}; a redeemer that names a different recipient than the one the proof
 *       was made for fails verification;</li>
 *   <li><b>payout enforcement</b> — some output must pay the bound recipient's payment credential at
 *       least the datum's {@code refundAmount}; underpaying or paying someone else fails.</li>
 * </ol>
 *
 * <p>A tiny 2-public-input Groth16 circuit (packed v4: one scalar per hash) stands in for the 19M
 * derivation circuit — the on-chain verify is O(#public inputs) and blind to circuit size, so its
 * budget equals the real one and setup + prove run in well under a second. The success case prints
 * the evaluator budget as a proxy for on-chain ExUnits (expected ~2.8×10⁹ steps, under the 10×10⁹
 * per-tx limit).</p>
 */
class OwnershipProofValidatorVmTest extends ContractTest {

    private static final long REFUND = 2_000_000L;   // datum's minimum refund (2 ADA)

    private static SnarkjsToCardano.VkCompressed vk;
    private static SnarkjsToCardano.ProofCompressed proof;
    private static byte[] pkh;         // 28 bytes the proof attests
    private static byte[] recipient;   // 28 bytes the proof is bound to (public inputs 28..55)

    @BeforeAll
    static void buildProof() {
        pkh = new byte[28];
        recipient = new byte[28];
        for (int i = 0; i < 28; i++) { pkh[i] = (byte) (i + 1); recipient[i] = (byte) (100 + i); }
        // v4: the two public inputs are the big-endian packing of the 28-byte hashes — the same
        // scalars the validator recomputes from the datum/redeemer bytes via byteStringToInteger.
        BigInteger packedPkh = new BigInteger(1, pkh);
        BigInteger packedRecipient = new BigInteger(1, recipient);

        // A stand-in circuit with exactly 2 public inputs (Groth16 verify is O(#public inputs) and
        // blind to circuit size, so this measures the real on-chain cost). One constraint keeps both
        // public inputs live: pkh + recipient == secret.
        var cb = CircuitBuilder.create("ownership-packed-2-public");
        cb = cb.publicVar("pkh");
        cb = cb.publicVar("recipient");
        cb = cb.secretVar("s");
        cb = cb.define(api -> api.assertEqual(
                api.add(api.var("pkh"), api.var("recipient")), api.var("s")));

        var r1cs = cb.compileR1CS(CurveId.BLS12_381);
        assertEquals(2, r1cs.numPublicInputs(), "stand-in circuit must have 2 public inputs");

        BigInteger[] witness = cb.calculateWitness(Map.of(
                "pkh", List.of(packedPkh),
                "recipient", List.of(packedRecipient),
                "s", List.of(packedPkh.add(packedRecipient))), CurveId.BLS12_381);

        var srs = PowersOfTauBLS381.generate(8);
        var setup = Groth16SetupBLS381.setup(
                r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(), srs.tauScalar());
        var p = Groth16ProverBLS381.prove(
                setup.provingKey(), witness, r1cs.constraints(), r1cs.numWires());

        vk = ProverToCardano.compressVk(setup);
        proof = ProverToCardano.compressProof(p);
        assertEquals(3, vk.ic().size(), "IC must have #public + 1 entries");
    }

    @Test
    void validProofAndCorrectPayout_succeeds() {
        EvalResult r = run(recipient, REFUND, recipient, REFUND);
        assertSuccess(r);
        System.out.println("[OwnershipProofValidator v3] budget consumed: " + r.budgetConsumed());
    }

    @Test
    void underpayingTheRecipient_fails() {
        // proof is valid and paid to the right recipient, but below the datum's refund amount.
        assertFailure(run(recipient, REFUND, recipient, REFUND - 1));
    }

    @Test
    void payingSomeoneElse_fails() {
        // valid proof, full amount, but no output pays the bound recipient.
        byte[] someoneElse = new byte[28];
        for (int i = 0; i < 28; i++) someoneElse[i] = (byte) (200 + i);
        assertFailure(run(recipient, REFUND, someoneElse, REFUND));
    }

    @Test
    void redeemerNamesADifferentRecipientThanTheProof_fails() {
        // The redeemer (and the paid output) claim a recipient the proof was NOT bound to: the
        // reconstructed public inputs no longer match the proof, so verification fails — even though
        // the payout to that recipient is correct. This is the binding.
        byte[] tampered = recipient.clone();
        tampered[0] ^= 0x01;
        assertFailure(run(tampered, REFUND, tampered, REFUND));
    }

    @Test
    void datumPkhDoesNotMatchTheProof_fails() {
        // The datum claims a different pkh than the proof attests: the reconstructed first public
        // input no longer matches the proof, so verification fails. This is the pkh binding.
        byte[] wrongPkh = pkh.clone();
        wrongPkh[0] ^= 0x01;
        assertFailure(run(wrongPkh, recipient, REFUND, recipient, REFUND));
    }

    /**
     * Compile + parameterise the validator, then evaluate it against a spending context whose single
     * output pays {@code outputRecipient} exactly {@code paid} lovelace.
     *
     * @param redeemerRecipient the recipient bytes placed in the redeemer (bound into the proof when
     *                          equal to {@link #recipient})
     * @param refundAmount      the datum's minimum refund
     * @param outputRecipient   the payment key hash the output actually pays
     * @param paid              lovelace on that output
     */
    private EvalResult run(byte[] redeemerRecipient, long refundAmount,
                                byte[] outputRecipient, long paid) {
        return run(pkh, redeemerRecipient, refundAmount, outputRecipient, paid);
    }

    private EvalResult run(byte[] datumPkh, byte[] redeemerRecipient, long refundAmount,
                                byte[] outputRecipient, long paid) {
        var compiled = compileValidator(OwnershipProofValidator.class);
        var program = compiled.program().applyParams(
                PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()), vkIcData(vk.ic()));

        var datum = PlutusData.constr(0,
                PlutusData.bytes(datumPkh), PlutusData.integer(BigInteger.valueOf(refundAmount)));
        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(proof.piA()), PlutusData.bytes(proof.piB()),
                PlutusData.bytes(proof.piC()), PlutusData.bytes(redeemerRecipient));

        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        TxOut payout = TestDataBuilder.txOut(
                TestDataBuilder.pubKeyAddress(PubKeyHash.of(outputRecipient)),
                Value.lovelace(BigInteger.valueOf(paid)));
        var ctx = spendingContext(ref, datum).redeemer(redeemer).output(payout).buildPlutusData();

        return evaluate(program, ctx);
    }

    private static PlutusData vkIcData(List<byte[]> ic) {
        List<PlutusData> values = new ArrayList<>();
        for (byte[] point : ic) values.add(PlutusData.bytes(point));
        return PlutusData.list(values.toArray(new PlutusData[0]));
    }
}
