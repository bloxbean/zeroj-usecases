package com.bloxbean.cardano.zeroj.usecases.recovery.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PolicyId;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.StakingCredential;
import org.julclang.ledger.TokenName;
import org.julclang.ledger.TxId;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.TxOutRef;
import org.julclang.ledger.Value;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;
import org.zeroj.crypto.groth16.Groth16ProverBLS381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Runs the compiled {@link OwnershipProofValidator} (circuit v4) in the Julc UPLC evaluator — no
 * node, no DevKit. It exercises the two things the validator adds over a bare Groth16 verify:
 *
 * <ol>
 *   <li><b>recipient binding</b> — the proof's 2 packed public inputs are reconstructed on-chain as
 *       {@code [pack(pkh), pack(recipient)]}; a redeemer that names a different recipient than the
 *       one the proof was made for fails verification;</li>
 *   <li><b>payout enforcement</b> (ADR-0009 D6) — only outputs tagged with the voucher's outref
 *       count: the recipient's must sum to the refund and the funder's to the remainder. The M2
 *       mutations are refused: the remainder kept by a third party, outputs shared between two
 *       vouchers (same validator with different stake parts, or a reusable-KYC voucher), untagged
 *       payouts, funder = recipient with only one obligation paid, and a non-ADA voucher.</li>
 * </ol>
 *
 * <p>A tiny 2-public-input Groth16 circuit (packed v4: one scalar per hash) stands in for the 19M
 * derivation circuit — the on-chain verify is O(#public inputs) and blind to circuit size, so its
 * budget equals the real one and setup + prove run in well under a second. The success case prints
 * the evaluator budget as a proxy for on-chain ExUnits.</p>
 */
class OwnershipProofValidatorVmTest extends ContractTest {

    private static final long REFUND = 2_000_000L;   // datum's minimum refund (2 ADA)
    private static final long VOUCHER_LOVELACE = 10_000_000L;
    private static final long MAX_FEE = 2_000_000L;
    /** What the funder must get back: voucher − refund − maxFee. */
    private static final long REMAINDER = VOUCHER_LOVELACE - REFUND - MAX_FEE;

    /** The voucher this claim spends, and another one in the same transaction. */
    private static final TxOutRef VOUCHER = ref(0x11, 1);
    private static final TxOutRef OTHER_VOUCHER = ref(0x22, 0);
    /** This validator's script credential, in the test (the validator never reads its own hash). */
    private static final Credential OWNERSHIP_SCRIPT = scriptCred(0xc2);
    /** A stand-in for another tag-enforcing validator (the reusable-KYC voucher). */
    private static final Credential KYC_SCRIPT = scriptCred(0xc1);
    private static final byte[] FUNDER = filled(0x3c);
    private static final byte[] THIRD_PARTY = filled(0x77);

    private static Program program;

    private static SnarkjsToCardano.VkCompressed vk;
    private static SnarkjsToCardano.ProofCompressed proof;
    private static byte[] pkh;         // 28 bytes the proof attests
    private static byte[] recipient;   // 28 bytes the proof is bound to (the second public input)
    private static CircuitBuilder circuit;
    private static R1CSConstraintSystem r1cs;
    private static Groth16SetupBLS381.SetupResult setup;

    @BeforeAll
    static void buildProof() {
        pkh = new byte[28];
        recipient = new byte[28];
        for (int i = 0; i < 28; i++) { pkh[i] = (byte) (i + 1); recipient[i] = (byte) (100 + i); }
        // v4: the two public inputs are the big-endian packing of the 28-byte hashes — the same
        // scalars the validator recomputes from the datum/redeemer bytes via byteStringToInteger.
        // A stand-in circuit with exactly 2 public inputs (Groth16 verify is O(#public inputs) and
        // blind to circuit size, so this measures the real on-chain cost). One constraint keeps both
        // public inputs live: pkh + recipient == secret.
        CircuitBuilder cb = CircuitBuilder.create("ownership-packed-2-public");
        cb = cb.publicVar("pkh");
        cb = cb.publicVar("recipient");
        cb = cb.secretVar("s");
        cb = cb.define(api -> api.assertEqual(
                api.add(api.var("pkh"), api.var("recipient")), api.var("s")));

        circuit = cb;
        r1cs = cb.compileR1CS(CurveId.BLS12_381);
        assertEquals(2, r1cs.numPublicInputs(), "stand-in circuit must have 2 public inputs");

        var srs = PowersOfTauBLS381.generate(8);
        setup = Groth16SetupBLS381.setup(
                r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(), srs.tauScalar());

        vk = ProverToCardano.compressVk(setup);
        proof = proveFor(pkh, recipient);
        assertEquals(3, vk.ic().size(), "IC must have #public + 1 entries");

        program = new OwnershipProofValidatorVmTest().compileValidator(OwnershipProofValidator.class).program()
                .applyParams(PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                        PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()), vkIcData(vk.ic()));
    }

    /** A stand-in proof for the packed {@code (pkhBytes, recipientBytes)}. */
    private static SnarkjsToCardano.ProofCompressed proveFor(byte[] pkhBytes, byte[] recipientBytes) {
        BigInteger packedPkh = new BigInteger(1, pkhBytes);
        BigInteger packedRecipient = new BigInteger(1, recipientBytes);
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "pkh", List.of(packedPkh),
                "recipient", List.of(packedRecipient),
                "s", List.of(packedPkh.add(packedRecipient))), CurveId.BLS12_381);
        var p = Groth16ProverBLS381.prove(setup.provingKey(), witness, r1cs.constraints(), r1cs.numWires());
        return ProverToCardano.compressProof(p);
    }

    // ---- accepted ----

    @Test
    void validProofAndCorrectPayout_succeeds() {
        EvalResult r = evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER)));
        assertSuccess(r);
        System.out.println("[OwnershipProofValidator v4] budget consumed: " + r.budgetConsumed());
    }

    @Test
    void zeroRemainder_needsNoFunderOutput() {
        long refund = VOUCHER_LOVELACE - MAX_FEE;
        assertSuccess(evaluate(program, ctx(datum(pkh, refund, FUNDER, MAX_FEE), recipient, adaVoucher(), List.of(),
                tagged(recipient, refund, VOUCHER))));
    }

    @Test
    void funderEqualToRecipient_withBothObligationsInOneOutput_succeeds() {
        assertSuccess(evaluate(program, ctx(datum(pkh, REFUND, recipient, MAX_FEE), recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND + REMAINDER, VOUCHER))));
    }

    @Test
    void twoVouchers_eachPaidByItsOwnTaggedOutputs_succeeds() {
        TxInInfo other = voucherInput(OTHER_VOUCHER, OWNERSHIP_SCRIPT, filled(0x02), datum(), adaVoucher());
        assertSuccess(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(other),
                tagged(recipient, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER),
                tagged(recipient, REFUND, OTHER_VOUCHER), tagged(FUNDER, REMAINDER, OTHER_VOUCHER))));
    }

    // ---- payout mutations (ADR-0009 D6, M2 exit) ----

    @Test
    void thirdPartyKeepingTheRemainder_fails() {
        assertFailure(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND, VOUCHER), tagged(THIRD_PARTY, REMAINDER, VOUCHER))));
        assertFailure(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND, VOUCHER))));
    }

    @Test
    void funderShortByOneLovelace_fails() {
        assertFailure(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND, VOUCHER), tagged(FUNDER, REMAINDER - 1, VOUCHER))));
    }

    @Test
    void underpayingTheRecipient_fails() {
        // proof is valid and paid to the right recipient, but below the datum's refund amount.
        assertFailure(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND - 1, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void payingSomeoneElse_fails() {
        // valid proof, full amount, but no output pays the bound recipient.
        assertFailure(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(),
                tagged(THIRD_PARTY, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void untaggedPayouts_fail() {
        assertFailure(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(),
                untagged(recipient, REFUND), untagged(FUNDER, REMAINDER))));
        assertFailure(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(),
                withDatum(recipient, REFUND, PlutusData.bytes(VOUCHER.txId().hash())),
                withDatum(FUNDER, REMAINDER, PlutusData.bytes(VOUCHER.txId().hash())))));
    }

    @Test
    void twoVouchersOfThisValidator_withDifferentStakeParts_sharingOutputs_fail() {
        TxInInfo other = voucherInput(OTHER_VOUCHER, OWNERSHIP_SCRIPT, filled(0x02), datum(), adaVoucher());
        assertFailure(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(other),
                tagged(recipient, 2 * REFUND, OTHER_VOUCHER), tagged(FUNDER, 2 * REMAINDER, OTHER_VOUCHER))));
    }

    @Test
    void aVoucherOfAnotherValidator_sharingOutputs_fails() {
        // A reusable-KYC voucher (another tag-enforcing validator) in the same transaction.
        PlutusData kycDatum = PlutusData.constr(0, PlutusData.bytes("USA".getBytes()),
                PlutusData.bytes("verified".getBytes()), PlutusData.bytes(recipient),
                PlutusData.integer(big(REFUND)), PlutusData.bytes(FUNDER), PlutusData.integer(big(MAX_FEE)));
        TxInInfo other = voucherInput(OTHER_VOUCHER, KYC_SCRIPT, filled(0x01), kycDatum, adaVoucher());
        assertFailure(evaluate(program, ctx(datum(), recipient, adaVoucher(), List.of(other),
                tagged(recipient, 2 * REFUND, OTHER_VOUCHER), tagged(FUNDER, 2 * REMAINDER, OTHER_VOUCHER))));
    }

    @Test
    void funderEqualToRecipient_withOnlyOneObligationPaid_fails() {
        PlutusData sameKey = datum(pkh, REFUND, recipient, MAX_FEE);
        assertFailure(evaluate(program, ctx(sameKey, recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND, VOUCHER))));
        assertFailure(evaluate(program, ctx(sameKey, recipient, adaVoucher(), List.of(),
                tagged(recipient, REMAINDER, VOUCHER))));
        assertFailure(evaluate(program, ctx(sameKey, recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND + REMAINDER - 1, VOUCHER))));
    }

    @Test
    void nonAdaVoucher_fails() {
        Value withToken = adaVoucher().merge(
                Value.singleton(PolicyId.of(filled(0x99)), TokenName.of("t".getBytes()), BigInteger.ONE));
        assertFailure(evaluate(program, ctx(datum(), recipient, withToken, List.of(),
                tagged(recipient, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void outOfRangeTerms_fail() {
        assertFailure(evaluate(program, ctx(datum(pkh, REFUND, FUNDER, VOUCHER_LOVELACE - REFUND + 1), recipient,
                adaVoucher(), List.of(), tagged(recipient, REFUND, VOUCHER))));
        assertFailure(evaluate(program, ctx(datum(pkh, REFUND, FUNDER, -1), recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND, VOUCHER), tagged(FUNDER, VOUCHER_LOVELACE, VOUCHER))));
        assertFailure(evaluate(program, ctx(datum(pkh, -1, FUNDER, MAX_FEE), recipient, adaVoucher(), List.of(),
                tagged(recipient, 0, VOUCHER), tagged(FUNDER, VOUCHER_LOVELACE, VOUCHER))));
        assertFailure(evaluate(program, ctx(datum(pkh, REFUND, new byte[27], MAX_FEE), recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND, VOUCHER), tagged(new byte[27], REMAINDER, VOUCHER))));
    }

    // ---- proof binding (unchanged) ----

    @Test
    void redeemerNamesADifferentRecipientThanTheProof_fails() {
        // The redeemer (and the paid output) claim a recipient the proof was NOT bound to: the
        // reconstructed public inputs no longer match the proof, so verification fails — even though
        // the payout to that recipient is correct. This is the binding.
        byte[] tampered = recipient.clone();
        tampered[0] ^= 0x01;
        assertFailure(evaluate(program, ctx(datum(), tampered, adaVoucher(), List.of(),
                tagged(tampered, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void datumPkhDoesNotMatchTheProof_fails() {
        // The datum claims a different pkh than the proof attests: the reconstructed first public
        // input no longer matches the proof, so verification fails. This is the pkh binding.
        byte[] wrongPkh = pkh.clone();
        wrongPkh[0] ^= 0x01;
        assertFailure(evaluate(program, ctx(datum(wrongPkh, REFUND, FUNDER, MAX_FEE), recipient, adaVoucher(), List.of(),
                tagged(recipient, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void datumPkhNotExactly28Bytes_fails() {
        // A proof made for a pkh whose first byte is 0x00: the 27-byte tail packs to the same
        // scalar, so without the length check the datum could name a 27-byte "pkh".
        byte[] zeroLed = pkh.clone();
        zeroLed[0] = 0;
        byte[] tail = Arrays.copyOfRange(zeroLed, 1, 28);
        assertEquals(new BigInteger(1, zeroLed), new BigInteger(1, tail));
        var zeroProof = proveFor(zeroLed, recipient);
        assertSuccess(evaluate(program, ctx(datum(zeroLed, REFUND, FUNDER, MAX_FEE), recipient, zeroProof,
                adaVoucher(), List.of(), tagged(recipient, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
        assertFailure(evaluate(program, ctx(datum(tail, REFUND, FUNDER, MAX_FEE), recipient, zeroProof,
                adaVoucher(), List.of(), tagged(recipient, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
        // A 29-byte pkh (an extra leading zero) is refused too.
        byte[] padded = new byte[29];
        System.arraycopy(zeroLed, 0, padded, 1, 28);
        assertFailure(evaluate(program, ctx(datum(padded, REFUND, FUNDER, MAX_FEE), recipient, zeroProof,
                adaVoucher(), List.of(), tagged(recipient, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    private static PlutusData datum() {
        return datum(pkh, REFUND, FUNDER, MAX_FEE);
    }

    private static PlutusData datum(byte[] datumPkh, long refund, byte[] funder, long maxFee) {
        return PlutusData.constr(0, PlutusData.bytes(datumPkh), PlutusData.integer(big(refund)),
                PlutusData.bytes(funder), PlutusData.integer(big(maxFee)));
    }

    /**
     * A spend of {@link #VOUCHER} (at this script, stake part {@code 0x01…}) holding
     * {@code voucherValue} under {@code datum}, with the proof and {@code redeemerRecipient} as the
     * redeemer, alongside {@code otherInputs}, with {@code outputs}.
     */
    private PlutusData ctx(PlutusData datum, byte[] redeemerRecipient, Value voucherValue,
                           List<TxInInfo> otherInputs, TxOut... outputs) {
        return ctx(datum, redeemerRecipient, proof, voucherValue, otherInputs, outputs);
    }

    private PlutusData ctx(PlutusData datum, byte[] redeemerRecipient, SnarkjsToCardano.ProofCompressed withProof,
                           Value voucherValue, List<TxInInfo> otherInputs, TxOut... outputs) {
        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(withProof.piA()), PlutusData.bytes(withProof.piB()),
                PlutusData.bytes(withProof.piC()), PlutusData.bytes(redeemerRecipient));
        var builder = spendingContext(VOUCHER, datum).redeemer(redeemer)
                .input(voucherInput(VOUCHER, OWNERSHIP_SCRIPT, filled(0x01), datum, voucherValue));
        for (TxInInfo input : otherInputs) builder = builder.input(input);
        for (TxOut output : outputs) builder = builder.output(output);
        return builder.buildPlutusData();
    }

    private static Value adaVoucher() {
        return Value.lovelace(big(VOUCHER_LOVELACE));
    }

    /** A voucher input at {@code script} with stake key {@code stake}, holding an inline datum. */
    private static TxInInfo voucherInput(TxOutRef ref, Credential script, byte[] stake, PlutusData datum, Value value) {
        Address address = new Address(script, Optional.of(
                new StakingCredential.StakingHash(new Credential.PubKeyCredential(PubKeyHash.of(stake)))));
        return new TxInInfo(ref, new TxOut(address, value, new OutputDatum.OutputDatumInline(datum), Optional.empty()));
    }

    /** An output to {@code pkh}'s key credential tagged with {@code voucher}'s outref. */
    private static TxOut tagged(byte[] pkh, long lovelace, TxOutRef voucher) {
        return withDatum(pkh, lovelace, voucher.toPlutusData());
    }

    private static TxOut withDatum(byte[] pkh, long lovelace, PlutusData datum) {
        return new TxOut(TestDataBuilder.pubKeyAddress(PubKeyHash.of(pkh)), Value.lovelace(big(lovelace)),
                new OutputDatum.OutputDatumInline(datum), Optional.empty());
    }

    private static TxOut untagged(byte[] pkh, long lovelace) {
        return TestDataBuilder.txOut(TestDataBuilder.pubKeyAddress(PubKeyHash.of(pkh)), Value.lovelace(big(lovelace)));
    }

    private static TxOutRef ref(int fill, long index) {
        byte[] txId = new byte[32];
        Arrays.fill(txId, (byte) fill);
        return new TxOutRef(TxId.of(txId), BigInteger.valueOf(index));
    }

    private static Credential scriptCred(int fill) {
        return new Credential.ScriptCredential(ScriptHash.of(filled(fill)));
    }

    private static byte[] filled(int fill) {
        byte[] out = new byte[28];
        Arrays.fill(out, (byte) fill);
        return out;
    }

    private static BigInteger big(long value) {
        return BigInteger.valueOf(value);
    }

    private static PlutusData vkIcData(List<byte[]> ic) {
        List<PlutusData> values = new ArrayList<>();
        for (byte[] point : ic) values.add(PlutusData.bytes(point));
        return PlutusData.list(values.toArray(new PlutusData[0]));
    }
}
