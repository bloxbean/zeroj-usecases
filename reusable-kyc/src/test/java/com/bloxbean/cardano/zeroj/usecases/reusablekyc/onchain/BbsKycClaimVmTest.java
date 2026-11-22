package com.bloxbean.cardano.zeroj.usecases.reusablekyc.onchain;

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
import org.zeroj.bbs.BbsCiphersuite;
import org.zeroj.bbs.BbsPresentation;
import org.zeroj.bbs.internal.BbsCodec;
import org.zeroj.bbs.internal.CfrgBbsCore;
import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.Bls12381Providers;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycCredential;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.HolderService;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.IssuerService;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.OnChainKycClaimService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The full reusable-KYC on-chain claim gate in the Julc VM: a voucher is spent only when the holder's
 * BBS presentation verifies <b>on-chain</b>, discloses exactly the attributes the voucher requires,
 * and the voucher pays exactly what it owes through outputs tagged with its own outref (ADR-0009 D6).
 * Exercises the accept paths, the presentation-binding failures, and the M2 voucher mutations: the
 * remainder kept by a third party, outputs shared between two vouchers (same validator with different
 * stake parts, or a voucher of another tag-enforcing validator), untagged payouts, funder = recipient
 * with only one obligation paid, and a non-ADA voucher.
 */
class BbsKycClaimVmTest extends ContractTest {

    private static final BbsCiphersuite SUITE = BbsCiphersuite.BLS12381_SHA256;
    private static final Bls12381Provider BLS = Bls12381Providers.pureJava();
    private static final long REFUND = 2_000_000L;
    private static final long VOUCHER_LOVELACE = 10_000_000L;
    private static final long MAX_FEE = 2_000_000L;
    /** What the funder must get back: voucher − refund − maxFee. */
    private static final long REMAINDER = VOUCHER_LOVELACE - REFUND - MAX_FEE;

    /** This validator's script credential, in the test (the validator never reads its own hash). */
    private static final Credential KYC_SCRIPT = scriptCred(0xc1);
    /** A stand-in for another tag-enforcing validator (the account-ownership voucher). */
    private static final Credential OWNERSHIP_SCRIPT = scriptCred(0xc2);

    private static byte[] u(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static byte[] a(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] g1c(org.zeroj.bls12381.ec.G1Point p) { return Bls12381Codecs.g1ToCompressed(p); }

    private static Program program;
    /** The voucher this claim spends — its ref is what the presentation header is derived from. */
    private static final TxOutRef VOUCHER = ref(0x11, 1);
    /** A different voucher, to show a presentation can't be lifted from one claim to another. */
    private static final TxOutRef OTHER_VOUCHER = ref(0x22, 0);

    private static BbsCodec.ProofParts pp;
    private static BbsCodec.ProofParts ppOther;
    private static byte[] ph;
    private static byte[] phOther;
    private static byte[] recipientPkh;
    private static final byte[] FUNDER = filled(0x3c);
    private static final byte[] THIRD_PARTY = filled(0x77);

    @BeforeAll
    static void setup() {
        byte[] seed = new byte[32]; Arrays.fill(seed, (byte) 9);
        IssuerService issuer = new IssuerService(seed, "kyc-provider-1");
        var credential = issuer.issue(new KycCredential(
                "Alice Example", "1990-05-01", "USA", "verified", "9f86d081884c7d659a2feaa0c55ad015a"));

        recipientPkh = new byte[28];
        Arrays.fill(recipientPkh, (byte) 0x5a);

        // The header is not a chosen nonce: it's derived from the voucher being spent + the recipient,
        // exactly as the validator recomputes it on-chain.
        ph = headerFor(VOUCHER, recipientPkh);
        phOther = headerFor(OTHER_VOUCHER, recipientPkh);

        var holder = new HolderService(credential);
        BbsPresentation presentation = holder.present(List.of("country", "kycLevel"), ph);
        pp = BbsCodec.octetsToProof(presentation.proof().bytes(), SUITE);
        ppOther = BbsCodec.octetsToProof(
                holder.present(List.of("country", "kycLevel"), phOther).proof().bytes(), SUITE);

        byte[] apiId = SUITE.apiId();
        byte[] w = issuer.publicKey().bytes();
        CfrgBbsCore.Generators gens = CfrgBbsCore.createGenerators(6, SUITE, BLS);
        byte[] domainBytes = BbsCodec.scalarToBytesAllowZero(
                CfrgBbsCore.calculateDomain(w, gens, issuer.header(), SUITE));

        program = new BbsKycClaimVmTest().compileValidator(BbsKycClaimValidator.class).program().applyParams(
                PlutusData.bytes(w),
                PlutusData.bytes(Bls12381Codecs.g2ToCompressed(BLS.g2Generator())),
                PlutusData.bytes(g1c(SUITE.p1())),
                PlutusData.bytes(g1c(gens.q1())),
                PlutusData.bytes(g1c(gens.h().get(0))), PlutusData.bytes(g1c(gens.h().get(1))),
                PlutusData.bytes(g1c(gens.h().get(2))), PlutusData.bytes(g1c(gens.h().get(3))),
                PlutusData.bytes(g1c(gens.h().get(4))),
                PlutusData.bytes(domainBytes),
                PlutusData.bytes(concat(apiId, a("H2S_"))),
                PlutusData.bytes(concat(apiId, a("MAP_MSG_TO_SCALAR_AS_HASH_"))));
    }

    // ---- accepted ----

    @Test
    void valid_presentation_matching_policy_and_correct_payout_succeeds() {
        var result = evaluate(program, claimCtx(datum(), adaVoucher(),
                tagged(recipientPkh, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER)));
        assertSuccess(result);
        System.out.println("[BbsKycClaimValidator] budget consumed: " + result.budgetConsumed());
    }

    @Test
    void zero_remainder_needs_no_funder_output() {
        // refund + maxFee == voucher: nothing is owed to the funder.
        long refund = VOUCHER_LOVELACE - MAX_FEE;
        assertSuccess(evaluate(program, claimCtx(datum(recipientPkh, refund, FUNDER, MAX_FEE), adaVoucher(),
                tagged(recipientPkh, refund, VOUCHER))));
    }

    @Test
    void funder_equal_to_recipient_with_both_obligations_in_one_output_succeeds() {
        assertSuccess(evaluate(program, claimCtx(datum(recipientPkh, REFUND, recipientPkh, MAX_FEE), adaVoucher(),
                tagged(recipientPkh, REFUND + REMAINDER, VOUCHER))));
    }

    @Test
    void two_vouchers_each_paid_by_its_own_tagged_outputs_succeeds() {
        // Two vouchers of this validator in one transaction is fine when each is paid separately.
        TxInInfo other = voucherInput(OTHER_VOUCHER, KYC_SCRIPT, filled(0x02), datum(), Value.lovelace(big(VOUCHER_LOVELACE)));
        assertSuccess(evaluate(program, claimCtx(datum(), adaVoucher(), List.of(other),
                tagged(recipientPkh, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER),
                tagged(recipientPkh, REFUND, OTHER_VOUCHER), tagged(FUNDER, REMAINDER, OTHER_VOUCHER))));
    }

    // ---- payout mutations (ADR-0009 D6, M2 exit) ----

    @Test
    void third_party_keeping_the_remainder_fails() {
        // The recipient is paid, but the remainder goes to whoever submitted the claim.
        assertFailure(evaluate(program, claimCtx(datum(), adaVoucher(),
                tagged(recipientPkh, REFUND, VOUCHER), tagged(THIRD_PARTY, REMAINDER, VOUCHER))));
        assertFailure(evaluate(program, claimCtx(datum(), adaVoucher(),
                tagged(recipientPkh, REFUND, VOUCHER))));
    }

    @Test
    void funder_short_by_one_lovelace_fails() {
        assertFailure(evaluate(program, claimCtx(datum(), adaVoucher(),
                tagged(recipientPkh, REFUND, VOUCHER), tagged(FUNDER, REMAINDER - 1, VOUCHER))));
    }

    @Test
    void underpaying_the_recipient_fails() {
        assertFailure(evaluate(program, claimCtx(datum(), adaVoucher(),
                tagged(recipientPkh, REFUND - 1, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void paying_someone_else_fails() {
        assertFailure(evaluate(program, claimCtx(datum(), adaVoucher(),
                tagged(THIRD_PARTY, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void untagged_payouts_fail() {
        // Correct amounts to the correct keys, but without the voucher's outref as inline datum.
        assertFailure(evaluate(program, claimCtx(datum(), adaVoucher(),
                untagged(recipientPkh, REFUND), untagged(FUNDER, REMAINDER))));
        // Tagged with something other than the outref (the outref's tx id alone).
        assertFailure(evaluate(program, claimCtx(datum(), adaVoucher(),
                withDatum(recipientPkh, REFUND, PlutusData.bytes(VOUCHER.txId().hash())),
                withDatum(FUNDER, REMAINDER, PlutusData.bytes(VOUCHER.txId().hash())))));
    }

    @Test
    void two_vouchers_of_this_validator_with_different_stake_parts_sharing_outputs_fail() {
        // Another voucher under the same script credential but a different stake part. The outputs
        // pay enough for both, but are tagged only for the other voucher: they don't count here.
        TxInInfo other = voucherInput(OTHER_VOUCHER, KYC_SCRIPT, filled(0x02), datum(), Value.lovelace(big(VOUCHER_LOVELACE)));
        assertFailure(evaluate(program, claimCtx(datum(), adaVoucher(), List.of(other),
                tagged(recipientPkh, 2 * REFUND, OTHER_VOUCHER), tagged(FUNDER, 2 * REMAINDER, OTHER_VOUCHER))));
    }

    @Test
    void a_voucher_of_another_validator_sharing_outputs_fails() {
        // An account-ownership voucher (another tag-enforcing validator) in the same transaction,
        // whose tagged outputs would also cover this voucher's amounts.
        PlutusData ownershipDatum = PlutusData.constr(0, PlutusData.bytes(filled(0x44)),
                PlutusData.integer(big(REFUND)), PlutusData.bytes(FUNDER), PlutusData.integer(big(MAX_FEE)));
        TxInInfo other = voucherInput(OTHER_VOUCHER, OWNERSHIP_SCRIPT, filled(0x01), ownershipDatum,
                Value.lovelace(big(VOUCHER_LOVELACE)));
        assertFailure(evaluate(program, claimCtx(datum(), adaVoucher(), List.of(other),
                tagged(recipientPkh, 2 * REFUND, OTHER_VOUCHER), tagged(FUNDER, 2 * REMAINDER, OTHER_VOUCHER))));
    }

    @Test
    void funder_equal_to_recipient_with_only_one_obligation_paid_fails() {
        PlutusData sameKey = datum(recipientPkh, REFUND, recipientPkh, MAX_FEE);
        // Only the refund: the remainder owed to the (same) funder key is missing.
        assertFailure(evaluate(program, claimCtx(sameKey, adaVoucher(), tagged(recipientPkh, REFUND, VOUCHER))));
        // Only the remainder: one output can't count for both obligations.
        assertFailure(evaluate(program, claimCtx(sameKey, adaVoucher(), tagged(recipientPkh, REMAINDER, VOUCHER))));
        assertFailure(evaluate(program, claimCtx(sameKey, adaVoucher(),
                tagged(recipientPkh, REFUND + REMAINDER - 1, VOUCHER))));
    }

    @Test
    void non_ada_voucher_fails() {
        Value withToken = Value.lovelace(big(VOUCHER_LOVELACE)).merge(
                Value.singleton(PolicyId.of(filled(0x99)), TokenName.of(u("t")), BigInteger.ONE));
        assertFailure(evaluate(program, claimCtx(datum(), withToken,
                tagged(recipientPkh, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void out_of_range_terms_fail() {
        // refundAmount + maxFee > voucherLovelace
        assertFailure(evaluate(program, claimCtx(datum(recipientPkh, REFUND, FUNDER, VOUCHER_LOVELACE - REFUND + 1),
                adaVoucher(), tagged(recipientPkh, REFUND, VOUCHER))));
        // negative maxFee (would raise the remainder above the voucher's value)
        assertFailure(evaluate(program, claimCtx(datum(recipientPkh, REFUND, FUNDER, -1), adaVoucher(),
                tagged(recipientPkh, REFUND, VOUCHER), tagged(FUNDER, VOUCHER_LOVELACE, VOUCHER))));
        // negative refundAmount
        assertFailure(evaluate(program, claimCtx(datum(recipientPkh, -1, FUNDER, MAX_FEE), adaVoucher(),
                tagged(recipientPkh, 0, VOUCHER), tagged(FUNDER, VOUCHER_LOVELACE, VOUCHER))));
        // a funder key hash that isn't 28 bytes
        assertFailure(evaluate(program, claimCtx(datum(recipientPkh, REFUND, new byte[27], MAX_FEE), adaVoucher(),
                tagged(recipientPkh, REFUND, VOUCHER), tagged(new byte[27], REMAINDER, VOUCHER))));
    }

    // ---- presentation binding (unchanged) ----

    @Test
    void policy_mismatch_fails() {
        // voucher requires country=JPN, but the credential discloses USA
        PlutusData jpn = datum("JPN", "verified", recipientPkh, REFUND, FUNDER, MAX_FEE);
        assertFailure(evaluate(program, claimCtx(jpn, claim(pp, ph), adaVoucher(), List.of(),
                tagged(recipientPkh, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void tampered_presentation_header_fails() {
        assertFailure(evaluate(program, claimCtx(datum(), claim(pp, u("different-nonce")), adaVoucher(), List.of(),
                tagged(recipientPkh, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    @Test
    void presentation_bound_to_another_voucher_fails() {
        // A genuine, fully-valid presentation — but made for a different voucher. Replaying it here
        // must fail: the validator derives the expected header from the voucher it is spending.
        assertFailure(evaluate(program, claimCtx(datum(), claim(ppOther, phOther), adaVoucher(), List.of(),
                tagged(recipientPkh, REFUND, VOUCHER), tagged(FUNDER, REMAINDER, VOUCHER))));
    }

    private static PlutusData datum() {
        return datum(recipientPkh, REFUND, FUNDER, MAX_FEE);
    }

    private static PlutusData datum(byte[] recipient, long refund, byte[] funder, long maxFee) {
        return datum("USA", "verified", recipient, refund, funder, maxFee);
    }

    private static PlutusData datum(String country, String kycLevel, byte[] recipient, long refund,
                                    byte[] funder, long maxFee) {
        return PlutusData.constr(0, PlutusData.bytes(u(country)), PlutusData.bytes(u(kycLevel)),
                PlutusData.bytes(recipient), PlutusData.integer(big(refund)),
                PlutusData.bytes(funder), PlutusData.integer(big(maxFee)));
    }

    private static PlutusData claim(BbsCodec.ProofParts parts, byte[] presentationHeader) {
        return PlutusData.constr(0,
                PlutusData.bytes(g1c(parts.aBar())), PlutusData.bytes(g1c(parts.bBar())), PlutusData.bytes(g1c(parts.d())),
                PlutusData.integer(parts.eHat()), PlutusData.integer(parts.r1Hat()), PlutusData.integer(parts.r3Hat()),
                PlutusData.integer(parts.mHats().get(0)), PlutusData.integer(parts.mHats().get(1)),
                PlutusData.integer(parts.mHats().get(2)), PlutusData.integer(parts.challenge()),
                PlutusData.bytes(u("USA")), PlutusData.bytes(u("verified")), PlutusData.bytes(presentationHeader));
    }

    /** The voucher's own value: 10 ADA, nothing else. */
    private static Value adaVoucher() {
        return Value.lovelace(big(VOUCHER_LOVELACE));
    }

    private PlutusData claimCtx(PlutusData datum, Value voucherValue, TxOut... outputs) {
        return claimCtx(datum, claim(pp, ph), voucherValue, List.of(), outputs);
    }

    private PlutusData claimCtx(PlutusData datum, Value voucherValue, List<TxInInfo> otherInputs, TxOut... outputs) {
        return claimCtx(datum, claim(pp, ph), voucherValue, otherInputs, outputs);
    }

    /**
     * A spend of {@link #VOUCHER} (at this script, stake part {@code 0x01…}) holding
     * {@code voucherValue} under {@code datum}, alongside {@code otherInputs}, with {@code outputs}.
     */
    private PlutusData claimCtx(PlutusData datum, PlutusData redeemer, Value voucherValue,
                                List<TxInInfo> otherInputs, TxOut... outputs) {
        var builder = spendingContext(VOUCHER, datum).redeemer(redeemer)
                .input(voucherInput(VOUCHER, KYC_SCRIPT, filled(0x01), datum, voucherValue));
        for (TxInInfo input : otherInputs) builder = builder.input(input);
        for (TxOut output : outputs) builder = builder.output(output);
        return builder.buildPlutusData();
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

    /** A deterministic tx-out ref, so the derived presentation header is stable across runs. */
    private static TxOutRef ref(int fill, long index) {
        byte[] txId = new byte[32];
        Arrays.fill(txId, (byte) fill);
        return new TxOutRef(TxId.of(txId), BigInteger.valueOf(index));
    }

    /** The off-chain twin of the validator's expected header — the service computes this for real claims. */
    private static byte[] headerFor(TxOutRef voucher, byte[] recipient) {
        return OnChainKycClaimService.claimHeader(
                voucher.txId().hash(), voucher.index().longValue(), recipient);
    }

    private static byte[] concat(byte[] x, byte[] y) {
        byte[] out = Arrays.copyOf(x, x.length + y.length);
        System.arraycopy(y, 0, out, x.length, y.length);
        return out;
    }
}
