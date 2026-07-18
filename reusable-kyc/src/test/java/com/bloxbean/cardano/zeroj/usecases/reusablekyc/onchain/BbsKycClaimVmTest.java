package com.bloxbean.cardano.zeroj.usecases.reusablekyc.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.core.Program;
import com.bloxbean.cardano.julc.ledger.PubKeyHash;
import com.bloxbean.cardano.julc.ledger.TxId;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.ledger.TxOutRef;
import com.bloxbean.cardano.julc.ledger.Value;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.bbs.internal.BbsCodec;
import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Providers;
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

/**
 * The full reusable-KYC on-chain claim gate in the Julc VM: a voucher is spent only when the holder's
 * BBS presentation verifies <b>on-chain</b>, discloses exactly the attributes the voucher requires,
 * and the payout goes to the voucher's recipient. Exercises the accept path plus the three ways a
 * claim must fail.
 */
class BbsKycClaimVmTest extends ContractTest {

    private static final BbsCiphersuite SUITE = BbsCiphersuite.BLS12381_SHA256;
    private static final Bls12381Provider BLS = Bls12381Providers.pureJava();
    private static final long REFUND = 2_000_000L;

    private static byte[] u(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static byte[] a(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] g1c(com.bloxbean.cardano.zeroj.bls12381.ec.G1Point p) { return Bls12381Codecs.g1ToCompressed(p); }

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

    @Test
    void valid_presentation_matching_policy_and_correct_payout_succeeds() {
        var result = evaluate(program, ctx(datum("USA", "verified", recipientPkh, REFUND),
                claim(pp, ph), recipientPkh, REFUND));
        assertSuccess(result);
        System.out.println("[BbsKycClaimValidator] budget consumed: " + result.budgetConsumed());
    }

    @Test
    void underpaying_the_recipient_fails() {
        assertFailure(evaluate(program, ctx(datum("USA", "verified", recipientPkh, REFUND),
                claim(pp, ph), recipientPkh, REFUND - 1)));
    }

    @Test
    void paying_someone_else_fails() {
        byte[] other = new byte[28]; Arrays.fill(other, (byte) 0x77);
        assertFailure(evaluate(program, ctx(datum("USA", "verified", recipientPkh, REFUND),
                claim(pp, ph), other, REFUND)));
    }

    @Test
    void policy_mismatch_fails() {
        // voucher requires country=JPN, but the credential discloses USA
        assertFailure(evaluate(program, ctx(datum("JPN", "verified", recipientPkh, REFUND),
                claim(pp, ph), recipientPkh, REFUND)));
    }

    @Test
    void tampered_presentation_header_fails() {
        assertFailure(evaluate(program, ctx(datum("USA", "verified", recipientPkh, REFUND),
                claim(pp, u("different-nonce")), recipientPkh, REFUND)));
    }

    @Test
    void presentation_bound_to_another_voucher_fails() {
        // A genuine, fully-valid presentation — but made for a different voucher. Replaying it here
        // must fail: the validator derives the expected header from the voucher it is spending.
        assertFailure(evaluate(program, ctx(datum("USA", "verified", recipientPkh, REFUND),
                claim(ppOther, phOther), recipientPkh, REFUND)));
    }

    private static PlutusData datum(String country, String kycLevel, byte[] recipient, long refund) {
        return PlutusData.constr(0, PlutusData.bytes(u(country)), PlutusData.bytes(u(kycLevel)),
                PlutusData.bytes(recipient), PlutusData.integer(BigInteger.valueOf(refund)));
    }

    private static PlutusData claim(BbsCodec.ProofParts parts, byte[] presentationHeader) {
        return PlutusData.constr(0,
                PlutusData.bytes(g1c(parts.aBar())), PlutusData.bytes(g1c(parts.bBar())), PlutusData.bytes(g1c(parts.d())),
                PlutusData.integer(parts.eHat()), PlutusData.integer(parts.r1Hat()), PlutusData.integer(parts.r3Hat()),
                PlutusData.integer(parts.mHats().get(0)), PlutusData.integer(parts.mHats().get(1)),
                PlutusData.integer(parts.mHats().get(2)), PlutusData.integer(parts.challenge()),
                PlutusData.bytes(u("USA")), PlutusData.bytes(u("verified")), PlutusData.bytes(presentationHeader));
    }

    private PlutusData ctx(PlutusData datum, PlutusData redeemer, byte[] payTo, long paid) {
        TxOut payout = TestDataBuilder.txOut(
                TestDataBuilder.pubKeyAddress(PubKeyHash.of(payTo)),
                Value.lovelace(BigInteger.valueOf(paid)));
        return spendingContext(VOUCHER, datum).redeemer(redeemer).output(payout).buildPlutusData();
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
