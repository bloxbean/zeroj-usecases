package com.bloxbean.cardano.zeroj.usecases.pedersen.points;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.ConfidentialPoints.Note;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.onchain.PointsLedger;
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
import org.julclang.testkit.ScriptContextTestBuilder;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code PointsLedger} in the Plutus VM (ADR-0006 demo A): honest issue, transfer and redemption
 * are accepted; every mutation that would break P1–P8 is rejected.
 */
class PointsLedgerVmTest extends ContractTest {

    private static final byte[] POLICY = filled(28, (byte) 0x9a);
    private static final byte[] ISSUER = filled(28, (byte) 0x15);
    private static final byte[] ALICE = PointsCircuitTest.ALICE;
    private static final byte[] BOB = PointsCircuitTest.BOB;
    private static final byte[] PTS = ConfidentialPoints.NOTE_TOKEN;
    private static final Address LEDGER = new Address(
            new Credential.ScriptCredential(ScriptHash.of(POLICY)), Optional.empty());
    private static final Address ISSUER_ADDRESS = new Address(
            new Credential.PubKeyCredential(PubKeyHash.of(ISSUER)), Optional.empty());
    private static final Address ALICE_WALLET = new Address(
            new Credential.PubKeyCredential(PubKeyHash.of(ALICE)), Optional.empty());

    private static Program program;
    private static Note in;
    private static Note out1;
    private static Note out2;
    private static Note change;
    private static SnarkjsToCardano.ProofCompressed transferProof;
    private static SnarkjsToCardano.ProofCompressed redeemProof;
    private static final long PRICE = 120;

    @BeforeAll
    static void setup() {
        var points = new ConfidentialPoints();
        in = Note.of(ALICE, 1_000);
        out1 = Note.of(BOB, 700);
        out2 = Note.of(ALICE, 300);
        change = Note.of(ALICE, 880);
        transferProof = ProverToCardano.compressProof(points.proveTransfer(in, out1, out2));
        redeemProof = ProverToCardano.compressProof(points.proveRedeem(in, change, PRICE));
        var t = points.transferCircuit().compressedVk();
        var r = points.redeemCircuit().compressedVk();
        program = new PointsLedgerVmTest().compileValidator(
                PointsLedger.class, Path.of("src/main/java"))
                .program().applyParams(
                        PlutusData.bytes(ISSUER), PlutusData.bytes(PTS),
                        PlutusData.bytes(t.alpha()), PlutusData.bytes(t.beta()),
                        PlutusData.bytes(t.gamma()), PlutusData.bytes(t.delta()), icData(t.ic()),
                        PlutusData.bytes(r.alpha()), PlutusData.bytes(r.beta()),
                        PlutusData.bytes(r.gamma()), PlutusData.bytes(r.delta()), icData(r.ic()));
    }

    // ------------------------------------------------------------------
    //  Issue
    // ------------------------------------------------------------------

    enum IssueMutation { NONE, NO_SIGNER, NOTE_SPENT, COUNT_MISMATCH, TWO_TOKENS_IN_NOTE, EXTRA_MINT_ENTRY, SHORT_OWNER }

    @Test
    @DisplayName("Issue: the issuer mints one token per new note; every mutation is rejected")
    void issue() {
        assertSuccess(evaluate(program, issueContext(IssueMutation.NONE)));
        for (IssueMutation m : IssueMutation.values()) {
            if (m != IssueMutation.NONE && evaluate(program, issueContext(m)) instanceof EvalResult.Success) {
                fail("Issue accepted " + m);
            }
        }
    }

    private PlutusData issueContext(IssueMutation m) {
        Value mint = Value.singleton(PolicyId.of(POLICY), TokenName.of(PTS), BigInteger.TWO);
        if (m == IssueMutation.EXTRA_MINT_ENTRY) mint = mint.merge(token(filled(32, (byte) 1), 1));
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).mint(mint).redeemer(action(0));
        if (m != IssueMutation.NO_SIGNER) b.signer(ISSUER);
        if (m == IssueMutation.NOTE_SPENT) b.input(noteInput(in, TestDataBuilder.randomTxOutRef_typed()));
        Note first = m == IssueMutation.SHORT_OWNER
                ? new Note(Arrays.copyOf(ALICE, 27), 10, in.blinding(), in.commitment()) : in;
        b.output(noteOut(first, m == IssueMutation.TWO_TOKENS_IN_NOTE ? 2 : 1));
        if (m != IssueMutation.COUNT_MISMATCH && m != IssueMutation.TWO_TOKENS_IN_NOTE) b.output(noteOut(out1, 1));
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  Transfer (spend + Split mint)
    // ------------------------------------------------------------------

    enum TransferMutation {
        NONE, NO_SIGNER, TAMPERED_PROOF, SWAPPED_OUTPUTS, OUTPUT_COMMITMENT, EXTRA_SCRIPT_INPUT,
        EXTRA_STAKED_SCRIPT_INPUT, THREE_OUTPUTS, MINT_TWO, MINT_RECEIPT_INSTEAD, OUTPUT_TWO_TOKENS,
        NON_CANONICAL_OUTPUT, INPUT_WITHOUT_TOKEN
    }

    @Test
    @DisplayName("Transfer: an honest split is accepted by both purposes; every mutation is rejected")
    void transfer() {
        var spend = evaluate(program, transferSpend(TransferMutation.NONE));
        assertSuccess(spend);
        System.out.println("[PointsLedger transfer] budget: " + spend.budgetConsumed());
        assertSuccess(evaluate(program, transferMint(TransferMutation.NONE)));
        for (TransferMutation m : TransferMutation.values()) {
            if (m != TransferMutation.NONE && evaluate(program, transferSpend(m)) instanceof EvalResult.Success) {
                fail("Transfer spend accepted " + m);
            }
        }
        for (TransferMutation m : List.of(TransferMutation.MINT_TWO, TransferMutation.EXTRA_SCRIPT_INPUT,
                TransferMutation.EXTRA_STAKED_SCRIPT_INPUT)) {
            if (evaluate(program, transferMint(m)) instanceof EvalResult.Success) fail("Split mint accepted " + m);
        }
    }

    private ScriptContextTestBuilder transferTx(TransferMutation m, ScriptContextTestBuilder b, TxOutRef ownRef) {
        Value mint = token(PTS, m == TransferMutation.MINT_TWO ? 2 : 1);
        if (m == TransferMutation.MINT_RECEIPT_INSTEAD) mint = token(receiptName(ownRef), 1);
        b.mint(mint);
        if (m != TransferMutation.NO_SIGNER) b.signer(ALICE);
        b.input(m == TransferMutation.INPUT_WITHOUT_TOKEN
                ? new TxInInfo(ownRef, new TxOut(LEDGER, ada(), inline(noteDatum(in)), Optional.empty()))
                : noteInput(in, ownRef));
        if (m == TransferMutation.EXTRA_SCRIPT_INPUT) b.input(noteInput(Note.of(ALICE, 5), TestDataBuilder.randomTxOutRef_typed()));
        if (m == TransferMutation.EXTRA_STAKED_SCRIPT_INPUT) {
            Address staked = new Address(LEDGER.credential(), Optional.of(new StakingCredential.StakingHash(
                    new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x5a))))));
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(),
                    new TxOut(staked, ada().merge(token(PTS, 1)), inline(noteDatum(Note.of(ALICE, 5))), Optional.empty())));
        }
        Note first = m == TransferMutation.SWAPPED_OUTPUTS ? out2 : out1;
        Note second = m == TransferMutation.SWAPPED_OUTPUTS ? out1 : out2;
        if (m == TransferMutation.OUTPUT_COMMITMENT) second = Note.of(ALICE, 300);
        b.output(noteOut(first, m == TransferMutation.OUTPUT_TWO_TOKENS ? 2 : 1));
        if (m == TransferMutation.NON_CANONICAL_OUTPUT) {
            b.output(new TxOut(LEDGER, ada().merge(token(PTS, 1)), inline(PlutusData.constr(0,
                    PlutusData.bytes(second.owner()),
                    PlutusData.integer(second.commitment().affineU().add(JubjubCurve.BASE_FIELD_PRIME)),
                    PlutusData.integer(second.commitment().affineV()))), Optional.empty()));
        } else {
            b.output(noteOut(second, 1));
        }
        if (m == TransferMutation.THREE_OUTPUTS) b.output(noteOut(Note.of(ALICE, 0), 1));
        return b;
    }

    private PlutusData transferSpend(TransferMutation m) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x44)), BigInteger.ZERO);
        byte[] piA = m == TransferMutation.TAMPERED_PROOF ? flipped(transferProof.piA()) : transferProof.piA();
        var b = ScriptContextTestBuilder.spending(ownRef, noteDatum(in)).redeemer(PlutusData.constr(0,
                PlutusData.bytes(piA), PlutusData.bytes(transferProof.piB()), PlutusData.bytes(transferProof.piC())));
        return transferTx(m, b, ownRef).buildPlutusData();
    }

    private PlutusData transferMint(TransferMutation m) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x44)), BigInteger.ZERO);
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).redeemer(action(1));
        return transferTx(m, b, ownRef).buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  Redeem (spend + Receipt mint)
    // ------------------------------------------------------------------

    enum RedeemMutation {
        NONE, NO_SIGNER, PRICE_IN_REDEEMER, RECEIPT_PRICE, RECEIPT_TO_OTHER, RECEIPT_NAME_NOT_DERIVED,
        NO_RECEIPT_MINTED, ALSO_MINT_PTS, CHANGE_COMMITMENT, PRICE_ZERO, PRICE_TOO_LARGE, TWO_CHANGE_NOTES,
        RECEIPT_WITHOUT_TOKEN
    }

    @Test
    @DisplayName("Redeem: an honest redemption is accepted by both purposes; every mutation is rejected")
    void redeem() {
        var spend = evaluate(program, redeemSpend(RedeemMutation.NONE));
        assertSuccess(spend);
        System.out.println("[PointsLedger redeem] budget: " + spend.budgetConsumed());
        assertSuccess(evaluate(program, redeemMint(RedeemMutation.NONE)));
        for (RedeemMutation m : RedeemMutation.values()) {
            if (m != RedeemMutation.NONE && evaluate(program, redeemSpend(m)) instanceof EvalResult.Success) {
                fail("Redeem spend accepted " + m);
            }
        }
        if (evaluate(program, redeemMint(RedeemMutation.ALSO_MINT_PTS)) instanceof EvalResult.Success) {
            fail("Receipt mint accepted an extra entry");
        }
    }

    private ScriptContextTestBuilder redeemTx(RedeemMutation m, ScriptContextTestBuilder b, TxOutRef ownRef) {
        byte[] receipt = m == RedeemMutation.RECEIPT_NAME_NOT_DERIVED ? filled(32, (byte) 0x77) : receiptName(ownRef);
        Value mint = m == RedeemMutation.NO_RECEIPT_MINTED ? Value.zero() : token(receipt, 1);
        if (m == RedeemMutation.ALSO_MINT_PTS) mint = mint.merge(token(PTS, 1));
        b.mint(mint);
        if (m != RedeemMutation.NO_SIGNER) b.signer(ALICE);
        b.input(noteInput(in, ownRef));
        Note c = m == RedeemMutation.CHANGE_COMMITMENT ? Note.of(ALICE, 880) : change;
        b.output(noteOut(c, 1));
        if (m == RedeemMutation.TWO_CHANGE_NOTES) b.output(noteOut(Note.of(ALICE, 0), 1));
        long receiptPrice = m == RedeemMutation.RECEIPT_PRICE ? PRICE + 1 : PRICE;
        Address to = m == RedeemMutation.RECEIPT_TO_OTHER ? ALICE_WALLET : ISSUER_ADDRESS;
        Value receiptValue = m == RedeemMutation.RECEIPT_WITHOUT_TOKEN ? ada() : ada().merge(token(receipt, 1));
        b.output(new TxOut(to, receiptValue, inline(PlutusData.constr(0,
                PlutusData.bytes(ALICE), PlutusData.integer(BigInteger.valueOf(receiptPrice)))), Optional.empty()));
        return b;
    }

    private PlutusData redeemSpend(RedeemMutation m) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x45)), BigInteger.ONE);
        long price = switch (m) {
            case PRICE_IN_REDEEMER -> PRICE - 1;
            case PRICE_ZERO -> 0;
            case PRICE_TOO_LARGE -> 1L << 32;
            default -> PRICE;
        };
        var b = ScriptContextTestBuilder.spending(ownRef, noteDatum(in)).redeemer(PlutusData.constr(1,
                PlutusData.integer(BigInteger.valueOf(price)),
                PlutusData.bytes(redeemProof.piA()), PlutusData.bytes(redeemProof.piB()), PlutusData.bytes(redeemProof.piC())));
        return redeemTx(m, b, ownRef).buildPlutusData();
    }

    private PlutusData redeemMint(RedeemMutation m) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x45)), BigInteger.ONE);
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).redeemer(action(2));
        return redeemTx(m, b, ownRef).buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  Encodings
    // ------------------------------------------------------------------

    private static TxInInfo noteInput(Note n, TxOutRef ref) {
        return new TxInInfo(ref, noteOut(n, 1));
    }

    private static TxOut noteOut(Note n, int tokens) {
        return new TxOut(LEDGER, ada().merge(token(PTS, tokens)), inline(noteDatum(n)), Optional.empty());
    }

    private static PlutusData noteDatum(Note n) {
        return PlutusData.constr(0, PlutusData.bytes(n.owner()),
                PlutusData.integer(n.commitment().affineU()), PlutusData.integer(n.commitment().affineV()));
    }

    private static OutputDatum inline(PlutusData d) {
        return new OutputDatum.OutputDatumInline(d);
    }

    private static Value ada() {
        return Value.lovelace(BigInteger.valueOf(2_000_000));
    }

    private static Value token(byte[] name, long qty) {
        return Value.singleton(PolicyId.of(POLICY), TokenName.of(name), BigInteger.valueOf(qty));
    }

    private static PlutusData action(int tag) {
        return PlutusData.constr(tag, PlutusData.integer(0));
    }

    private static byte[] receiptName(TxOutRef ref) {
        int index = ref.index().intValueExact();
        byte[] bytes = Arrays.copyOf(ref.txId().hash(), 34);
        bytes[32] = (byte) (index >>> 8);
        bytes[33] = (byte) index;
        return Blake2bUtil.blake2bHash256(bytes);
    }

    private static PlutusData icData(List<byte[]> ic) {
        PlutusData[] points = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) points[i] = PlutusData.bytes(ic.get(i));
        return PlutusData.list(points);
    }

    private static byte[] flipped(byte[] bytes) {
        byte[] copy = bytes.clone();
        copy[copy.length - 1] ^= 1;
        return copy;
    }

    private static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
