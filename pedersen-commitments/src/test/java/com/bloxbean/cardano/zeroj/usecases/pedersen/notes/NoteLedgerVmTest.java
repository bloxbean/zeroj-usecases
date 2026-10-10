package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.KeyedCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.NoteIssueProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.NoteRedeemProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.NoteTransferProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain.NoteLedger;
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
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code NoteLedger} in the Plutus VM (ADR-0007 N2–N4; ZeroJ ADR-0055 M3). Honest issuance (trusted
 * and proved), transfer and redemption are accepted, and their complete-transaction cost (spending
 * plus minting purpose) is printed against the per-transaction limits for ADR-0055's 80% gate.
 * Every mutation of ADR-0006 P1–P8, ADR-0055 D3a/D8 and ADR-0007 N2 is rejected, including an
 * output under the ledger's payment credential with another stake credential (M3 criterion (a)).
 */
class NoteLedgerVmTest extends ContractTest {

    static final long STEP_LIMIT = 10_000_000_000L;
    static final long MEMORY_LIMIT = 16_500_000L;
    static final SecureRandom RANDOM = new SecureRandom();
    static final byte[] POLICY = filled(28, (byte) 0x9a);
    static final byte[] REGISTRY_POLICY = filled(28, (byte) 0x3e);
    static final byte[] ISSUER = filled(28, (byte) 0x15);
    static final byte[] ALICE = filled(28, (byte) 0x0a);
    static final byte[] BOB = filled(28, (byte) 0x0b);
    static final byte[] AUDITOR = filled(28, (byte) 0xa1);
    static final byte[] PTS = "PTS".getBytes(StandardCharsets.UTF_8);
    static final byte[] REG = Registry.TOKEN;
    static final long GENERATION = 3;
    static final long PRICE = 120;
    static final Address LEDGER = new Address(new Credential.ScriptCredential(ScriptHash.of(POLICY)), Optional.empty());
    static final Address STAKED_LEDGER = new Address(LEDGER.credential(), Optional.of(new StakingCredential.StakingHash(
            new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x5a))))));
    static final Address REGISTRY = new Address(new Credential.ScriptCredential(ScriptHash.of(REGISTRY_POLICY)), Optional.empty());
    static final Address ISSUER_ADDRESS = new Address(new Credential.PubKeyCredential(PubKeyHash.of(ISSUER)), Optional.empty());
    static final Address ALICE_WALLET = new Address(new Credential.PubKeyCredential(PubKeyHash.of(ALICE)), Optional.empty());

    static NoteProofs proofs;
    static Program points;
    static Program payroll;
    static KeyPossession possession;
    static RegistryEntry entry;
    static RegistryEntry otherEntry;
    static AdmittedAuditor auditor;
    static AdmittedAuditor otherAuditor;
    static NoteViewingKey aliceView = NoteViewingKey.generate(RANDOM);
    static NoteViewingKey bobView = NoteViewingKey.generate(RANDOM);

    static NoteProofs.Spent in;
    static AuditedNote out1;
    static AuditedNote out2;
    static AuditedNote change;
    static SnarkjsToCardano.ProofCompressed transferProof;
    static SnarkjsToCardano.ProofCompressed redeemProof;

    @BeforeAll
    static void setup() {
        proofs = NoteProofs.withIssuance();
        possession = new KeyPossession();
        entry = AuditorKeys.generate(RANDOM).entry(REGISTRY_POLICY, AUDITOR, GENERATION, possession);
        otherEntry = AuditorKeys.generate(RANDOM).entry(REGISTRY_POLICY, AUDITOR, GENERATION, possession);
        auditor = AdmittedAuditor.admit(REGISTRY_POLICY, entry, possession);
        otherAuditor = AdmittedAuditor.admit(REGISTRY_POLICY, otherEntry, possession);
        var compiled = new NoteLedgerVmTest().compileValidator(NoteLedger.class, Path.of("src/main/java")).program();
        points = compiled.applyParams(params(false));
        payroll = compiled.applyParams(params(true));

        long balance = 0x1_0000_1000L; // above 2^32: both limbs non-zero
        in = spent(balance);
        out1 = note(BOB, 700, bobView);
        out2 = note(ALICE, balance - 700, aliceView);
        change = note(ALICE, balance - PRICE, aliceView);
        transferProof = compress(proofs.proveTransfer(in, out1, out2, auditor));
        redeemProof = compress(proofs.proveRedeem(in, change, PRICE, auditor));
    }

    static PlutusData[] params(boolean proved) {
        return new PlutusData[]{PlutusData.bytes(ISSUER), PlutusData.bytes(PTS),
                PlutusData.integer(BigInteger.valueOf(proved ? 1 : 0)),
                PlutusData.bytes(REGISTRY_POLICY), PlutusData.bytes(REG),
                PlutusData.bytes(VerificationKeys.hash(proofs.transfer().compressedVk())),
                PlutusData.bytes(VerificationKeys.hash(proofs.redeem().compressedVk())),
                PlutusData.bytes(proved ? VerificationKeys.hash(proofs.issue(1).compressedVk()) : new byte[32]),
                PlutusData.bytes(proved ? VerificationKeys.hash(proofs.issue(2).compressedVk()) : new byte[32])};
    }

    static NoteProofs.Spent spent(long amount) {
        NoteOpening o = NoteOpening.random(BigInteger.valueOf(amount), RANDOM);
        JubjubPoint c = o.commitment().normalized();
        return new NoteProofs.Spent(o, c.affineU(), c.affineV());
    }

    static AuditedNote note(byte[] owner, long amount, NoteViewingKey view) {
        return AuditedNote.create(owner, amount, view.readerKey(), auditor, RANDOM);
    }

    static SnarkjsToCardano.ProofCompressed compress(Groth16ProofBLS381 proof) {
        return ProverToCardano.compressProof(proof);
    }

    // ------------------------------------------------------------------ encodings

    /** {@code Note(owner, u, v, generation, audit, deliveries)} with explicit audit data and deliveries. */
    static PlutusData noteDatum(byte[] owner, BigInteger u, BigInteger v, long generation, List<BigInteger> audit,
                                List<byte[]> deliveries) {
        PlutusData[] a = audit.stream().map(PlutusData::integer).toArray(PlutusData[]::new);
        PlutusData[] d = deliveries.stream().map(PlutusData::bytes).toArray(PlutusData[]::new);
        return PlutusData.constr(0, PlutusData.bytes(owner), PlutusData.integer(u), PlutusData.integer(v),
                PlutusData.integer(BigInteger.valueOf(generation)), PlutusData.list(a), PlutusData.list(d));
    }

    static PlutusData noteDatum(AuditedNote n) {
        return noteDatum(n.owner(), n.u(), n.v(), GENERATION, n.audit(), n.deliveries());
    }

    static TxOut noteOut(Address at, PlutusData datum, int tokens) {
        return new TxOut(at, ada(4).merge(token(PTS, tokens)), new OutputDatum.OutputDatumInline(datum), Optional.empty());
    }

    static TxInInfo registryInput(RegistryEntry e, long quantity, PlutusData datum) {
        Value value = ada(8).merge(Value.singleton(PolicyId.of(REGISTRY_POLICY), TokenName.of(REG), BigInteger.valueOf(quantity)));
        return new TxInInfo(TestDataBuilder.randomTxOutRef_typed(),
                new TxOut(REGISTRY, value, new OutputDatum.OutputDatumInline(datum), Optional.empty()));
    }

    static PlutusData entryDatum(RegistryEntry e) {
        return AuditorRegistryVmTest.datum(e);
    }

    static PlutusData vk(SnarkjsToCardano.VkCompressed vk) {
        return VerificationKeys.julcData(vk);
    }

    // ------------------------------------------------------------------ Transfer

    enum TransferMutation {
        NONE, NO_SIGNER, TAMPERED_PROOF, WRONG_VK, SWAPPED_OUTPUTS, EXTRA_SCRIPT_INPUT, EXTRA_STAKED_SCRIPT_INPUT,
        THREE_OUTPUTS, MINT_TWO, OUTPUT_TWO_TOKENS, OUTPUT_EXTRA_ASSET, NON_CANONICAL_OUTPUT, INPUT_WITHOUT_TOKEN,
        STAKE_VARIANT_EXTRA_OUTPUT, STAKE_VARIANT_NOTE,
        AUDIT_ABSENT, AUDIT_WRONG_OUT1, AUDIT_WRONG_OUT2, AUDIT_SWAPPED_BETWEEN_OUTPUTS, AUDIT_LIMBS_SWAPPED,
        AUDIT_NON_CANONICAL, AUDIT_SEVEN_ENTRIES, DELIVERY_SHORT, DELIVERY_MISSING, DELIVERY_EXTRA, STALE_GENERATION,
        REGISTRY_MISSING, REGISTRY_OTHER_KEY, REGISTRY_SECOND_ENTRY, REGISTRY_QUANTITY_TWO, REGISTRY_EXTRA_FIELD,
        REGISTRY_WRONG_TOKEN, NO_NOTE_SPENT
    }

    @Test
    @DisplayName("Transfer: accepted by both purposes, complete cost measured; every mutation is rejected")
    void transfer() {
        var spend = evaluate(points, transferSpend(TransferMutation.NONE, out1, out2, transferProof));
        assertInstanceOf(EvalResult.Success.class, spend);
        var mint = evaluate(points, transferMint(TransferMutation.NONE));
        assertInstanceOf(EvalResult.Success.class, mint);
        report("transfer (spend + Split mint)", spend, mint, proofs.transfer());
        for (TransferMutation m : TransferMutation.values()) {
            if (m != TransferMutation.NONE
                    && evaluate(points, transferSpend(m, out1, out2, transferProof)) instanceof EvalResult.Success) {
                fail("Transfer spend accepted " + m);
            }
        }
        for (TransferMutation m : List.of(TransferMutation.MINT_TWO, TransferMutation.EXTRA_SCRIPT_INPUT,
                TransferMutation.EXTRA_STAKED_SCRIPT_INPUT, TransferMutation.NO_NOTE_SPENT)) {
            if (evaluate(points, transferMint(m)) instanceof EvalResult.Success) fail("Split mint accepted " + m);
        }
    }

    @Test
    @DisplayName("Transfer: one limb randomness reused (within a note, across notes) proves, but the ledger refuses")
    void reusedHandles() {
        // Reuse within out1: limb 1 encrypted with limb 0's k (test fixture; the prover cannot be stopped).
        BigInteger k = out1.limbs().get(0).randomness();
        List<BigInteger> c = fixtureLimb(out1.limbs().get(1).message(), k, auditor);
        var inputs = NoteProofs.transferInputs(in, out1, out2, auditor)
                .o1K1(k).o1a1u(c.get(0)).o1a1v(c.get(1)).o1b1u(c.get(2)).o1b1v(c.get(3));
        var proof = compress(proofs.transfer().prove(inputs.toWitnessMap()));
        List<BigInteger> a1 = new ArrayList<>(out1.audit().subList(0, 4));
        a1.addAll(c);
        PlutusData o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION, a1, out1.deliveries());
        if (evaluate(points, transferSpend(TransferMutation.NONE, o1, noteDatum(out2), proof)) instanceof EvalResult.Success) {
            fail("one k for both limbs of a note was accepted");
        }
        // Reuse across notes: out2's limb 0 with out1's limb-0 k.
        List<BigInteger> c2 = fixtureLimb(out2.limbs().get(0).message(), k, auditor);
        var inputs2 = NoteProofs.transferInputs(in, out1, out2, auditor)
                .o2K0(k).o2a0u(c2.get(0)).o2a0v(c2.get(1)).o2b0u(c2.get(2)).o2b0v(c2.get(3));
        var proof2 = compress(proofs.transfer().prove(inputs2.toWitnessMap()));
        List<BigInteger> a2 = new ArrayList<>(c2);
        a2.addAll(out2.audit().subList(4, 8));
        PlutusData o2 = noteDatum(out2.owner(), out2.u(), out2.v(), GENERATION, a2, out2.deliveries());
        if (evaluate(points, transferSpend(TransferMutation.NONE, noteDatum(out1), o2, proof2)) instanceof EvalResult.Success) {
            fail("one k across two notes was accepted");
        }
    }

    private PlutusData transferSpend(TransferMutation m, AuditedNote a, AuditedNote b, SnarkjsToCardano.ProofCompressed p) {
        return transferSpend(m, noteDatum(a), noteDatum(b), p);
    }

    private PlutusData transferSpend(TransferMutation m, PlutusData a, PlutusData b, SnarkjsToCardano.ProofCompressed p) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x44)), BigInteger.ZERO);
        byte[] piA = m == TransferMutation.TAMPERED_PROOF ? flipped(p.piA()) : p.piA();
        PlutusData key = m == TransferMutation.WRONG_VK ? vk(proofs.redeem().compressedVk()) : vk(proofs.transfer().compressedVk());
        var builder = ScriptContextTestBuilder.spending(ownRef, inDatum()).redeemer(PlutusData.constr(0,
                PlutusData.bytes(piA), PlutusData.bytes(p.piB()), PlutusData.bytes(p.piC()), key));
        return transferTx(m, builder, ownRef, a, b).buildPlutusData();
    }

    private PlutusData transferMint(TransferMutation m) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x44)), BigInteger.ZERO);
        var builder = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).redeemer(PlutusData.constr(1, PlutusData.integer(0)));
        return transferTx(m, builder, ownRef, noteDatum(out1), noteDatum(out2)).buildPlutusData();
    }

    private ScriptContextTestBuilder transferTx(TransferMutation m, ScriptContextTestBuilder b, TxOutRef ownRef,
                                                PlutusData first, PlutusData second) {
        b.mint(token(PTS, m == TransferMutation.MINT_TWO ? 2 : 1));
        if (m != TransferMutation.NO_SIGNER) b.signer(ALICE);
        if (m == TransferMutation.NO_NOTE_SPENT) {
            // "Free tokens": a Split mint with no note spent, the new notes paid to the exact address.
            b.input(new TxInInfo(ownRef, new TxOut(ALICE_WALLET, ada(10), new OutputDatum.NoOutputDatum(), Optional.empty())));
        } else {
            b.input(m == TransferMutation.INPUT_WITHOUT_TOKEN
                    ? new TxInInfo(ownRef, new TxOut(LEDGER, ada(4), new OutputDatum.OutputDatumInline(inDatum()), Optional.empty()))
                    : new TxInInfo(ownRef, noteOut(LEDGER, inDatum(), 1)));
        }
        if (m == TransferMutation.EXTRA_SCRIPT_INPUT) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), noteOut(LEDGER, noteDatum(out1), 1)));
        }
        if (m == TransferMutation.EXTRA_STAKED_SCRIPT_INPUT) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), noteOut(STAKED_LEDGER, noteDatum(out1), 1)));
        }
        PlutusData o1 = first;
        PlutusData o2 = second;
        List<BigInteger> a1 = new ArrayList<>(out1.audit());
        List<BigInteger> a2 = new ArrayList<>(out2.audit());
        List<byte[]> d1 = new ArrayList<>(out1.deliveries());
        switch (m) {
            case SWAPPED_OUTPUTS -> { o1 = second; o2 = first; }
            case AUDIT_ABSENT -> o1 = PlutusData.constr(0, PlutusData.bytes(out1.owner()), PlutusData.integer(out1.u()),
                    PlutusData.integer(out1.v()), PlutusData.integer(BigInteger.valueOf(GENERATION)),
                    PlutusData.list(out1.deliveries().stream().map(PlutusData::bytes).toArray(PlutusData[]::new)));
            case AUDIT_WRONG_OUT1 -> { a1.set(5, a1.get(5).add(BigInteger.ONE)); o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION, a1, d1); }
            case AUDIT_WRONG_OUT2 -> { a2.set(0, a2.get(0).add(BigInteger.ONE)); o2 = noteDatum(out2.owner(), out2.u(), out2.v(), GENERATION, a2, out2.deliveries()); }
            case AUDIT_SWAPPED_BETWEEN_OUTPUTS -> {
                o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION, a2, d1);
                o2 = noteDatum(out2.owner(), out2.u(), out2.v(), GENERATION, a1, out2.deliveries());
            }
            case AUDIT_LIMBS_SWAPPED -> {
                List<BigInteger> s = new ArrayList<>(a1.subList(4, 8));
                s.addAll(a1.subList(0, 4));
                o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION, s, d1);
            }
            case AUDIT_NON_CANONICAL -> { a1.set(2, a1.get(2).add(JubjubCurve.BASE_FIELD_PRIME)); o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION, a1, d1); }
            case AUDIT_SEVEN_ENTRIES -> o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION, a1.subList(0, 7), d1);
            case DELIVERY_SHORT -> { d1.set(1, Arrays.copyOf(d1.get(1), 88)); o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION, a1, d1); }
            case DELIVERY_MISSING -> { d1.remove(1); o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION, a1, d1); }
            case DELIVERY_EXTRA -> { d1.add(d1.get(0)); o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION, a1, d1); }
            case STALE_GENERATION -> o1 = noteDatum(out1.owner(), out1.u(), out1.v(), GENERATION - 1, a1, d1);
            case NON_CANONICAL_OUTPUT -> o2 = noteDatum(out2.owner(), out2.u().add(JubjubCurve.BASE_FIELD_PRIME), out2.v(),
                    GENERATION, a2, out2.deliveries());
            default -> { }
        }
        Value v1 = ada(4).merge(token(PTS, m == TransferMutation.OUTPUT_TWO_TOKENS ? 2 : 1));
        if (m == TransferMutation.OUTPUT_EXTRA_ASSET) v1 = v1.merge(Value.singleton(PolicyId.of(filled(28, (byte) 0x77)), TokenName.of("Z".getBytes()), BigInteger.ONE));
        b.output(new TxOut(LEDGER, v1, new OutputDatum.OutputDatumInline(o1), Optional.empty()));
        b.output(noteOut(m == TransferMutation.STAKE_VARIANT_NOTE ? STAKED_LEDGER : LEDGER, o2, 1));
        if (m == TransferMutation.THREE_OUTPUTS) b.output(noteOut(LEDGER, noteDatum(note(ALICE, 0, aliceView)), 1));
        if (m == TransferMutation.STAKE_VARIANT_EXTRA_OUTPUT) b.output(noteOut(STAKED_LEDGER, noteDatum(out1), 0));
        registry(b, m.name());
        realistic(b);
        return b;
    }

    /**
     * What a real transaction also carries, for honest costs: the ledger's own reference-script
     * output (at the ledger address, no token), the fee payer's input and its change output.
     */
    private static void realistic(ScriptContextTestBuilder b) {
        b.referenceInput(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LEDGER, ada(40),
                new OutputDatum.OutputDatumInline(PlutusData.integer(BigInteger.ZERO)), Optional.of(ScriptHash.of(POLICY)))));
        b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(ALICE_WALLET, ada(50),
                new OutputDatum.NoOutputDatum(), Optional.empty())));
        b.output(new TxOut(ALICE_WALLET, ada(45), new OutputDatum.NoOutputDatum(), Optional.empty()));
    }

    /** The registry reference input, or a mutation of it named by {@code m}. */
    private static void registry(ScriptContextTestBuilder b, String m) {
        switch (m) {
            case "REGISTRY_MISSING" -> { }
            case "REGISTRY_OTHER_KEY" -> b.referenceInput(registryInput(otherEntry, 1, entryDatum(otherEntry)));
            case "REGISTRY_SECOND_ENTRY" -> {
                b.referenceInput(registryInput(entry, 1, entryDatum(entry)));
                b.referenceInput(registryInput(otherEntry, 1, entryDatum(otherEntry)));
            }
            case "REGISTRY_QUANTITY_TWO" -> b.referenceInput(registryInput(entry, 2, entryDatum(entry)));
            case "REGISTRY_EXTRA_FIELD" -> {
                List<PlutusData> f = AuditorRegistryVmTest.fields(entry);
                f.add(PlutusData.integer(BigInteger.ONE));
                b.referenceInput(registryInput(entry, 1, AuditorRegistryVmTest.constr(f)));
            }
            case "REGISTRY_WRONG_TOKEN" -> b.referenceInput(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(),
                    new TxOut(REGISTRY, ada(8).merge(Value.singleton(PolicyId.of(REGISTRY_POLICY), TokenName.of("REX".getBytes()), BigInteger.ONE)),
                            new OutputDatum.OutputDatumInline(entryDatum(entry)), Optional.empty())));
            default -> b.referenceInput(registryInput(entry, 1, entryDatum(entry)));
        }
    }

    // ------------------------------------------------------------------ Redeem

    enum RedeemMutation {
        NONE, NO_SIGNER, PRICE_IN_REDEEMER, RECEIPT_PRICE, RECEIPT_TO_OTHER, RECEIPT_NAME_NOT_DERIVED, NO_RECEIPT_MINTED,
        ALSO_MINT_PTS, PRICE_ZERO, PRICE_TOO_LARGE, TWO_CHANGE_NOTES, STAKE_VARIANT_CHANGE, AUDIT_WRONG, DELIVERY_MISSING,
        STALE_GENERATION, REGISTRY_MISSING, REGISTRY_OTHER_KEY, WRONG_VK, NO_NOTE_SPENT, TWO_NOTES_SPENT,
        RECEIPT_NAME_NOT_32_BYTES
    }

    @Test
    @DisplayName("Redeem: accepted by both purposes, complete cost measured; every mutation is rejected")
    void redeem() {
        var spend = evaluate(points, redeemSpend(RedeemMutation.NONE));
        assertInstanceOf(EvalResult.Success.class, spend);
        var mint = evaluate(points, redeemMint());
        assertInstanceOf(EvalResult.Success.class, mint);
        report("redeem (spend + Receipt mint)", spend, mint, proofs.redeem());
        for (RedeemMutation m : RedeemMutation.values()) {
            if (m != RedeemMutation.NONE && evaluate(points, redeemSpend(m)) instanceof EvalResult.Success) {
                fail("Redeem spend accepted " + m);
            }
        }
        for (RedeemMutation m : List.of(RedeemMutation.ALSO_MINT_PTS, RedeemMutation.NO_NOTE_SPENT,
                RedeemMutation.TWO_NOTES_SPENT, RedeemMutation.RECEIPT_NAME_NOT_32_BYTES)) {
            if (evaluate(points, redeemMint(m)) instanceof EvalResult.Success) fail("Receipt mint accepted " + m);
        }
    }

    private PlutusData redeemSpend(RedeemMutation m) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x45)), BigInteger.ONE);
        long price = switch (m) {
            case PRICE_IN_REDEEMER -> PRICE - 1;
            case PRICE_ZERO -> 0;
            case PRICE_TOO_LARGE -> 1L << 32;
            default -> PRICE;
        };
        PlutusData key = m == RedeemMutation.WRONG_VK ? vk(proofs.transfer().compressedVk()) : vk(proofs.redeem().compressedVk());
        var b = ScriptContextTestBuilder.spending(ownRef, inDatum()).redeemer(PlutusData.constr(1,
                PlutusData.integer(BigInteger.valueOf(price)), PlutusData.bytes(redeemProof.piA()),
                PlutusData.bytes(redeemProof.piB()), PlutusData.bytes(redeemProof.piC()), key));
        return redeemTx(m, b, ownRef).buildPlutusData();
    }

    private PlutusData redeemMint() {
        return redeemMint(RedeemMutation.NONE);
    }

    private PlutusData redeemMint(RedeemMutation m) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x45)), BigInteger.ONE);
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).redeemer(PlutusData.constr(2, PlutusData.integer(0)));
        return redeemTx(m, b, ownRef).buildPlutusData();
    }

    private ScriptContextTestBuilder redeemTx(RedeemMutation m, ScriptContextTestBuilder b, TxOutRef ownRef) {
        byte[] receipt = switch (m) {
            case RECEIPT_NAME_NOT_DERIVED -> filled(32, (byte) 0x77);
            case RECEIPT_NAME_NOT_32_BYTES -> filled(31, (byte) 0x77);
            default -> receiptName(ownRef);
        };
        Value mint = m == RedeemMutation.NO_RECEIPT_MINTED ? Value.zero() : token(receipt, 1);
        if (m == RedeemMutation.ALSO_MINT_PTS) mint = mint.merge(token(PTS, 1));
        b.mint(mint);
        if (m != RedeemMutation.NO_SIGNER) b.signer(ALICE);
        b.input(m == RedeemMutation.NO_NOTE_SPENT
                ? new TxInInfo(ownRef, new TxOut(ALICE_WALLET, ada(10), new OutputDatum.NoOutputDatum(), Optional.empty()))
                : new TxInInfo(ownRef, noteOut(LEDGER, inDatum(), 1)));
        if (m == RedeemMutation.TWO_NOTES_SPENT) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), noteOut(LEDGER, noteDatum(out1), 1)));
        }
        List<BigInteger> a = new ArrayList<>(change.audit());
        List<byte[]> d = new ArrayList<>(change.deliveries());
        long generation = GENERATION;
        switch (m) {
            case AUDIT_WRONG -> a.set(7, a.get(7).add(BigInteger.ONE));
            case DELIVERY_MISSING -> d.remove(1);
            case STALE_GENERATION -> generation = GENERATION - 1;
            default -> { }
        }
        PlutusData c = noteDatum(change.owner(), change.u(), change.v(), generation, a, d);
        b.output(noteOut(m == RedeemMutation.STAKE_VARIANT_CHANGE ? STAKED_LEDGER : LEDGER, c, 1));
        if (m == RedeemMutation.TWO_CHANGE_NOTES) b.output(noteOut(LEDGER, noteDatum(note(ALICE, 0, aliceView)), 1));
        long receiptPrice = switch (m) {
            case RECEIPT_PRICE -> PRICE + 1;
            case PRICE_IN_REDEEMER -> PRICE - 1;
            default -> PRICE;
        };
        Address to = m == RedeemMutation.RECEIPT_TO_OTHER ? ALICE_WALLET : ISSUER_ADDRESS;
        b.output(new TxOut(to, ada(2).merge(token(receipt, 1)), new OutputDatum.OutputDatumInline(PlutusData.constr(0,
                PlutusData.bytes(ALICE), PlutusData.integer(BigInteger.valueOf(receiptPrice)))), Optional.empty()));
        registry(b, m.name());
        realistic(b);
        return b;
    }

    // ------------------------------------------------------------------ Issue (trusted, points)

    enum IssueMutation {
        NONE, NO_SIGNER, NOTE_SPENT, COUNT_MISMATCH, STAKE_VARIANT_NOTE, STAKE_VARIANT_EXTRA_OUTPUT, DELIVERY_SHORT,
        STALE_GENERATION, REGISTRY_MISSING, PROVED_ISSUE_IN_TRUSTED_MODE
    }

    @Test
    @DisplayName("Trusted issue (points): the issuer mints notes of the current generation; every mutation is rejected")
    void trustedIssue() {
        var honest = evaluate(points, issueContext(IssueMutation.NONE));
        assertInstanceOf(EvalResult.Success.class, honest);
        System.out.println("[NoteLedger issue (trusted, 2 notes)] budget: " + honest.budgetConsumed());
        for (IssueMutation m : IssueMutation.values()) {
            if (m != IssueMutation.NONE && evaluate(points, issueContext(m)) instanceof EvalResult.Success) {
                fail("Issue accepted " + m);
            }
        }
    }

    private PlutusData issueContext(IssueMutation m) {
        PlutusData redeemer = m == IssueMutation.PROVED_ISSUE_IN_TRUSTED_MODE
                ? PlutusData.constr(3, PlutusData.bytes(transferProof.piA()), PlutusData.bytes(transferProof.piB()),
                        PlutusData.bytes(transferProof.piC()), vk(proofs.transfer().compressedVk()))
                : PlutusData.constr(0, PlutusData.integer(0));
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).mint(token(PTS, 2)).redeemer(redeemer);
        if (m != IssueMutation.NO_SIGNER) b.signer(ISSUER);
        if (m == IssueMutation.NOTE_SPENT) b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), noteOut(LEDGER, inDatum(), 1)));
        List<byte[]> d = new ArrayList<>(out1.deliveries());
        if (m == IssueMutation.DELIVERY_SHORT) d.set(0, Arrays.copyOf(d.get(0), 88));
        long generation = m == IssueMutation.STALE_GENERATION ? GENERATION - 1 : GENERATION;
        b.output(noteOut(m == IssueMutation.STAKE_VARIANT_NOTE ? STAKED_LEDGER : LEDGER,
                noteDatum(out1.owner(), out1.u(), out1.v(), generation, out1.audit(), d), 1));
        if (m != IssueMutation.COUNT_MISMATCH) b.output(noteOut(LEDGER, noteDatum(out2), 1));
        if (m == IssueMutation.STAKE_VARIANT_EXTRA_OUTPUT) b.output(noteOut(STAKED_LEDGER, noteDatum(out1), 0));
        registry(b, m.name());
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------ ProvedIssue (payroll)

    enum ProvedIssueMutation {
        NONE, UNDER_REPORTED_IN_DATUM, PROOF_FOR_OTHER_KEY, REUSED_HANDLE_ACROSS_NOTES, COUNT_MISMATCH,
        LEDGER_INPUT_SPENT, NO_SIGNER, WRONG_VK, TRUSTED_ISSUE_IN_PROVED_MODE, STAKE_VARIANT_EXTRA_OUTPUT, REGISTRY_MISSING
    }

    @Test
    @DisplayName("Proved issue (payroll): n = 1 and n = 2 accepted with cost measured; an issuer that under-reports or mutates is refused")
    void provedIssue() {
        for (int n = 1; n <= 2; n++) {
            List<AuditedNote> notes = n == 1 ? List.of(out1) : List.of(out1, out2);
            var proof = compress(proofs.proveIssue(notes, auditor));
            var honest = evaluate(payroll, provedIssueContext(ProvedIssueMutation.NONE, notes, proof));
            assertInstanceOf(EvalResult.Success.class, honest);
            report("proved issue n=" + n + " (mint only)", honest, null, proofs.issue(n));
        }
        List<AuditedNote> notes = List.of(out1, out2);
        var proof = compress(proofs.proveIssue(notes, auditor));
        for (ProvedIssueMutation m : ProvedIssueMutation.values()) {
            if (m == ProvedIssueMutation.NONE || m == ProvedIssueMutation.PROOF_FOR_OTHER_KEY
                    || m == ProvedIssueMutation.REUSED_HANDLE_ACROSS_NOTES) {
                continue;
            }
            if (evaluate(payroll, provedIssueContext(m, notes, proof)) instanceof EvalResult.Success) {
                fail("ProvedIssue accepted " + m);
            }
        }
        // Limbs to another key, proved honestly against that key: the ledger feeds the registry key.
        AuditedNote foreign1 = AuditedNote.create(ALICE, 5_000, aliceView.readerKey(), otherAuditor, RANDOM);
        var foreignProof = compress(proofs.proveIssue(List.of(foreign1), otherAuditor));
        if (evaluate(payroll, provedIssueContext(ProvedIssueMutation.PROOF_FOR_OTHER_KEY, List.of(foreign1), foreignProof))
                instanceof EvalResult.Success) {
            fail("ProvedIssue accepted limbs to a key that is not the registry's");
        }
        // One k for limb 0 of both notes: provable, refused by the distinct-handle rule.
        BigInteger k = out1.limbs().get(0).randomness();
        List<BigInteger> c = fixtureLimb(out2.limbs().get(0).message(), k, auditor);
        var inputs = NoteProofs.issueInputs(notes, auditor);
        List<BigInteger> audit = new ArrayList<>(out1.audit());
        List<BigInteger> a2 = new ArrayList<>(c);
        a2.addAll(out2.audit().subList(4, 8));
        audit.addAll(a2);
        List<BigInteger> ks = new ArrayList<>(List.of(k, out1.limbs().get(1).randomness(), k, out2.limbs().get(1).randomness()));
        inputs.audit(audit).randomness(ks);
        var reusedProof = compress(proofs.issue(2).prove(inputs.toWitnessMap()));
        var b = provedIssueBuilder(List.of(noteDatum(out1), noteDatum(out2.owner(), out2.u(), out2.v(), GENERATION, a2, out2.deliveries())),
                reusedProof, proofs.issue(2).compressedVk());
        if (evaluate(payroll, b.buildPlutusData()) instanceof EvalResult.Success) fail("ProvedIssue accepted a reused handle");
    }

    private PlutusData provedIssueContext(ProvedIssueMutation m, List<AuditedNote> notes, SnarkjsToCardano.ProofCompressed proof) {
        List<PlutusData> datums = new ArrayList<>();
        for (AuditedNote n : notes) datums.add(noteDatum(n));
        if (m == ProvedIssueMutation.UNDER_REPORTED_IN_DATUM) {
            AuditedNote under = notes.getFirst().withLimbs(AuditedNote.limbsOf(BigInteger.valueOf(1), auditor, RANDOM));
            datums.set(0, noteDatum(under));
        }
        var vkUsed = m == ProvedIssueMutation.WRONG_VK ? proofs.issue(notes.size() == 1 ? 2 : 1).compressedVk()
                : proofs.issue(notes.size()).compressedVk();
        if (m == ProvedIssueMutation.TRUSTED_ISSUE_IN_PROVED_MODE) {
            var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).mint(token(PTS, datums.size()))
                    .redeemer(PlutusData.constr(0, PlutusData.integer(0))).signer(ISSUER);
            for (PlutusData d : datums) b.output(noteOut(LEDGER, d, 1));
            registry(b, "NONE");
            return b.buildPlutusData();
        }
        var b = provedIssueBuilder(datums, proof, vkUsed);
        if (m == ProvedIssueMutation.COUNT_MISMATCH) b.mint(token(PTS, 1));
        if (m == ProvedIssueMutation.LEDGER_INPUT_SPENT) b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), noteOut(LEDGER, inDatum(), 1)));
        if (m == ProvedIssueMutation.STAKE_VARIANT_EXTRA_OUTPUT) b.output(noteOut(STAKED_LEDGER, noteDatum(out1), 0));
        if (m != ProvedIssueMutation.NO_SIGNER) b.signer(ISSUER);
        registry(b, m.name());
        return b.buildPlutusData();
    }

    private ScriptContextTestBuilder provedIssueBuilder(List<PlutusData> datums, SnarkjsToCardano.ProofCompressed proof,
                                                        SnarkjsToCardano.VkCompressed key) {
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).mint(token(PTS, datums.size()))
                .redeemer(PlutusData.constr(3, PlutusData.bytes(proof.piA()), PlutusData.bytes(proof.piB()),
                        PlutusData.bytes(proof.piC()), vk(key)));
        for (PlutusData d : datums) b.output(noteOut(LEDGER, d, 1));
        return b;
    }

    // ------------------------------------------------------------------ rogue verification keys

    @Test
    @DisplayName("Hash-pinned keys: an honest proof under a fresh setup of the same circuit (same shape) is refused")
    void rogueVerificationKeysAreRefused() {
        // Another party's setup of exactly the same circuits: same key shape, a trapdoor it knows.
        var rogueTransfer = KeyedCircuit.compile("note-transfer-rogue", NoteTransferProofCircuit.build());
        var rogueRedeem = KeyedCircuit.compile("note-redeem-rogue",
                NoteRedeemProofCircuit.build());
        var rogueIssue = KeyedCircuit.compile("note-issue-n1-rogue", NoteIssueProofCircuit.build(1, 2, 8));
        assertTrue(rogueTransfer.compressedVk().ic().size() == proofs.transfer().compressedVk().ic().size());

        var t = NoteProofs.transferInputs(in, out1, out2, auditor);
        var tProof = rogueTransfer.prove(t.toWitnessMap());
        assertTrue(rogueTransfer.verify(tProof, NoteTransferProofCircuit.publicInputs(t)), "positive control: valid under the rogue key");
        var tp = compress(tProof);
        var spend = ScriptContextTestBuilder.spending(new TxOutRef(TxId.of(filled(32, (byte) 0x44)), BigInteger.ZERO), inDatum())
                .redeemer(PlutusData.constr(0, PlutusData.bytes(tp.piA()), PlutusData.bytes(tp.piB()), PlutusData.bytes(tp.piC()),
                        vk(rogueTransfer.compressedVk())));
        var ctx = transferTx(TransferMutation.NONE, spend, new TxOutRef(TxId.of(filled(32, (byte) 0x44)), BigInteger.ZERO),
                noteDatum(out1), noteDatum(out2)).buildPlutusData();
        assertTrue(evaluate(points, ctx) instanceof EvalResult.Failure, "a transfer proof under a rogue key is refused");

        var r = NoteProofs.redeemInputs(in, change, PRICE, auditor);
        var rp = compress(rogueRedeem.prove(r.toWitnessMap()));
        var rSpend = ScriptContextTestBuilder.spending(new TxOutRef(TxId.of(filled(32, (byte) 0x45)), BigInteger.ONE), inDatum())
                .redeemer(PlutusData.constr(1, PlutusData.integer(BigInteger.valueOf(PRICE)), PlutusData.bytes(rp.piA()),
                        PlutusData.bytes(rp.piB()), PlutusData.bytes(rp.piC()), vk(rogueRedeem.compressedVk())));
        assertTrue(evaluate(points, redeemTx(RedeemMutation.NONE, rSpend,
                new TxOutRef(TxId.of(filled(32, (byte) 0x45)), BigInteger.ONE)).buildPlutusData()) instanceof EvalResult.Failure,
                "a redeem proof under a rogue key is refused");

        var ip = compress(rogueIssue.prove(NoteProofs.issueInputs(List.of(out1), auditor).toWitnessMap()));
        var b = provedIssueBuilder(List.of(noteDatum(out1)), ip, rogueIssue.compressedVk()).signer(ISSUER);
        registry(b, "NONE");
        assertTrue(evaluate(payroll, b.buildPlutusData()) instanceof EvalResult.Failure, "an issuance proof under a rogue key is refused");
    }

    // ------------------------------------------------------------------ helpers

    private void report(String what, EvalResult spend, EvalResult mint, KeyedCircuit circuit) {
        long cpu = spend.budgetConsumed().cpuSteps() + (mint == null ? 0 : mint.budgetConsumed().cpuSteps());
        long mem = spend.budgetConsumed().memoryUnits() + (mint == null ? 0 : mint.budgetConsumed().memoryUnits());
        System.out.printf("[NoteLedger %s] constraints=%d publicInputs=%d cpu=%d (%.1f%% of steps) mem=%d (%.1f%% of memory)%n",
                what, circuit.numConstraints(), circuit.numPublicInputs(), cpu, 100.0 * cpu / STEP_LIMIT,
                mem, 100.0 * mem / MEMORY_LIMIT);
        // ZeroJ ADR-0055 Q5: D3a is adopted only within 80% of both per-transaction limits.
        assertTrue(cpu <= STEP_LIMIT * 8 / 10 && mem <= MEMORY_LIMIT * 8 / 10,
                what + " exceeds the 80% gate");
    }

    static PlutusData inDatum() {
        return noteDatum(ALICE, in.u(), in.v(), GENERATION - 1, out1.audit(), out1.deliveries());
    }

    /** <b>Test fixture only.</b> A limb ciphertext with a chosen {@code k} (variable-time {@code scalarMul}). */
    static List<BigInteger> fixtureLimb(BigInteger m, BigInteger k, AdmittedAuditor a) {
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
        JubjubPoint pk = a.context().jointKey().point();
        JubjubPoint ha = g.scalarMul(k).normalized();
        JubjubPoint hb = g.scalarMul(m).add(pk.scalarMul(k)).normalized();
        return List.of(ha.affineU(), ha.affineV(), hb.affineU(), hb.affineV());
    }

    static Value token(byte[] name, long qty) {
        return Value.singleton(PolicyId.of(POLICY), TokenName.of(name), BigInteger.valueOf(qty));
    }

    static Value ada(long ada) {
        return Value.lovelace(BigInteger.valueOf(ada * 1_000_000));
    }

    static byte[] receiptName(TxOutRef ref) {
        byte[] bytes = Arrays.copyOf(ref.txId().hash(), 34);
        int index = ref.index().intValueExact();
        bytes[32] = (byte) (index >>> 8);
        bytes[33] = (byte) index;
        return Blake2bUtil.blake2bHash256(bytes);
    }

    static byte[] flipped(byte[] bytes) {
        byte[] copy = bytes.clone();
        copy[copy.length - 1] ^= 1;
        return copy;
    }

    static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
