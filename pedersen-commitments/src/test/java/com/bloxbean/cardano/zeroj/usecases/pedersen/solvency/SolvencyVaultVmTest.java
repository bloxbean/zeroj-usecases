package com.bloxbean.cardano.zeroj.usecases.pedersen.solvency;

import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Customer;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Entry;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.onchain.SolvencyVault;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.Interval;
import org.julclang.ledger.IntervalBound;
import org.julclang.ledger.IntervalBoundType;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PolicyId;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.StakingCredential;
import org.julclang.ledger.TokenName;
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
import java.security.SecureRandom;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code SolvencyVault} in the Plutus VM (ADR-0006 demo C): an honest attestation before the
 * period and an honest release after it are accepted; every mutation that would break S1–S7 is
 * rejected.
 */
class SolvencyVaultVmTest extends ContractTest {

    private static final byte[] VAULT = filled(28, (byte) 0x5f);
    private static final byte[] EXCHANGE = filled(28, (byte) 0xe5);
    private static final byte[] TOKEN = SolvencyAttestation.ATTEST_TOKEN;
    private static final Address VAULT_ADDRESS = new Address(
            new Credential.ScriptCredential(ScriptHash.of(VAULT)), Optional.empty());
    private static final Address EXCHANGE_ADDRESS = new Address(
            new Credential.PubKeyCredential(PubKeyHash.of(EXCHANGE)), Optional.empty());
    private static final long RESERVES = 2_000_000_000L;
    private static final long PERIOD_START = 1_800_000_000_000L;
    private static final long PERIOD_END = PERIOD_START + 86_400_000L;
    private static final Address STAKED_VAULT_ADDRESS = new Address(VAULT_ADDRESS.credential(),
            Optional.of(new StakingCredential.StakingHash(new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x5a))))));

    private static Program program;
    private static List<Entry> entries;
    private static SnarkjsToCardano.ProofCompressed proof;

    @BeforeAll
    static void setup() {
        var solvency = new SolvencyAttestation(SolvencyCircuitTest.N);
        List<Customer> book = SolvencyCircuitTest.book();
        entries = SolvencyAttestation.entries(book);
        proof = ProverToCardano.compressProof(solvency.prove(RESERVES, book));
        var vk = solvency.circuit().compressedVk();
        program = new SolvencyVaultVmTest().compileValidator(SolvencyVault.class, Path.of("src/main/java"))
                .program().applyParams(
                        PlutusData.bytes(EXCHANGE), PlutusData.bytes(TOKEN),
                        PlutusData.integer(BigInteger.valueOf(SolvencyCircuitTest.N)),
                        PlutusData.integer(BigInteger.valueOf(PERIOD_START)),
                        PlutusData.integer(BigInteger.valueOf(PERIOD_END)),
                        PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                        PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()), icData(vk.ic()));
    }

    // ------------------------------------------------------------------
    //  Attest
    // ------------------------------------------------------------------

    enum Attest {
        NONE, NO_SIGNER, MALFORMED_PROOF, LESS_LOCKED, EXTRA_TOKEN_IN_VAULT, VAULT_ELSEWHERE, STAKED_VAULT,
        MISSING_ENTRY, EXTRA_ENTRY, SWAPPED_ENTRIES, NON_CANONICAL_U, SHORT_ID_HASH, TWO_TOKENS, EXTRA_MINT_ENTRY,
        VAULT_SPENT_IN_SAME_TX, AFTER_PERIOD_START, NO_UPPER_BOUND,
        SHORT_DELIVERY, ENTRY_WITHOUT_DELIVERY, NO_AUDITOR_DELIVERY, SHORT_AUDITOR_DELIVERY, EXTRA_ATTESTATION_FIELD
    }

    @Test
    @DisplayName("Attest: an honest attestation locks the reserve; every mutation is rejected")
    void attest() {
        var ok = evaluate(program, attestContext(Attest.NONE));
        assertSuccess(ok);
        System.out.println("[SolvencyVault attest] budget: " + ok.budgetConsumed());
        for (Attest m : Attest.values()) {
            if (m != Attest.NONE && evaluate(program, attestContext(m)) instanceof EvalResult.Success) {
                fail("attest accepted " + m);
            }
        }
    }

    private PlutusData attestContext(Attest m) {
        Value mint = token(m == Attest.TWO_TOKENS ? 2 : 1);
        if (m == Attest.EXTRA_MINT_ENTRY) mint = mint.merge(Value.singleton(PolicyId.of(VAULT), TokenName.of(new byte[] {7}), BigInteger.ONE));
        byte[] piA = m == Attest.MALFORMED_PROOF ? flipped(proof.piA()) : proof.piA();
        IntervalBound upper = switch (m) {
            case AFTER_PERIOD_START -> new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(PERIOD_START + 1000)), false);
            case NO_UPPER_BOUND -> new IntervalBound(new IntervalBoundType.PosInf(), true);
            default -> new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(PERIOD_START)), false);
        };
        var b = ScriptContextTestBuilder.minting(PolicyId.of(VAULT)).mint(mint)
                .validRange(new Interval(new IntervalBound(new IntervalBoundType.NegInf(), true), upper))
                .redeemer(PlutusData.constr(0, PlutusData.bytes(piA), PlutusData.bytes(proof.piB()), PlutusData.bytes(proof.piC())));
        if (m != Attest.NO_SIGNER) b.signer(EXCHANGE);
        if (m == Attest.VAULT_SPENT_IN_SAME_TX) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(VAULT_ADDRESS,
                    Value.lovelace(BigInteger.valueOf(RESERVES)).merge(token(1)),
                    new OutputDatum.OutputDatumInline(attestation(entries, Attest.NONE)), Optional.empty())));
        }
        List<Entry> published = new ArrayList<>(entries);
        if (m == Attest.MISSING_ENTRY) published.remove(3);
        if (m == Attest.EXTRA_ENTRY) published.add(entries.getFirst());
        if (m == Attest.SWAPPED_ENTRIES) {
            published.set(0, entries.get(1));
            published.set(1, entries.get(0));
        }
        if (m == Attest.SHORT_ID_HASH) published.set(0, new Entry(Arrays.copyOf(entries.getFirst().idHash(), 31),
                entries.getFirst().commitment(), entries.getFirst().delivery()));
        if (m == Attest.SHORT_DELIVERY) published.set(1, new Entry(entries.get(1).idHash(), entries.get(1).commitment(),
                Arrays.copyOf(entries.get(1).delivery(), 88)));
        long locked = m == Attest.LESS_LOCKED ? RESERVES - 1 : RESERVES;
        Value vaultValue = Value.lovelace(BigInteger.valueOf(locked)).merge(token(m == Attest.TWO_TOKENS ? 2 : 1));
        if (m == Attest.EXTRA_TOKEN_IN_VAULT) vaultValue = vaultValue.merge(Value.singleton(PolicyId.of(filled(28, (byte) 3)), TokenName.of(new byte[] {1}), BigInteger.ONE));
        Address to = switch (m) {
            case VAULT_ELSEWHERE -> EXCHANGE_ADDRESS;
            case STAKED_VAULT -> STAKED_VAULT_ADDRESS;
            default -> VAULT_ADDRESS;
        };
        b.output(new TxOut(to, vaultValue,
                new OutputDatum.OutputDatumInline(attestation(published, m)), Optional.empty()));
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  Release
    // ------------------------------------------------------------------

    enum Release { NONE, BEFORE_PERIOD_END, NO_LOWER_BOUND, NO_SIGNER, NO_BURN, TWO_VAULTS }

    @Test
    @DisplayName("Release: after the period, with the exchange's signature and a burn; every mutation is rejected")
    void release() {
        assertSuccess(evaluate(program, releaseSpend(Release.NONE)));
        assertSuccess(evaluate(program, releaseBurn(Release.NONE)));
        for (Release m : Release.values()) {
            if (m != Release.NONE && evaluate(program, releaseSpend(m)) instanceof EvalResult.Success) {
                fail("release accepted " + m);
            }
        }
        if (evaluate(program, releaseBurn(Release.TWO_VAULTS)) instanceof EvalResult.Success) {
            fail("burn accepted with two vault inputs");
        }
    }

    private ScriptContextTestBuilder releaseTx(Release m, ScriptContextTestBuilder b, TxOutRef ref) {
        b.mint(m == Release.NO_BURN ? Value.zero() : token(-1));
        if (m != Release.NO_SIGNER) b.signer(EXCHANGE);
        long from = m == Release.BEFORE_PERIOD_END ? PERIOD_END - 1000 : PERIOD_END;
        IntervalBound lower = m == Release.NO_LOWER_BOUND
                ? new IntervalBound(new IntervalBoundType.NegInf(), true)
                : new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(from)), true);
        b.validRange(new Interval(lower, new IntervalBound(new IntervalBoundType.PosInf(), true)));
        b.input(new TxInInfo(ref, vaultOut()));
        if (m == Release.TWO_VAULTS) b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), vaultOut()));
        b.output(new TxOut(EXCHANGE_ADDRESS, Value.lovelace(BigInteger.valueOf(RESERVES)),
                new OutputDatum.NoOutputDatum(), Optional.empty()));
        return b;
    }

    private PlutusData releaseSpend(Release m) {
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        var b = ScriptContextTestBuilder.spending(ref, attestation(entries, Attest.NONE)).redeemer(PlutusData.constr(0));
        return releaseTx(m, b, ref).buildPlutusData();
    }

    private PlutusData releaseBurn(Release m) {
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        var b = ScriptContextTestBuilder.minting(PolicyId.of(VAULT)).redeemer(PlutusData.constr(1, PlutusData.integer(0)));
        return releaseTx(m, b, ref).buildPlutusData();
    }

    // ------------------------------------------------------------------

    private static TxOut vaultOut() {
        return new TxOut(VAULT_ADDRESS, Value.lovelace(BigInteger.valueOf(RESERVES)).merge(token(1)),
                new OutputDatum.OutputDatumInline(attestation(entries, Attest.NONE)), Optional.empty());
    }

    /** {@code Attestation([Entry(idHash, u, v, delivery)], auditorDelivery)}, or a mutation of it. */
    private static PlutusData attestation(List<Entry> es, Attest m) {
        PlutusData[] items = new PlutusData[es.size()];
        for (int i = 0; i < es.size(); i++) {
            Entry e = es.get(i);
            BigInteger u = e.commitment().affineU();
            if (m == Attest.NON_CANONICAL_U && i == 0) u = u.add(JubjubCurve.BASE_FIELD_PRIME);
            items[i] = m == Attest.ENTRY_WITHOUT_DELIVERY && i == 2
                    ? PlutusData.constr(0, PlutusData.bytes(e.idHash()), PlutusData.integer(u), PlutusData.integer(e.commitment().affineV()))
                    : PlutusData.constr(0, PlutusData.bytes(e.idHash()), PlutusData.integer(u),
                            PlutusData.integer(e.commitment().affineV()), PlutusData.bytes(e.delivery()));
        }
        return switch (m) {
            case NO_AUDITOR_DELIVERY -> PlutusData.constr(0, PlutusData.list(items));
            case SHORT_AUDITOR_DELIVERY -> PlutusData.constr(0, PlutusData.list(items), PlutusData.bytes(new byte[88]));
            case EXTRA_ATTESTATION_FIELD -> PlutusData.constr(0, PlutusData.list(items), PlutusData.bytes(AUDITOR_DELIVERY),
                    PlutusData.integer(BigInteger.ONE));
            default -> PlutusData.constr(0, PlutusData.list(items), PlutusData.bytes(AUDITOR_DELIVERY));
        };
    }

    private static final byte[] AUDITOR_DELIVERY = SolvencyAttestation.auditorDelivery(SolvencyCircuitTest.book(),
            NoteViewingKey.generate(new SecureRandom()).readerKey());

    private static Value token(long qty) {
        return Value.singleton(PolicyId.of(VAULT), TokenName.of(TOKEN), BigInteger.valueOf(qty));
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
