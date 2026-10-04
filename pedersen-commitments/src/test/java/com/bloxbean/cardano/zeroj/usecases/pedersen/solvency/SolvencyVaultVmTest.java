package com.bloxbean.cardano.zeroj.usecases.pedersen.solvency;

import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Customer;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.SolvencyAttestation.Entry;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.onchain.SolvencyVault;
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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code SolvencyVault} in the Plutus VM (ADR-0006 demo C): an honest attestation and an honest
 * release after the lock are accepted; every mutation that would break S1–S5 is rejected.
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
    private static final long UNLOCK = 1_800_000_000_000L;

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
                        PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                        PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()), icData(vk.ic()));
    }

    // ------------------------------------------------------------------
    //  Attest
    // ------------------------------------------------------------------

    enum Attest {
        NONE, NO_SIGNER, TAMPERED_PROOF, LESS_LOCKED, EXTRA_TOKEN_IN_VAULT, VAULT_ELSEWHERE, MISSING_ENTRY,
        EXTRA_ENTRY, SWAPPED_ENTRIES, NON_CANONICAL_U, SHORT_ID_HASH, TWO_TOKENS, EXTRA_MINT_ENTRY,
        VAULT_SPENT_IN_SAME_TX
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
        byte[] piA = m == Attest.TAMPERED_PROOF ? flipped(proof.piA()) : proof.piA();
        var b = ScriptContextTestBuilder.minting(PolicyId.of(VAULT)).mint(mint)
                .redeemer(PlutusData.constr(0, PlutusData.bytes(piA), PlutusData.bytes(proof.piB()), PlutusData.bytes(proof.piC())));
        if (m != Attest.NO_SIGNER) b.signer(EXCHANGE);
        if (m == Attest.VAULT_SPENT_IN_SAME_TX) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(VAULT_ADDRESS,
                    Value.lovelace(BigInteger.valueOf(RESERVES)).merge(token(1)),
                    new OutputDatum.OutputDatumInline(attestation(entries, false)), Optional.empty())));
        }
        List<Entry> published = new ArrayList<>(entries);
        if (m == Attest.MISSING_ENTRY) published.remove(3);
        if (m == Attest.EXTRA_ENTRY) published.add(entries.getFirst());
        if (m == Attest.SWAPPED_ENTRIES) {
            published.set(0, entries.get(1));
            published.set(1, entries.get(0));
        }
        if (m == Attest.SHORT_ID_HASH) published.set(0, new Entry(Arrays.copyOf(entries.getFirst().idHash(), 31), entries.getFirst().commitment()));
        long locked = m == Attest.LESS_LOCKED ? RESERVES - 1 : RESERVES;
        Value vaultValue = Value.lovelace(BigInteger.valueOf(locked)).merge(token(m == Attest.TWO_TOKENS ? 2 : 1));
        if (m == Attest.EXTRA_TOKEN_IN_VAULT) vaultValue = vaultValue.merge(Value.singleton(PolicyId.of(filled(28, (byte) 3)), TokenName.of(new byte[] {1}), BigInteger.ONE));
        b.output(new TxOut(m == Attest.VAULT_ELSEWHERE ? EXCHANGE_ADDRESS : VAULT_ADDRESS, vaultValue,
                new OutputDatum.OutputDatumInline(attestation(published, m == Attest.NON_CANONICAL_U)), Optional.empty()));
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  Release
    // ------------------------------------------------------------------

    enum Release { NONE, BEFORE_UNLOCK, NO_LOWER_BOUND, NO_SIGNER, NO_BURN, TWO_VAULTS }

    @Test
    @DisplayName("Release: after the lock, with the exchange's signature and a burn; every mutation is rejected")
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
        long from = m == Release.BEFORE_UNLOCK ? UNLOCK - 1000 : UNLOCK;
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
        var b = ScriptContextTestBuilder.spending(ref, attestation(entries, false)).redeemer(PlutusData.constr(0));
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
                new OutputDatum.OutputDatumInline(attestation(entries, false)), Optional.empty());
    }

    private static PlutusData attestation(List<Entry> es, boolean nonCanonical) {
        PlutusData[] items = new PlutusData[es.size()];
        for (int i = 0; i < es.size(); i++) {
            Entry e = es.get(i);
            BigInteger u = e.commitment().affineU();
            if (nonCanonical && i == 0) u = u.add(JubjubCurve.BASE_FIELD_PRIME);
            items[i] = PlutusData.constr(0, PlutusData.bytes(e.idHash()), PlutusData.integer(u),
                    PlutusData.integer(e.commitment().affineV()));
        }
        return PlutusData.constr(0, PlutusData.integer(BigInteger.valueOf(UNLOCK)), PlutusData.list(items));
    }

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
