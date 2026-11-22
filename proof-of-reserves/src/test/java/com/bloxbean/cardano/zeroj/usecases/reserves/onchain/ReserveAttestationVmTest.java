package com.bloxbean.cardano.zeroj.usecases.reserves.onchain;

import com.bloxbean.cardano.zeroj.usecases.reserves.model.AccountEntity;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.AttestationPeriods;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.MerkleSumTreeService;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.ReserveCircuitService;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.DatumHash;
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
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code ReserveAttestation} in the Plutus VM (ADR-0009 D4, M4 exit): an honest attestation mint
 * and a burn with a lower bound of exactly the period's end are accepted; every mutation is
 * rejected. The proofs are real Groth16 proofs of the unchanged {@code SolvencyProof} circuit
 * (depth 2) over a salted tree.
 */
class ReserveAttestationVmTest extends ContractTest {

    private static final int DEPTH = 2;
    private static final byte[] POLICY = filled(28, (byte) 0x7a);
    private static final byte[] CUSTODIAN = filled(28, (byte) 0xc5);
    private static final byte[] OTHER = filled(28, (byte) 0x0b);
    private static final long GENESIS = 1_800_000_000_000L;
    private static final long PERIOD_MS = 3_600_000L;
    private static final long PERIOD = 5;
    private static final AttestationPeriods CLOCK = new AttestationPeriods(GENESIS, PERIOD_MS);
    private static final long END = CLOCK.end(PERIOD);
    private static final Address SCRIPT_ADDRESS = new Address(
            new Credential.ScriptCredential(ScriptHash.of(POLICY)), Optional.empty());
    private static final Address STAKED_SCRIPT_ADDRESS = new Address(SCRIPT_ADDRESS.credential(),
            Optional.of(new StakingCredential.StakingHash(new Credential.PubKeyCredential(PubKeyHash.of(OTHER)))));
    private static final Address CUSTODIAN_ADDRESS = new Address(
            new Credential.PubKeyCredential(PubKeyHash.of(CUSTODIAN)), Optional.empty());
    private static final BigInteger LOCKED = BigInteger.valueOf(3_000_000);

    @TempDir
    static Path dataDir;

    private static Program program;
    private static Program zeroPeriodProgram;
    private static BigInteger root;
    private static BigInteger liabilities;
    private static BigInteger reserves;
    private static BigInteger insolventReserves;
    private static SnarkjsToCardano.ProofCompressed proof;
    private static SnarkjsToCardano.ProofCompressed insolventProof;

    @BeforeAll
    static void setup() {
        var circuit = new ReserveCircuitService();
        ReflectionTestUtils.setField(circuit, "treeDepth", DEPTH);
        ReflectionTestUtils.setField(circuit, "potPower", 13);
        ReflectionTestUtils.setField(circuit, "dataDir", dataDir.toString());
        circuit.init();

        List<AccountEntity> accounts = List.of(
                new AccountEntity("alice", "Alice", 500_000_000L),
                new AccountEntity("bob", "Bob", 1_200_000_000L),
                new AccountEntity("charlie", "Charlie", 300_000_000L));
        var snapshot = MerkleSumTreeService.build(accounts, DEPTH, new SecureRandom());
        root = snapshot.root();
        liabilities = snapshot.totalLiabilities();
        reserves = liabilities.add(BigInteger.valueOf(1_000_000_000L));
        insolventReserves = liabilities.subtract(BigInteger.ONE);

        var solvent = circuit.prove(reserves, root, liabilities, snapshot.leafIds(), snapshot.leafBalances());
        var insolvent = circuit.prove(insolventReserves, root, liabilities, snapshot.leafIds(), snapshot.leafBalances());
        assertTrue(solvent.solvent());
        assertFalse(insolvent.solvent());
        proof = ProverToCardano.compressProof(solvent.proof());
        insolventProof = ProverToCardano.compressProof(insolvent.proof());

        var vk = ProverToCardano.compressVk(circuit.getSetupResult());
        var compiled = new ReserveAttestationVmTest().compileValidatorWithSourceMap(ReserveAttestation.class, Path.of("src/main/java"));
        program = compiled.program().applyParams(params(vk, PERIOD_MS));
        zeroPeriodProgram = compiled.program().applyParams(params(vk, 0));
    }

    private static PlutusData[] params(SnarkjsToCardano.VkCompressed vk, long periodMs) {
        return new PlutusData[] {
                PlutusData.bytes(CUSTODIAN), PlutusData.integer(BigInteger.valueOf(GENESIS)),
                PlutusData.integer(BigInteger.valueOf(periodMs)),
                PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()), icData(vk.ic())};
    }

    // ------------------------------------------------------------------
    //  Mint
    // ------------------------------------------------------------------

    enum Mint {
        NONE, NO_SIGNER, OTHER_SIGNER, BAD_PROOF, INSOLVENT, PROOF_FOR_OTHER_RESERVES, WRONG_ROOT, WRONG_LIABILITIES,
        TWO_TOKENS, EXTRA_TOKEN_NAME, NAME_NOT_PERIOD, TWO_HOLDERS, EXTRA_DATUM_FIELD, MISSING_DATUM_FIELD,
        DATUM_TAG_1, HASHED_DATUM, NO_DATUM, NON_CANONICAL_ROOT, PERIOD_TOO_LARGE, NEGATIVE_PERIOD,
        OUTSIDE_SCRIPT_ADDRESS, STAKED_SCRIPT_ADDRESS, EXTRA_TOKEN_IN_OUTPUT, OWN_INPUT_SPENT
    }

    @Test
    @DisplayName("Mint: an honest solvent attestation is accepted; every mutation is rejected")
    void mint() {
        var ok = evaluate(program, mintContext(Mint.NONE));
        assertSuccess(ok);
        System.out.println("[ReserveAttestation mint] budget: " + ok.budgetConsumed());
        for (Mint m : Mint.values()) {
            if (m != Mint.NONE && evaluate(program, mintContext(m)) instanceof EvalResult.Success) {
                fail("mint accepted " + m);
            }
        }
    }

    @Test
    @DisplayName("A script with periodMs = 0 refuses every mint and spend")
    void zeroPeriodRefused() {
        assertFailure(evaluate(zeroPeriodProgram, mintContext(Mint.NONE)));
        assertFailure(evaluate(zeroPeriodProgram, spendContext(Spend.NONE)));
    }

    private PlutusData mintContext(Mint m) {
        BigInteger datumPeriod = switch (m) {
            case PERIOD_TOO_LARGE -> BigInteger.ONE.shiftLeft(64);
            case NEGATIVE_PERIOD -> BigInteger.valueOf(-1);
            default -> BigInteger.valueOf(PERIOD);
        };
        byte[] name = switch (m) {
            case PERIOD_TOO_LARGE, NEGATIVE_PERIOD -> new byte[8];
            case NAME_NOT_PERIOD -> AttestationPeriods.tokenName(PERIOD + 1);
            default -> AttestationPeriods.tokenName(PERIOD);
        };
        long qty = m == Mint.TWO_TOKENS || m == Mint.TWO_HOLDERS ? 2 : 1;
        Value mint = Value.singleton(PolicyId.of(POLICY), TokenName.of(name), BigInteger.valueOf(qty));
        if (m == Mint.EXTRA_TOKEN_NAME) {
            mint = mint.merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(AttestationPeriods.tokenName(PERIOD + 7)), BigInteger.ONE));
        }

        var p = m == Mint.INSOLVENT ? insolventProof : proof;
        byte[] piA = m == Mint.BAD_PROOF ? flipped(p.piA()) : p.piA();
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).mint(mint)
                .redeemer(PlutusData.constr(0, PlutusData.bytes(piA), PlutusData.bytes(p.piB()), PlutusData.bytes(p.piC())));
        if (m == Mint.OTHER_SIGNER) b.signer(OTHER);
        else if (m != Mint.NO_SIGNER) b.signer(CUSTODIAN);
        if (m == Mint.OWN_INPUT_SPENT) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(SCRIPT_ADDRESS,
                    Value.lovelace(LOCKED), new OutputDatum.OutputDatumInline(datum(BigInteger.valueOf(PERIOD - 1), root, liabilities, reserves)),
                    Optional.empty())));
        }

        BigInteger r = switch (m) {
            case INSOLVENT -> insolventReserves;
            case PROOF_FOR_OTHER_RESERVES -> reserves.add(BigInteger.ONE);
            default -> reserves;
        };
        BigInteger dRoot = switch (m) {
            case WRONG_ROOT -> root.add(BigInteger.ONE);
            case NON_CANONICAL_ROOT -> root.add(FR);
            default -> root;
        };
        BigInteger dLiabilities = m == Mint.WRONG_LIABILITIES ? liabilities.add(BigInteger.ONE) : liabilities;
        PlutusData d = switch (m) {
            case EXTRA_DATUM_FIELD -> PlutusData.constr(0, PlutusData.integer(datumPeriod), PlutusData.integer(dRoot),
                    PlutusData.integer(dLiabilities), PlutusData.integer(r), PlutusData.integer(BigInteger.ONE));
            case MISSING_DATUM_FIELD -> PlutusData.constr(0, PlutusData.integer(datumPeriod), PlutusData.integer(dRoot),
                    PlutusData.integer(dLiabilities));
            case DATUM_TAG_1 -> PlutusData.constr(1, PlutusData.integer(datumPeriod), PlutusData.integer(dRoot),
                    PlutusData.integer(dLiabilities), PlutusData.integer(r));
            default -> datum(datumPeriod, dRoot, dLiabilities, r);
        };
        OutputDatum outputDatum = switch (m) {
            case HASHED_DATUM -> new OutputDatum.OutputDatumHash(DatumHash.of(filled(32, (byte) 0x11)));
            case NO_DATUM -> new OutputDatum.NoOutputDatum();
            default -> new OutputDatum.OutputDatumInline(d);
        };
        Address to = switch (m) {
            case OUTSIDE_SCRIPT_ADDRESS -> CUSTODIAN_ADDRESS;
            case STAKED_SCRIPT_ADDRESS -> STAKED_SCRIPT_ADDRESS;
            default -> SCRIPT_ADDRESS;
        };
        Value held = Value.lovelace(LOCKED).merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(name),
                BigInteger.valueOf(m == Mint.TWO_HOLDERS ? 1 : qty)));
        if (m == Mint.EXTRA_TOKEN_NAME) {
            held = held.merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(AttestationPeriods.tokenName(PERIOD + 7)), BigInteger.ONE));
        }
        if (m == Mint.EXTRA_TOKEN_IN_OUTPUT) {
            held = held.merge(Value.singleton(PolicyId.of(OTHER), TokenName.of(new byte[] {1}), BigInteger.ONE));
        }
        b.output(new TxOut(to, held, outputDatum, Optional.empty()));
        if (m == Mint.TWO_HOLDERS) {
            b.output(new TxOut(CUSTODIAN_ADDRESS, Value.lovelace(LOCKED).merge(
                    Value.singleton(PolicyId.of(POLICY), TokenName.of(name), BigInteger.ONE)),
                    new OutputDatum.NoOutputDatum(), Optional.empty()));
        }
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  Spend (release) and its burn
    // ------------------------------------------------------------------

    enum Spend {
        NONE, NO_SIGNER, NO_BURN, LOWER_END_MINUS_1, UNBOUNDED_LOWER, LOWER_POS_INF, BURN_OTHER_TOKEN, BURN_TWO,
        EXTRA_MINT, RELOCK_AT_SCRIPT, TWO_SCRIPT_INPUTS, INPUT_WITHOUT_TOKEN
    }

    @Test
    @DisplayName("Release: a custodian-signed burn from exactly the period end is accepted; every mutation is rejected")
    void spend() {
        var ok = evaluate(program, spendContext(Spend.NONE));
        assertSuccess(ok);
        System.out.println("[ReserveAttestation release] budget: " + ok.budgetConsumed());
        assertSuccess(evaluate(program, burnContext(Spend.NONE)));
        for (Spend m : Spend.values()) {
            if (m != Spend.NONE && evaluate(program, spendContext(m)) instanceof EvalResult.Success) {
                fail("spend accepted " + m);
            }
        }
        for (Spend m : List.of(Spend.BURN_TWO, Spend.EXTRA_MINT, Spend.TWO_SCRIPT_INPUTS, Spend.NO_BURN)) {
            if (evaluate(program, burnContext(m)) instanceof EvalResult.Success) {
                fail("burn accepted " + m);
            }
        }
    }

    private ScriptContextTestBuilder releaseTx(Spend m, ScriptContextTestBuilder b, TxOutRef ref) {
        byte[] name = m == Spend.BURN_OTHER_TOKEN ? AttestationPeriods.tokenName(PERIOD + 1) : AttestationPeriods.tokenName(PERIOD);
        Value mint = switch (m) {
            case NO_BURN -> Value.zero();
            case BURN_TWO -> Value.singleton(PolicyId.of(POLICY), TokenName.of(name), BigInteger.valueOf(-2));
            default -> Value.singleton(PolicyId.of(POLICY), TokenName.of(name), BigInteger.valueOf(-1));
        };
        if (m == Spend.EXTRA_MINT) {
            mint = mint.merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(AttestationPeriods.tokenName(PERIOD + 2)), BigInteger.ONE));
        }
        b.mint(mint);
        if (m != Spend.NO_SIGNER) b.signer(CUSTODIAN);
        IntervalBound lower = switch (m) {
            case LOWER_END_MINUS_1 -> new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(END - 1)), true);
            case UNBOUNDED_LOWER -> new IntervalBound(new IntervalBoundType.NegInf(), true);
            case LOWER_POS_INF -> new IntervalBound(new IntervalBoundType.PosInf(), true);
            default -> new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(END)), true);
        };
        b.validRange(new Interval(lower, new IntervalBound(new IntervalBoundType.PosInf(), true)));
        b.input(new TxInInfo(ref, m == Spend.INPUT_WITHOUT_TOKEN
                ? new TxOut(SCRIPT_ADDRESS, Value.lovelace(LOCKED), new OutputDatum.OutputDatumInline(lockedDatum()), Optional.empty())
                : lockedOut()));
        if (m == Spend.TWO_SCRIPT_INPUTS) b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), lockedOut()));
        b.output(new TxOut(m == Spend.RELOCK_AT_SCRIPT ? SCRIPT_ADDRESS : CUSTODIAN_ADDRESS, Value.lovelace(LOCKED),
                m == Spend.RELOCK_AT_SCRIPT ? new OutputDatum.OutputDatumInline(lockedDatum()) : new OutputDatum.NoOutputDatum(),
                Optional.empty()));
        return b;
    }

    private PlutusData spendContext(Spend m) {
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        var b = ScriptContextTestBuilder.spending(ref, lockedDatum()).redeemer(PlutusData.constr(0));
        return releaseTx(m, b, ref).buildPlutusData();
    }

    private PlutusData burnContext(Spend m) {
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).redeemer(PlutusData.constr(1, PlutusData.integer(0)));
        return releaseTx(m, b, ref).buildPlutusData();
    }

    // ------------------------------------------------------------------

    private static final BigInteger FR = new BigInteger(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513");

    private static PlutusData lockedDatum() {
        return datum(BigInteger.valueOf(PERIOD), root, liabilities, reserves);
    }

    private static TxOut lockedOut() {
        return new TxOut(SCRIPT_ADDRESS, Value.lovelace(LOCKED).merge(
                Value.singleton(PolicyId.of(POLICY), TokenName.of(AttestationPeriods.tokenName(PERIOD)), BigInteger.ONE)),
                new OutputDatum.OutputDatumInline(lockedDatum()), Optional.empty());
    }

    /** {@code Attestation(period, liabilitiesRoot, totalLiabilities, totalReserves)}. */
    private static PlutusData datum(BigInteger period, BigInteger liabilitiesRoot, BigInteger totalLiabilities,
                                    BigInteger totalReserves) {
        return PlutusData.constr(0, PlutusData.integer(period), PlutusData.integer(liabilitiesRoot),
                PlutusData.integer(totalLiabilities), PlutusData.integer(totalReserves));
    }

    private static PlutusData icData(List<byte[]> ic) {
        List<PlutusData> points = new ArrayList<>();
        for (byte[] p : ic) points.add(PlutusData.bytes(p));
        return PlutusData.list(points.toArray(new PlutusData[0]));
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
