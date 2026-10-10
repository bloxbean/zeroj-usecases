package com.bloxbean.cardano.zeroj.usecases.pedersen.credential;

import com.bloxbean.cardano.zeroj.usecases.pedersen.common.CostProfiler;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.CreditGate.Profile;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.circuit.CreditProfileProof;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.onchain.CreditGatePolicy;
import org.julclang.compiler.CompileResult;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PolicyId;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.TokenName;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.Value;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.ScriptContextTestBuilder;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code CreditGatePolicy} in the Plutus VM (ADR-0006 demo B): a qualifying, issued credential
 * gets a badge; every mutation that would break C1–C5 is rejected.
 */
class CreditGateVmTest extends ContractTest {

    private static final byte[] GATE = filled(28, (byte) 0x6a);
    private static final byte[] BUREAU = filled(28, (byte) 0xb7);
    private static final byte[] HOLDER = filled(28, (byte) 0xa1);
    private static final byte[] MALLORY = filled(28, (byte) 0x3e);

    private static Program program;
    private static CompileResult compiled;
    private static Profile profile;
    private static PedersenVectorCommitment commitment;
    private static SnarkjsToCardano.ProofCompressed proof;
    private static SnarkjsToCardano.ProofCompressed lowThresholdProof;

    @BeforeAll
    static void setup() {
        var gate = new CreditGate();
        profile = Profile.of(85_000, 720, 1990, 356);
        commitment = profile.commitment();
        proof = ProverToCardano.compressProof(gate.prove(profile, CreditCircuitTest.MIN_INCOME, CreditCircuitTest.MIN_SCORE));
        // Valid, but for lower thresholds than the gate's.
        lowThresholdProof = ProverToCardano.compressProof(gate.prove(profile, 40_000, 600));
        var vk = gate.circuit().compressedVk();
        compiled = new CreditGateVmTest().compileValidatorWithSourceMap(CreditGatePolicy.class, Path.of("src/main/java"));
        program = compiled.program().applyParams(
                        PlutusData.bytes(Fields.i2osp(CreditProfileProof.SCHEMA.digest(), 32)),
                        PlutusData.bytes(BUREAU),
                        PlutusData.integer(BigInteger.valueOf(CreditCircuitTest.MIN_INCOME)),
                        PlutusData.integer(BigInteger.valueOf(CreditCircuitTest.MIN_SCORE)),
                        PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                        PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()), icData(vk.ic()));
    }

    enum Mutation {
        NONE, NO_SIGNER, MALFORMED_PROOF, LOWER_THRESHOLD_PROOF, NO_RECORD, RECORD_OTHER_SCHEMA_DATUM,
        RECORD_FOR_OTHER_HOLDER, RECORD_UNDER_OTHER_POLICY, RECORD_AS_INPUT_NOT_REFERENCE, BADGE_NAME_NOT_HOLDER,
        BADGE_TO_OTHER, TWO_BADGES, EXTRA_MINT_ENTRY, OTHER_COMMITMENT, NON_CANONICAL_U, SHORT_HOLDER,
        IMPOSTOR_HOLDER
    }

    @Test
    @DisplayName("Credit gate: a qualifying issued credential mints a badge; every mutation is rejected")
    void gate() {
        var ctx = context(Mutation.NONE);
        var ok = evaluate(program, ctx);
        CostProfiler.profile("credit gate", program, compiled, ctx);
        assertSuccess(ok);
        System.out.println("[CreditGatePolicy] budget: " + ok.budgetConsumed());
        for (Mutation m : Mutation.values()) {
            if (m != Mutation.NONE && evaluate(program, context(m)) instanceof EvalResult.Success) {
                fail("credit gate accepted " + m);
            }
        }
    }

    private PlutusData context(Mutation m) {
        byte[] holder = switch (m) {
            case SHORT_HOLDER -> Arrays.copyOf(HOLDER, 27);
            case IMPOSTOR_HOLDER -> MALLORY;   // Mallory presents the holder's commitment as hers
            default -> HOLDER;
        };
        var point = commitment.point().normalized();
        BigInteger u = m == Mutation.NON_CANONICAL_U ? point.affineU().add(JubjubCurve.BASE_FIELD_PRIME) : point.affineU();
        BigInteger v = point.affineV();
        if (m == Mutation.OTHER_COMMITMENT) {
            var other = Profile.of(85_000, 720, 1990, 356).commitment().point().normalized();
            u = other.affineU();
            v = other.affineV();
        }
        var p = m == Mutation.LOWER_THRESHOLD_PROOF ? lowThresholdProof : proof;
        byte[] piA = m == Mutation.MALFORMED_PROOF ? flipped(p.piA()) : p.piA();

        byte[] badgeName = m == Mutation.BADGE_NAME_NOT_HOLDER ? MALLORY : holder;
        Value mint = Value.singleton(PolicyId.of(GATE), TokenName.of(badgeName), BigInteger.valueOf(m == Mutation.TWO_BADGES ? 2 : 1));
        if (m == Mutation.EXTRA_MINT_ENTRY) mint = mint.merge(Value.singleton(PolicyId.of(GATE), TokenName.of(filled(28, (byte) 1)), BigInteger.ONE));

        var b = ScriptContextTestBuilder.minting(PolicyId.of(GATE))
                .mint(mint)
                .redeemer(PlutusData.constr(0, PlutusData.bytes(holder), PlutusData.integer(u), PlutusData.integer(v),
                        PlutusData.bytes(piA), PlutusData.bytes(p.piB()), PlutusData.bytes(p.piC())));
        if (m != Mutation.NO_SIGNER) b.signer(holder);

        // The issuance record names the honest holder (and, for the impostor, still the honest holder).
        byte[] recordHolder = m == Mutation.RECORD_FOR_OTHER_HOLDER ? MALLORY : HOLDER;
        byte[] recordPolicy = m == Mutation.RECORD_UNDER_OTHER_POLICY ? filled(28, (byte) 0x99) : BUREAU;
        BigInteger recordSigma = m == Mutation.RECORD_OTHER_SCHEMA_DATUM
                ? CreditProfileProof.SCHEMA.digest().add(BigInteger.ONE) : CreditProfileProof.SCHEMA.digest();
        // NON_CANONICAL_U: the record is made for the same u + p, so the record lookup matches and
        // only the gate's canonical check (and the verifier's own) can reject it.
        BigInteger recordU = m == Mutation.NON_CANONICAL_U ? u : point.affineU();
        byte[] recordName = Blake2bUtil.blake2bHash256(Fields.concat(Fields.i2osp(recordU, 32),
                Fields.i2osp(point.affineV(), 32), Fields.i2osp(CreditProfileProof.SCHEMA.digest(), 32), recordHolder));
        TxOut record = new TxOut(TestDataBuilder.pubKeyAddress(PubKeyHash.of(HOLDER)),
                Value.lovelace(BigInteger.valueOf(2_000_000)).merge(
                        Value.singleton(PolicyId.of(recordPolicy), TokenName.of(recordName), BigInteger.ONE)),
                new OutputDatum.OutputDatumInline(PlutusData.constr(0,
                        PlutusData.integer(recordU), PlutusData.integer(point.affineV()),
                        PlutusData.integer(recordSigma), PlutusData.bytes(recordHolder))),
                Optional.empty());
        if (m == Mutation.RECORD_AS_INPUT_NOT_REFERENCE) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), record));
        } else if (m != Mutation.NO_RECORD) {
            b.referenceInput(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), record));
        }

        byte[] payee = m == Mutation.BADGE_TO_OTHER ? MALLORY : holder;
        b.output(new TxOut(new Address(new Credential.PubKeyCredential(PubKeyHash.of(payee)), Optional.empty()),
                Value.lovelace(BigInteger.valueOf(2_000_000)).merge(
                        Value.singleton(PolicyId.of(GATE), TokenName.of(badgeName), BigInteger.ONE)),
                new OutputDatum.NoOutputDatum(), Optional.empty()));
        return b.buildPlutusData();
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
