package com.bloxbean.cardano.zeroj.usecases.plonk.credential;

import com.bloxbean.cardano.julc.core.Program;
import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.MultiInputProofCompressed;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.VkCompressed;
import com.bloxbean.cardano.zeroj.usecases.plonk.credential.onchain.CredentialPlonkVerifier;
import com.bloxbean.cardano.zeroj.usecases.plonk.credential.circuit.ComplianceCredentialGateProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.plonk.credential.service.PlonkCredentialProofService;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

class PlonkCredentialJulcVerifierTest extends ContractTest {
    private static Fixture cachedFixture;

    @Test
    void julcVerifierAcceptsCredentialProofDatumInputs() throws Exception {
        var fixture = fixture();

        var result = evaluate(fixture.program(), context(fixture, datum(fixture.publicInputs())));

        assertSuccess(result);
    }

    @Test
    void julcVerifierRejectsTamperedCredentialDatum() throws Exception {
        var fixture = fixture();
        BigInteger[] tampered = fixture.publicInputs().clone();
        tampered[1] = tampered[1].add(BigInteger.ONE);

        var result = evaluate(fixture.program(), context(fixture, datum(tampered)));

        assertFailure(result);
    }

    @Test
    void julcVerifierRejectsProofBelowOnChainMinimumAgePolicy() throws Exception {
        var fixture = createFixture(ComplianceCredentialGateProofCircuit.inputs()
                .credentialCommitment(SampleComplianceCredential.credentialCommitment(
                        BigInteger.valueOf(29), BigInteger.ONE, BigInteger.ONE, BigInteger.valueOf(555_777)))
                .minimumAge(BigInteger.valueOf(17))
                .requiredJurisdiction(BigInteger.ONE)
                .age(BigInteger.valueOf(29))
                .ageSurplus(BigInteger.valueOf(12))
                .jurisdiction(BigInteger.ONE)
                .notSanctioned(BigInteger.ONE)
                .credentialSalt(BigInteger.valueOf(555_777)));

        var result = evaluate(fixture.program(), context(fixture, datum(fixture.publicInputs())));

        assertFailure(result);
    }

    private Fixture fixture() throws Exception {
        if (cachedFixture == null) {
            cachedFixture = createFixture(SampleComplianceCredential.validFixture().inputs());
        }
        return cachedFixture;
    }

    private Fixture createFixture(ComplianceCredentialGateProofCircuit.Inputs inputs) throws Exception {
        var prover = new PlonkCredentialProofService(10);
        var bundle = prover.prove(inputs);
        var compiled = compileValidator(CredentialPlonkVerifier.class);
        Program program = applyParams(compiled.program(), bundle.vk(), bundle.publicInputs().length);
        return new Fixture(program, bundle.cardanoProof(), bundle.publicInputs());
    }

    private PlutusData context(Fixture fixture, PlutusData datum) {
        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        return spendingContext(txOutRef, datum)
                .redeemer(redeemer(fixture.proof()))
                .buildPlutusData();
    }

    private static Program applyParams(Program program, VkCompressed vk, int publicInputCount) {
        return program.applyParams(
                PlutusData.bytes(vk.qm()),
                PlutusData.bytes(vk.ql()),
                PlutusData.bytes(vk.qr()),
                PlutusData.bytes(vk.qo()),
                PlutusData.bytes(vk.qc()),
                PlutusData.bytes(vk.s1()),
                PlutusData.bytes(vk.s2()),
                PlutusData.bytes(vk.s3()),
                PlutusData.bytes(vk.x2()),
                PlutusData.integer(vk.domainSize()),
                PlutusData.integer(vk.domainPower()),
                PlutusData.integer(vk.omega()),
                PlutusData.integer(vk.k1()),
                PlutusData.integer(vk.k2()),
                PlutusData.integer(vk.k1OverK2()),
                PlutusData.integer(vk.fr()),
                PlutusData.integer(vk.nInv()),
                PlutusData.bytes(vk.g1Gen()),
                PlutusData.bytes(vk.g2Gen()),
                PlutusData.bytes(PlonKProverToCardano.CARDANO_MPI_PROOF_FORMAT.getBytes(StandardCharsets.US_ASCII)),
                PlutusData.integer(publicInputCount));
    }

    private static PlutusData datum(BigInteger[] publicInputs) {
        PlutusData[] values = new PlutusData[publicInputs.length];
        for (int i = 0; i < publicInputs.length; i++) {
            values[i] = PlutusData.integer(publicInputs[i]);
        }
        return PlutusData.list(values);
    }

    private static PlutusData redeemer(MultiInputProofCompressed proof) {
        return PlutusData.constr(0,
                PlutusData.bytes(proof.cmA()),
                PlutusData.bytes(proof.cmB()),
                PlutusData.bytes(proof.cmC()),
                PlutusData.bytes(proof.cmZ()),
                PlutusData.bytes(proof.cmT1()),
                PlutusData.bytes(proof.cmT2()),
                PlutusData.bytes(proof.cmT3()),
                PlutusData.bytes(proof.wXi()),
                PlutusData.bytes(proof.wXiw()),
                PlutusData.integer(proof.evalA()),
                PlutusData.integer(proof.evalB()),
                PlutusData.integer(proof.evalC()),
                PlutusData.integer(proof.evalS1()),
                PlutusData.integer(proof.evalS2()),
                PlutusData.integer(proof.evalZw()),
                datum(proof.publicInputInverses()));
    }

    private record Fixture(
            Program program,
            MultiInputProofCompressed proof,
            BigInteger[] publicInputs) {
    }
}
