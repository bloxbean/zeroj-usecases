package com.bloxbean.cardano.zeroj.usecases.plonk.credential;

import com.bloxbean.cardano.zeroj.api.VerificationResult;
import com.bloxbean.cardano.zeroj.usecases.plonk.credential.service.PlonkCredentialProofService;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlonkCredentialProofServiceTest {
    @Test
    void provesAndVerifiesCardanoMpiProfileOffChain() {
        var prover = new PlonkCredentialProofService(10);
        var fixture = SampleComplianceCredential.validFixture();

        var bundle = prover.prove(fixture.inputs());
        VerificationResult result = prover.verifyOffChain(bundle);

        assertTrue(result.proofValid(), () -> "verification failed: " + result);
        assertEquals(3, bundle.publicInputs().length);
        assertEquals(fixture.credentialCommitment(), bundle.publicInputs()[0]);
        assertEquals(BigInteger.valueOf(18), bundle.publicInputs()[1]);
        assertEquals(BigInteger.ONE, bundle.publicInputs()[2]);
        assertEquals(3, bundle.cardanoProof().publicInputInverses().length);
    }
}
