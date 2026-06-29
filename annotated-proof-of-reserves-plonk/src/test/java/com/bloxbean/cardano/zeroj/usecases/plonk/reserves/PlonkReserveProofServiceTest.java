package com.bloxbean.cardano.zeroj.usecases.plonk.reserves;

import com.bloxbean.cardano.zeroj.api.VerificationResult;
import com.bloxbean.cardano.zeroj.usecases.plonk.reserves.service.PlonkReserveProofService;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlonkReserveProofServiceTest {
    @Test
    void provesAndVerifiesCardanoMpiProfileOffChain() {
        var prover = new PlonkReserveProofService(SampleReserveStatement.ACCOUNT_COUNT, 10);
        var fixture = SampleReserveStatement.solventFixture();

        var bundle = prover.prove(fixture.inputs());
        VerificationResult result = prover.verifyOffChain(bundle);

        assertTrue(result.proofValid(), () -> "verification failed: " + result);
        assertEquals(3, bundle.publicInputs().length);
        assertEquals(fixture.liabilityBatchCommitment(), bundle.publicInputs()[0]);
        assertEquals(BigInteger.valueOf(200), bundle.publicInputs()[1]);
        assertEquals(BigInteger.valueOf(175), bundle.publicInputs()[2]);
        assertEquals(3, bundle.cardanoProof().publicInputInverses().length);
    }
}
