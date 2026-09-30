package com.bloxbean.cardano.zeroj.usecases.identity.onchain;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.core.types.JulcList;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * On-chain Groth16 BLS12-381 verifier for KYC credential proofs backed by
 * EdDSA-Jubjub signatures (ADR-0016).
 *
 * <p>Public inputs (5): {@code pkU, pkV, minAge, countryRoot, eligible}.
 * The first two identify the issuer by their Jubjub public key; the next
 * two bind the proof to a specific policy; {@code eligible} is the assertion
 * the caller claims (1 = eligible). The validator accepts only when the
 * Groth16 proof is valid AND {@code eligible == 1}.
 *
 * <p>Stateless — no nullifiers, proofs can be reused for ongoing access.
 */
@SpendingValidator
public class CredentialGatedValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;
    @Param static BigInteger issuerPkU;
    @Param static BigInteger issuerPkV;
    @Param static BigInteger policyMinAge;
    @Param static BigInteger policyCountryRoot;

    record CredentialProof(byte[] piA, byte[] piB, byte[] piC,
                           byte[] pkU, byte[] pkV,
                           byte[] minAge, byte[] countryRoot, byte[] eligible) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, CredentialProof proof, ScriptContext ctx) {
        BigInteger eligibleVal = Builtins.byteStringToInteger(true, proof.eligible());
        boolean isEligible = eligibleVal.compareTo(BigInteger.ONE) == 0;

        BigInteger pub0 = Builtins.byteStringToInteger(true, proof.pkU());
        BigInteger pub1 = Builtins.byteStringToInteger(true, proof.pkV());
        BigInteger pub2 = Builtins.byteStringToInteger(true, proof.minAge());
        BigInteger pub3 = Builtins.byteStringToInteger(true, proof.countryRoot());
        BigInteger pub4 = Builtins.byteStringToInteger(true, proof.eligible());

        // verifyWithRegisteredKey shifts issuer authorization to the protocol. These
        // script parameters are that registry binding: a proof under any other key fails.
        boolean registeredIssuer = isRegisteredIssuer(pub0, pub1);
        boolean registeredPolicy = isRegisteredPolicy(pub2, pub3);

        PlutusData publicInputs = JulcList.of(pub0, pub1, pub2, pub3, pub4).toPlutusData();
        boolean proofValid = Groth16BLS12381Lib.verify(publicInputs,
                proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return registeredIssuer && registeredPolicy && isEligible && proofValid;
    }

    static boolean isRegisteredIssuer(BigInteger publicKeyU, BigInteger publicKeyV) {
        return publicKeyU.equals(issuerPkU) && publicKeyV.equals(issuerPkV);
    }

    static boolean isRegisteredPolicy(BigInteger minAge, BigInteger countryRoot) {
        return minAge.equals(policyMinAge) && countryRoot.equals(policyCountryRoot);
    }
}
