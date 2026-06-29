package com.bloxbean.cardano.zeroj.usecases.annotated.credential.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkJubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidonN;

/**
 * Hardened compliance-credential circuit (v2). Unlike {@link ComplianceCredentialProof},
 * which only proves knowledge of a preimage of a <em>self-asserted</em> commitment, this
 * circuit roots trust in an <b>issuer EdDSA-Jubjub signature</b> verified in-circuit.
 *
 * <h2>Why v1 is not sound on its own</h2>
 * In v1 {@code credentialCommitment} is a public input chosen by the prover. Nothing forces
 * it to be a commitment an issuer actually created, so an attacker can fabricate any
 * compliant attributes, compute the matching Poseidon commitment themselves, and produce a
 * valid proof. v1 proves <em>internal consistency</em>, not <em>legitimacy</em>.
 *
 * <h2>What v2 proves</h2>
 * <i>"I hold a credential, signed by the issuer whose public key is {@code (pkU, pkV)},
 * attesting {@code (age, countryCode, notSanctioned)}; and {@code age >= minimumAge} AND
 * {@code countryCode == requiredCountryCode} AND {@code notSanctioned}"</i> — without
 * revealing {@code age}, {@code countryCode}, {@code notSanctioned}, or the signature.
 *
 * <p>Forgery now requires the issuer's secret key: the in-circuit EdDSA verification binds
 * the same secret attributes that drive the predicates to a message the issuer signed. A
 * verifier (e.g. an on-chain validator) pins the trusted {@code (pkU, pkV)} as public inputs,
 * so a proof made under any other key is rejected.
 *
 * <h2>Public vs secret</h2>
 * Public (verifier-supplied / pinned): {@code pkU, pkV, minimumAge, requiredCountryCode}.
 * Secret (witness): {@code age, countryCode, notSanctioned} plus the signature components
 * {@code sigRU, sigRV, sigS} and the challenge-reduction witnesses {@code kModL, kQuotient}.
 *
 * <h2>Remaining hardening (out of scope for this circuit)</h2>
 * Issuer-signature binding closes the forgery hole. Two orthogonal concerns remain and belong
 * at the transaction/validator layer (or a v3 that adds public inputs):
 * <ul>
 *   <li><b>Replay</b> — a Groth16 proof is a bearer token; bind it to the spending tx (a nonce,
 *       UTxO ref, or tx hash as a public input checked against the script context).</li>
 *   <li><b>Holder binding</b> — bind the credential to the holder's key (include it in the
 *       signed claims and require that key to sign the spending tx), so a credential cannot be
 *       shared.</li>
 * </ul>
 *
 * @see ComplianceCredentialProof the unsound v1 (kept as a teaching contrast)
 */
@ZKCircuit(name = "annotated-compliance-credential-signed", version = 1)
public class ComplianceCredentialProofV2 {
    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    @Prove
    ZkBool prove(
            ZkContext zk,
            // --- Public: issuer public key (affine Jubjub coords) + policy params ---
            @Public ZkField pkU,
            @Public ZkField pkV,
            @Public @UInt(bits = 8) ZkUInt minimumAge,
            @Public @UInt(bits = 16) ZkUInt requiredCountryCode,
            // --- Secret: attested claims ---
            @Secret @UInt(bits = 8) ZkUInt age,
            @Secret @UInt(bits = 16) ZkUInt countryCode,
            @Secret ZkBool notSanctioned,
            // --- Secret: issuer signature (R, S) + EdDSA challenge-reduction witnesses ---
            @Secret ZkField sigRU,
            @Secret ZkField sigRV,
            @Secret @UInt(bits = 252) ZkUInt sigS,
            @Secret @UInt(bits = 252) ZkUInt kModL,
            @Secret @UInt(bits = 4) ZkUInt kQuotient) {

        // 1. Recompute the signed message exactly as the issuer composed it off-circuit:
        //    claimsMsg = Poseidon(age, countryCode, notSanctioned).
        //    The very attributes checked below are the ones fed into the hash, so they cannot
        //    be swapped for the signature check vs. the predicate checks.
        var claimsMsg = ZkPoseidonN.hash(
                zk,
                POSEIDON,
                age.asField(),
                countryCode.asField(),
                notSanctioned.asField());

        // 2. Verify the issuer EdDSA-Jubjub signature over claimsMsg. This is a hard assertion:
        //    an invalid signature makes the witness unsatisfiable. The trusted issuer key
        //    (pkU, pkV) is public, so only the issuer can mint credentials this circuit accepts.
        var issuerKey = ZkJubjubPoint.fromTrustedAffine(zk, pkU, pkV);
        var signatureR = ZkJubjubPoint.fromTrustedAffine(zk, sigRU, sigRV);
        ZkEdDSAJubjub.verify(zk, issuerKey, claimsMsg, signatureR, sigS, kModL, kQuotient);

        // 3. Compliance predicates over the (now issuer-attested) secret attributes.
        return age.gte(minimumAge)
                .and(countryCode.isEqual(requiredCountryCode))
                .and(notSanctioned);
    }
}
