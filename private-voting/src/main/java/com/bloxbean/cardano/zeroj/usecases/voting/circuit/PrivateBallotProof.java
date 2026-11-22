package com.bloxbean.cardano.zeroj.usecases.voting.circuit;

import org.zeroj.circuit.annotation.CircuitParam;
import org.zeroj.circuit.annotation.FixedSize;
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkElGamal;
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;
import org.zeroj.circuit.lib.zk.ZkMerkle;
import org.zeroj.circuit.lib.zk.ZkPoseidon;

/**
 * The private ballot relation {@code R_ballot} of ADR-0005.
 *
 * <p>Public, in order: {@code electionId, voterRoot, PK.u, PK.v, N, A.u, A.v, B.u, B.v}. The
 * prover shows that it holds an eligibility secret whose key is in the voter tree, that
 * {@code N} is that voter's nullifier for this election, and that {@code (A, B)} encrypts a vote
 * of 0 or 1 under the election key {@code PK}.
 *
 * <p>The encryption is ZeroJ's {@code elgamal-jubjub-v1} relation {@code R_enc(1)} (spec §9.1),
 * {@code A = [k]·G}, {@code B = [v]·G + [k]·PK}, with a 1-bit message. The key group and the
 * ciphertext group keep their spec §8 order; the application's own inputs sit around them.
 * {@code PK} is fixed by the verifier: it is a parameter of the ballot policy, and its subgroup
 * membership is discharged off-chain from the trustees' proofs of possession (ADR-0005).
 *
 * <p>Neither the vote nor {@code k} is revealed, and because {@code B} is blinded by the election
 * key, nobody can open a single ballot. Only the trustees can jointly decrypt the <em>sum</em> of
 * all ballots (see {@code TallyService}).
 *
 * <p>Version 3 replaced the application's own ElGamal gadget with the library relation. It is a
 * new constraint system, with its own setup, verification key and ballot-policy hash.
 */
@ZKCircuit(
        name = "private-ballot",
        nameTemplate = "private-ballot-d{treeDepth}-jubjub-elgamal",
        version = 3)
public class PrivateBallotProof {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int treeDepth;

    public PrivateBallotProof(@CircuitParam("treeDepth") int treeDepth) {
        if (treeDepth < 1) {
            throw new IllegalArgumentException("treeDepth must be positive");
        }
        this.treeDepth = treeDepth;
    }

    @Prove
    void prove(
            ZkContext zk,
            @Public ZkField electionId,
            @Public ZkField voterRoot,
            @Public ZkField electionKeyU,
            @Public ZkField electionKeyV,
            @Public ZkField nullifier,
            @Public ZkField handleU,
            @Public ZkField handleV,
            @Public ZkField ballotU,
            @Public ZkField ballotV,
            @Secret @UInt(bits = 1) ZkUInt vote,
            @Secret @UInt(bits = 252) ZkUInt randomness,
            @Secret ZkField secretKey,
            @Secret @FixedSize(param = "treeDepth") ZkArray<ZkField> siblings,
            @Secret @FixedSize(param = "treeDepth") ZkArray<ZkBool> pathBits) {

        // Eligibility, and one nullifier per voter and election.
        ZkPoseidon.hash(zk, POSEIDON, secretKey, electionId).assertEqual(nullifier);
        var voterKey = ZkPoseidon.hash(zk, POSEIDON, secretKey, zk.constant(0));
        ZkMerkle.verifyProofPoseidon(zk, POSEIDON, voterKey, voterRoot, siblings, pathBits);

        // The ballot: an elgamal-jubjub-v1 encryption of a 1-bit vote under the election key.
        var electionKey = ZkElGamalPublicKey.fromVerifierFixedPublic(zk, electionKeyU, electionKeyV);
        ZkElGamal.encrypt(zk, vote, randomness, electionKey)
                .assertAffineEquals(zk, handleU, handleV, ballotU, ballotV);
    }
}
