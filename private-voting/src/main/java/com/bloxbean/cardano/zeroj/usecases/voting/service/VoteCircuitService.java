package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.zeroj.usecases.voting.circuit.PrivateBallotProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.voting.circuit.TrusteeShareProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.voting.crypto.JubjubElGamal;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 * The two circuits of ADR-0005 and their keys:
 * <ul>
 *   <li>{@code private-ballot}: a voter's ballot is an ElGamal encryption of 0 or 1 under the
 *       election key, cast by an eligible voter under its nullifier. Verified on-chain.</li>
 *   <li>{@code trustee-dleq}: a trustee's key proof and decryption-share proof. Verified
 *       off-chain by anyone.</li>
 * </ul>
 */
@Service
public class VoteCircuitService {

    private static final Logger log = LoggerFactory.getLogger(VoteCircuitService.class);
    private static final Path CACHE_DIR = Path.of("./data");

    @Value("${zk.tree-depth}")
    private int treeDepth;

    private KeyedCircuit ballot;
    private KeyedCircuit dleq;

    @PostConstruct
    public void init() {
        log.info("Compiling private ballot and trustee circuits (treeDepth={})...", treeDepth);
        ballot = KeyedCircuit.compile("private-ballot-d" + treeDepth,
                PrivateBallotProofCircuit.build(treeDepth), CACHE_DIR);
        dleq = KeyedCircuit.compile("trustee-dleq", TrusteeShareProofCircuit.build(), CACHE_DIR);
        log.info("Circuits ready.");
    }

    // ------------------------------------------------------------------
    //  Ballots
    // ------------------------------------------------------------------

    /** Everything a voter needs to prove a ballot; {@code k} must be fresh per ballot. */
    public record BallotWitness(BigInteger electionId, BigInteger voterRoot, JubjubPoint electionKey,
                                BigInteger secretKey, int vote, BigInteger k,
                                BigInteger[] siblings, BigInteger[] pathBits) {}

    /** A proved ballot: the ciphertext and nullifier it binds, and the proof's public inputs. */
    public record BallotProof(Groth16ProofBLS381 proof, BigInteger nullifier,
                              JubjubElGamal.Ciphertext ciphertext, List<BigInteger> publicInputs) {}

    public BallotProof proveBallot(BallotWitness w) {
        if (w.siblings().length != treeDepth || w.pathBits().length != treeDepth) {
            throw new IllegalArgumentException("siblings and pathBits must have length " + treeDepth);
        }
        BigInteger nullifier = computeNullifier(w.secretKey(), w.electionId());
        JubjubPoint key = w.electionKey().normalized();
        JubjubElGamal.Ciphertext c = JubjubElGamal.encrypt(w.vote(), w.k(), key);
        var inputs = PrivateBallotProofCircuit.inputs(treeDepth)
                .electionId(w.electionId())
                .voterRoot(w.voterRoot())
                .electionKeyU(key.affineU())
                .electionKeyV(key.affineV())
                .nullifier(nullifier)
                .handleU(c.handle().affineU())
                .handleV(c.handle().affineV())
                .ballotU(c.ballot().affineU())
                .ballotV(c.ballot().affineV())
                .vote(w.vote())
                .randomness(w.k())
                .secretKey(w.secretKey())
                .siblings(Arrays.asList(w.siblings()))
                .pathBits(Arrays.asList(w.pathBits()));
        Groth16ProofBLS381 proof = ballot.prove(inputs.toWitnessMap());
        return new BallotProof(proof, nullifier, c, PrivateBallotProofCircuit.publicInputs(inputs));
    }

    /** The ballot statement's public inputs, in circuit order (ADR-0005 {@code R_ballot}). */
    public static List<BigInteger> ballotPublicInputs(BigInteger electionId, BigInteger voterRoot,
                                                      JubjubPoint electionKey, BigInteger nullifier,
                                                      JubjubElGamal.Ciphertext c) {
        JubjubPoint key = electionKey.normalized();
        return List.of(electionId, voterRoot, key.affineU(), key.affineV(), nullifier,
                c.handle().affineU(), c.handle().affineV(), c.ballot().affineU(), c.ballot().affineV());
    }

    public boolean verifyBallot(Groth16ProofBLS381 proof, List<BigInteger> publicInputs) {
        return ballot.verify(SnarkjsGroth16Json.proofJson(proof), publicInputs);
    }

    // ------------------------------------------------------------------
    //  Trustee key and decryption-share proofs
    // ------------------------------------------------------------------

    /** A proof of {@code R_dleq} with its public inputs and snarkjs-format JSON. */
    public record DleqProof(List<BigInteger> publicInputs, String proofJson) {}

    /** Proves {@code P = [x]·G} and {@code D = [x]·X} for the verifier-chosen base {@code X}. */
    public DleqProof proveDleq(JubjubPoint base, BigInteger secret) {
        JubjubPoint x = base.normalized();
        JubjubPoint publicKey = JubjubElGamal.G.scalarMul(secret).normalized();
        JubjubPoint share = x.scalarMul(secret).normalized();
        var inputs = TrusteeShareProofCircuit.inputs()
                .baseU(x.affineU()).baseV(x.affineV())
                .publicKeyU(publicKey.affineU()).publicKeyV(publicKey.affineV())
                .shareU(share.affineU()).shareV(share.affineV())
                .secretShare(secret);
        Groth16ProofBLS381 proof = dleq.prove(inputs.toWitnessMap());
        return new DleqProof(TrusteeShareProofCircuit.publicInputs(inputs), SnarkjsGroth16Json.proofJson(proof));
    }

    /** {@code [X.u, X.v, P.u, P.v, D.u, D.v]}, the order {@code R_dleq} fixes. */
    public static List<BigInteger> dleqPublicInputs(JubjubPoint base, JubjubPoint publicKey, JubjubPoint share) {
        JubjubPoint x = base.normalized();
        JubjubPoint p = publicKey.normalized();
        JubjubPoint d = share.normalized();
        return List.of(x.affineU(), x.affineV(), p.affineU(), p.affineV(), d.affineU(), d.affineV());
    }

    /**
     * Verifies a DLEQ proof against public inputs the <b>verifier</b> derived: the base it chose,
     * the trustee's published key and the claimed share. Never against inputs taken from the
     * prover.
     */
    public boolean verifyDleq(String proofJson, JubjubPoint base, JubjubPoint publicKey, JubjubPoint share) {
        return dleq.verify(proofJson, dleqPublicInputs(base, publicKey, share));
    }

    // ------------------------------------------------------------------
    //  Poseidon (BLS12-381, t = 3)
    // ------------------------------------------------------------------

    public BigInteger computeNullifier(BigInteger secretKey, BigInteger electionId) {
        return poseidon(secretKey, electionId);
    }

    public BigInteger computePublicKey(BigInteger secretKey) {
        return poseidon(secretKey, BigInteger.ZERO);
    }

    public BigInteger merkleHash(BigInteger left, BigInteger right) {
        return poseidon(left, right);
    }

    private static BigInteger poseidon(BigInteger a, BigInteger b) {
        return PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, a, b);
    }

    // ------------------------------------------------------------------

    public Groth16SetupBLS381.SetupResult ballotSetup() {
        return ballot.setup();
    }

    public String ballotVerificationKeyJson() {
        return ballot.verificationKeyJson();
    }

    public String dleqVerificationKeyJson() {
        return dleq.verificationKeyJson();
    }

    public int ballotConstraints() {
        return ballot.numConstraints();
    }

    public int getTreeDepth() {
        return treeDepth;
    }
}
