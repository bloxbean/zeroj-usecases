package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.zeroj.usecases.voting.circuit.PrivateBallotProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.voting.circuit.TrusteeShareProofCircuit;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.jubjub.DleqStatement;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.EncryptionStatement;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The two circuits of ADR-0005 and their keys:
 * <ul>
 *   <li>{@code private-ballot}: a voter's ballot is an {@code elgamal-jubjub-v1} encryption of a
 *       1-bit vote under the election key, cast by an eligible voter under its nullifier.
 *       Verified on-chain.</li>
 *   <li>{@code trustee-dleq}: the {@code elgamal-jubjub-v1} DLEQ relation, for a trustee's key
 *       proof and decryption-share proof. Verified off-chain by anyone.</li>
 * </ul>
 * Statements come from ZeroJ's ElGamal API ({@link EncryptionStatement}, {@link DleqStatement});
 * this service proves them and verifies proofs against their public inputs verbatim.
 */
@Service
public class VoteCircuitService {

    private static final Logger log = LoggerFactory.getLogger(VoteCircuitService.class);
    private static final Path CACHE_DIR = Path.of("./data");

    /** The ballot's message width: {@code R_ballot} embeds {@code R_enc(1)}. */
    public static final int BALLOT_MESSAGE_BITS = 1;

    @Value("${zk.tree-depth}")
    private int treeDepth;

    private KeyedCircuit ballot;
    private KeyedCircuit dleq;

    @PostConstruct
    public void init() {
        log.info("Compiling private ballot and trustee circuits (treeDepth={})...", treeDepth);
        // The circuit version is part of the key-cache name: a new circuit version never loads the
        // setup of an older one, even if the cache directory still holds it.
        ballot = KeyedCircuit.compile("private-ballot-d" + treeDepth + "-v" + PrivateBallotProofCircuit.CIRCUIT_VERSION,
                PrivateBallotProofCircuit.build(treeDepth), CACHE_DIR);
        dleq = KeyedCircuit.compile("trustee-dleq-v" + TrusteeShareProofCircuit.CIRCUIT_VERSION,
                TrusteeShareProofCircuit.build(), CACHE_DIR);
        log.info("Circuits ready.");
    }

    // ------------------------------------------------------------------
    //  Ballots
    // ------------------------------------------------------------------

    /**
     * Everything a voter needs to prove a ballot. {@code encryption} is the voter's own
     * {@code ElGamal.encryptWithOpening} result: the ciphertext under the election's key context
     * and its secret opening {@code (m, k)}, which becomes the witness.
     */
    public record BallotWitness(BigInteger electionId, BigInteger voterRoot, BigInteger secretKey,
                                ElGamalEncryption encryption, BigInteger[] siblings, BigInteger[] pathBits) {
        @Override
        public String toString() {
            return "BallotWitness{electionId=" + electionId + ", secrets=<redacted>}";
        }
    }

    /** A proved ballot: the ciphertext and nullifier it binds, and the proof's public inputs. */
    public record BallotProof(Groth16ProofBLS381 proof, BigInteger nullifier,
                              ElGamalCiphertext ciphertext, List<BigInteger> publicInputs) {}

    public BallotProof proveBallot(BallotWitness w) {
        if (w.siblings().length != treeDepth || w.pathBits().length != treeDepth) {
            throw new IllegalArgumentException("siblings and pathBits must have length " + treeDepth);
        }
        ElGamalEncryption encryption = w.encryption();
        if (encryption.width() != BALLOT_MESSAGE_BITS) {
            throw new IllegalArgumentException("a ballot encrypts a " + BALLOT_MESSAGE_BITS + "-bit vote");
        }
        BigInteger nullifier = computeNullifier(w.secretKey(), w.electionId());
        EncryptionStatement statement = encryption.statement();
        List<BigInteger> key = statement.keyPublicInputs();
        List<BigInteger> ciphertext = statement.ciphertextPublicInputs();
        var inputs = PrivateBallotProofCircuit.inputs(treeDepth)
                .electionId(w.electionId())
                .voterRoot(w.voterRoot())
                .electionKeyU(key.get(0))
                .electionKeyV(key.get(1))
                .nullifier(nullifier)
                .handleU(ciphertext.get(0))
                .handleV(ciphertext.get(1))
                .ballotU(ciphertext.get(2))
                .ballotV(ciphertext.get(3))
                .vote(encryption.message())
                .randomness(encryption.randomness())
                .secretKey(w.secretKey())
                .siblings(Arrays.asList(w.siblings()))
                .pathBits(Arrays.asList(w.pathBits()));
        Groth16ProofBLS381 proof = ballot.prove(inputs.toWitnessMap());
        List<BigInteger> publicInputs = PrivateBallotProofCircuit.publicInputs(inputs);
        if (!publicInputs.equals(ballotPublicInputs(w.electionId(), w.voterRoot(), statement.key(), nullifier,
                encryption.ciphertext().raw()))) {
            throw new IllegalStateException("ballot public inputs are not in R_ballot order");
        }
        return new BallotProof(proof, nullifier, encryption.ciphertext(), publicInputs);
    }

    /**
     * The ballot statement's public inputs, in circuit order (ADR-0005 {@code R_ballot}): the
     * election id and voter root, the key group {@code PK.u, PK.v}, the nullifier, and the
     * ciphertext group {@code A.u, A.v, B.u, B.v} (spec §8 order within each group).
     */
    public static List<BigInteger> ballotPublicInputs(BigInteger electionId, BigInteger voterRoot,
                                                      ElGamalPublicKey electionKey, BigInteger nullifier,
                                                      RawElGamalCiphertext ciphertext) {
        List<BigInteger> out = new ArrayList<>(9);
        out.add(electionId);
        out.add(voterRoot);
        out.addAll(electionKey.publicInputs());
        out.add(nullifier);
        out.addAll(ciphertext.publicInputs());
        return List.copyOf(out);
    }

    public boolean verifyBallot(Groth16ProofBLS381 proof, List<BigInteger> publicInputs) {
        return ballot.verify(SnarkjsGroth16Json.proofJson(proof), publicInputs);
    }

    // ------------------------------------------------------------------
    //  Trustee key and decryption-share proofs
    // ------------------------------------------------------------------

    /** A proof of {@code R_dleq} with its public inputs and snarkjs-format JSON. */
    public record DleqProof(List<BigInteger> publicInputs, String proofJson) {}

    /**
     * Proves a DLEQ statement the library built ({@code ElGamalSecretKey.possessionStatement()}
     * or {@code VerifiedDecryptionShare.statement()}), with the trustee's secret scalar as the
     * witness. The statement's six public inputs are used verbatim.
     */
    public DleqProof proveDleq(DleqStatement statement, BigInteger secret) {
        List<BigInteger> pub = statement.publicInputs();
        var inputs = TrusteeShareProofCircuit.inputs()
                .baseU(pub.get(0)).baseV(pub.get(1))
                .publicKeyU(pub.get(2)).publicKeyV(pub.get(3))
                .shareU(pub.get(4)).shareV(pub.get(5))
                .secretShare(secret);
        Groth16ProofBLS381 proof = dleq.prove(inputs.toWitnessMap());
        List<BigInteger> publicInputs = TrusteeShareProofCircuit.publicInputs(inputs);
        if (!publicInputs.equals(pub)) {
            throw new IllegalStateException("DLEQ public inputs are not in spec §8 order");
        }
        return new DleqProof(publicInputs, SnarkjsGroth16Json.proofJson(proof));
    }

    /**
     * Verifies a DLEQ proof against {@code publicInputs}. Callers pass a library-built
     * {@code DleqStatement.publicInputs()} unchanged (the delegated-verifier obligation of
     * {@code DleqStatementVerifier}), never values taken from the prover.
     */
    public boolean verifyDleq(String proofJson, List<BigInteger> publicInputs) {
        if (proofJson == null || publicInputs == null || publicInputs.size() != 6) {
            return false;
        }
        return dleq.verify(proofJson, publicInputs);
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

    public int dleqConstraints() {
        return dleq.numConstraints();
    }

    public int getTreeDepth() {
        return treeDepth;
    }
}
