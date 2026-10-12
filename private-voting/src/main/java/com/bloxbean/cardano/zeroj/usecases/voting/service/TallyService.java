package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.jubjub.DleqStatement;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalDecryptionException;
import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.VerifiedDecryptionShare;
import org.zeroj.circuit.lib.jubjub.VerifiedKeyShare;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService.BALLOT_MESSAGE_BITS;

/**
 * The homomorphic tally (ADR-0005), on ZeroJ's {@code elgamal-jubjub-v1} safe layer.
 *
 * <p>No ballot is ever decrypted. After the voting deadline, every ballot in the vote list is
 * admitted under the election's key context ({@link ElGamal#admit}) and the admitted ciphertexts
 * are summed ({@link ElGamalCiphertext#sum}); the sum carries the bound {@code |ballots|}. Each
 * trustee publishes {@code D_j = [sk_j]·ΣA} ({@link ElGamal#decryptionShare}) with a proof of the
 * share's DLEQ statement. The shares are accepted only through
 * {@link VerifiedDecryptionShare#verify}, and {@link ElGamal#decrypt} recovers the number of YES
 * votes {@code T ∈ [0, |ballots|]}, failing closed.
 *
 * <p>Decryption happens <b>once</b> per election, over the final ballot set, after the chain is
 * past the deadline plus a settling margin (V7). Decrypting the running sum after each ballot
 * would reveal every ballot by differencing.
 */
@Service
public class TallyService {

    private static final Logger log = LoggerFactory.getLogger(TallyService.class);

    private final ElectionService electionService;
    private final OnChainVoteService onChainVoteService;
    private final VoteCircuitService circuitService;

    @Value("${election.tally-settle-seconds:20}")
    private long settleSeconds = 20;

    /** Decrypted results by election id: each election is decrypted at most once. */
    private final Map<BigInteger, TallyResult> decrypted = new ConcurrentHashMap<>();

    public TallyService(ElectionService electionService, OnChainVoteService onChainVoteService,
                        VoteCircuitService circuitService) {
        this.electionService = electionService;
        this.onChainVoteService = onChainVoteService;
        this.circuitService = circuitService;
    }

    /**
     * One trustee's published decryption share: the trustee's key encoding, the 32-byte encoding
     * of {@code D_j} ({@link VerifiedDecryptionShare#encode()}), both hex, and the Groth16 proof of
     * the share's DLEQ statement.
     */
    public record Share(String trustee, String publicKeyHex, String shareHex, String proofJson) {}

    /**
     * The tally as published. {@code yes}/{@code no} are {@code null} while voting is open.
     * {@code aggregate} is the encrypted sum {@code (ΣA, ΣB)}, raw as published, and {@code null}
     * when no ballot was cast. Everything needed to re-check the result is here or on-chain.
     */
    public record TallyResult(BigInteger electionId, boolean decrypted, long votingDeadlineMillis,
                              int ballots, Integer yes, Integer no,
                              RawElGamalCiphertext aggregate, List<Share> shares,
                              List<OnChainVoteService.BallotNode> ballotNodes, String ballotSetDigest) {}

    public synchronized TallyResult tally() throws Exception {
        var config = electionService.getConfig();
        if (config == null) throw new IllegalStateException("Election not finalized");
        TallyResult done = decrypted.get(config.electionId());
        if (done != null) return done;

        // Time first, then the ballots: once the chain is past the deadline no ballot can be added,
        // so a set read after this check is final.
        long now = onChainVoteService.chainTimeMillis();
        var ballots = onChainVoteService.getBallots(config);
        String ballotPolicyId = onChainVoteService.recomputeBallotPolicyId(config);
        List<ElGamalCiphertext> admitted = admitBallots(ballots, config.keyContext(), config.electionKey(), ballotPolicyId);
        ElGamalCiphertext total = admitted.isEmpty() ? null : ElGamalCiphertext.sum(admitted);
        RawElGamalCiphertext published = total == null ? null : total.raw();
        String digest = ballotSetDigest(config.electionId(), onChainVoteService.scriptBinding(config).listPolicyId(), ballots);
        if (now < config.votingDeadlineMillis() + settleSeconds * 1000) {
            return new TallyResult(config.electionId(), false, config.votingDeadlineMillis(),
                    ballots.size(), null, null, published, List.of(), ballots, digest);
        }

        log.info("Voting closed; decrypting the sum of {} ballots (once)...", ballots.size());
        List<Share> shares = new ArrayList<>();
        int yes = 0;
        if (total != null) {
            // Each trustee computes its share of the admitted sum and proves the share's statement.
            // (In the demo the trustees run in-process; each would run on its own machine.)
            for (var trustee : electionService.trustees()) {
                VerifiedDecryptionShare own = ElGamal.decryptionShare(trustee.secretKey(), total);
                var proof = circuitService.proveDleq(own.statement(), trustee.secretKey().secretScalar());
                shares.add(new Share(trustee.label(), HexUtil.encodeHexString(trustee.secretKey().publicKey().encode()),
                        HexUtil.encodeHexString(own.encode()), proof.proofJson()));
            }
            // The combiner accepts the published shares only through their proofs, as anyone would.
            Map<String, ElGamalPublicKey> trusteeKeys = new LinkedHashMap<>();
            for (var trustee : electionService.trustees()) {
                trusteeKeys.put(trustee.label(), trustee.secretKey().publicKey());
            }
            List<VerifiedDecryptionShare> verified = new ArrayList<>();
            for (Share share : shares) {
                verified.add(verifiedShare(total, trusteeKeys.get(share.trustee()), share));
            }
            yes = Math.toIntExact(ElGamal.decrypt(total, verified, total.bound().longValueExact()));
        }
        var result = new TallyResult(config.electionId(), true, config.votingDeadlineMillis(),
                ballots.size(), yes, ballots.size() - yes, published, List.copyOf(shares), ballots, digest);
        var verification = verify(result);
        if (!verification.valid()) {
            throw new IllegalStateException("tally failed its own verification; not publishing: "
                    + verification.checks().stream().filter(c -> !c.startsWith("ok")).toList());
        }
        decrypted.put(config.electionId(), result);
        log.info("Tally: YES={}, NO={}, ballots={}", yes, ballots.size() - yes, ballots.size());
        return result;
    }

    /** The outcome of re-checking a published tally. */
    public record Verification(boolean valid, List<String> checks) {}

    /**
     * Re-checks a published tally the way any observer could, rebuilding everything from public
     * data. The trustees' secrets and this service's own key context are not consulted.
     * <ol>
     *   <li>rebuild the key context from the manifest: each trustee key registered through its key
     *       proof ({@link VerifiedKeyShare#verify}), then aggregated; its joint key must be the
     *       election key the ballot policy is parameterised with;</li>
     *   <li>recompute both script hashes from the manifest's parameters, and check that the list
     *       root was created by spending the manifest's seed;</li>
     *   <li>re-walk the vote list, recompute the ballot-set digest, re-admit every ballot under the
     *       rebuilt context and sum them;</li>
     *   <li>accept each trustee's share only through {@link VerifiedDecryptionShare#verify}, which
     *       builds the DLEQ statement from the re-admitted sum and the trustee's registered key;</li>
     *   <li>decrypt with {@link ElGamal#decrypt} and compare with the published counts.</li>
     * </ol>
     */
    public Verification verify(TallyResult result) throws Exception {
        var config = electionService.getConfig();
        List<String> checks = new ArrayList<>();
        boolean ok = result.decrypted() && config != null && config.electionId().equals(result.electionId());
        if (!ok) return new Verification(false, List.of("no decrypted tally for the current election"));

        // 1. The key context, from the manifest's key encodings and key proofs alone (V9).
        Map<String, ElGamalPublicKey> trusteeKeys = new LinkedHashMap<>();
        List<VerifiedKeyShare> keyShares = new ArrayList<>();
        for (var trustee : config.trustees()) {
            try {
                VerifiedKeyShare share = ElectionService.verifiedKeyShare(circuitService, trustee);
                keyShares.add(share);
                trusteeKeys.put(trustee.label(), share.publicKey());
                checks.add("ok: " + trustee.label() + " key proof");
            } catch (IllegalArgumentException e) {
                checks.add("FAIL: " + trustee.label() + " key proof (" + e.getMessage() + ")");
                ok = false;
            }
        }
        NOfNKeyContext context = null;
        if (ok) {
            try {
                context = ElGamalPublicKey.aggregate(keyShares);
            } catch (IllegalArgumentException e) {
                checks.add("FAIL: trustee keys do not aggregate (" + e.getMessage() + ")");
            }
        }
        boolean keyOk = context != null && context.jointKey().equals(config.electionKey());
        checks.add((keyOk ? "ok" : "FAIL") + ": election key = Σ possession-verified trustee keys");
        if (!keyOk) return new Verification(false, checks);

        // 2. The scripts the ballots were cast under are the ones the manifest's parameters produce (V12).
        var binding = onChainVoteService.scriptBinding(config);
        String ballotPolicyId = onChainVoteService.recomputeBallotPolicyId(config);
        boolean scriptsOk = binding.ballotPolicyId().equals(ballotPolicyId)
                && binding.listPolicyId().equals(onChainVoteService.recomputeListPolicyId(config,
                        HexUtil.decodeHexString(binding.seedRef())));
        checks.add((scriptsOk ? "ok" : "FAIL") + ": script hashes recomputed from the manifest");
        boolean seedOk = onChainVoteService.rootSpendsSeed(config);
        checks.add((seedOk ? "ok" : "FAIL") + ": list root created by spending the manifest's seed");
        ok &= scriptsOk && seedOk;

        // 3. The ballot set, re-read from chain data and re-admitted under the rebuilt context.
        var ballots = onChainVoteService.getBallots(config);
        boolean sameDigest = ballotSetDigest(config.electionId(), binding.listPolicyId(), ballots)
                .equals(result.ballotSetDigest());
        checks.add((sameDigest ? "ok" : "FAIL") + ": ballot-set digest " + result.ballotSetDigest().substring(0, 16) + "...");
        ok &= sameDigest;
        ElGamalCiphertext total;
        try {
            List<ElGamalCiphertext> admitted = admitBallots(ballots, context, config.electionKey(), ballotPolicyId);
            total = admitted.isEmpty() ? null : ElGamalCiphertext.sum(admitted);
        } catch (IllegalArgumentException e) {
            checks.add("FAIL: on-chain ballots not admitted (" + e.getMessage() + ")");
            return new Verification(false, checks);
        }
        checks.add("ok: " + ballots.size() + " on-chain ballots admitted (elgamal-jubjub-v1, width "
                + BALLOT_MESSAGE_BITS + ")");
        boolean sameSet = ballots.size() == result.ballots() && (total == null
                ? result.aggregate() == null
                : result.aggregate() != null && Arrays.equals(total.encode(), result.aggregate().encode()));
        checks.add((sameSet ? "ok" : "FAIL") + ": aggregate recomputed from " + ballots.size() + " on-chain ballots");
        ok &= sameSet;

        if (total == null) {
            // No ballot: nothing to decrypt, and no share may be published.
            boolean emptyOk = result.shares().isEmpty()
                    && Integer.valueOf(0).equals(result.yes()) && Integer.valueOf(0).equals(result.no());
            checks.add((emptyOk ? "ok" : "FAIL") + ": no ballots, YES = NO = 0");
            return new Verification(ok && emptyOk, checks);
        }

        // 4. Every trustee's share, accepted only through its proof (spec §10.2).
        if (result.shares().size() != config.trustees().size()) {
            checks.add("FAIL: expected " + config.trustees().size() + " shares, got " + result.shares().size());
            return new Verification(false, checks);
        }
        List<VerifiedDecryptionShare> verified = new ArrayList<>();
        for (int j = 0; j < config.trustees().size(); j++) {
            var trustee = config.trustees().get(j);
            var share = result.shares().get(j);
            boolean shareOk = trustee.label().equals(share.trustee());
            if (shareOk) {
                try {
                    verified.add(verifiedShare(total, trusteeKeys.get(trustee.label()), share));
                } catch (IllegalArgumentException e) {
                    shareOk = false;
                }
            }
            checks.add((shareOk ? "ok" : "FAIL") + ": " + trustee.label() + " decryption-share proof");
            ok &= shareOk;
        }
        if (verified.size() != config.trustees().size()) return new Verification(false, checks);

        // 5. Decrypt: the unique T in [0, |ballots|], or failure.
        Long t;
        try {
            t = ElGamal.decrypt(total, verified, total.bound().longValueExact());
        } catch (IllegalArgumentException | ElGamalDecryptionException e) {
            t = null;
            checks.add("FAIL: decryption refused (" + e.getMessage() + ")");
        }
        boolean totalOk = t != null && result.yes() != null && result.no() != null
                && result.yes() >= 0 && result.no() >= 0
                && result.yes() + result.no() == ballots.size()
                && t == result.yes().longValue();
        checks.add((totalOk ? "ok" : "FAIL") + ": decrypt(Σ ballots; verified shares) = " + result.yes()
                + " of " + ballots.size());
        ok &= totalOk;
        return new Verification(ok, checks);
    }

    /**
     * Admits the ballots read from the vote list into the safe layer under {@code context}, each at
     * the ballot's width.
     *
     * <p><b>Delegated verification ({@code elgamal-jubjub-v1} §10.1, item 2).</b> The ballot proofs
     * are not re-verified here: an on-chain validator verified each one before its ballot reached
     * the ledger, which §10.1 names as a legitimate delegation provided the caller establishes
     * from chain data that the ciphertext is one that validator accepted. That is established
     * as follows:
     * <ul>
     *   <li>A {@link OnChainVoteService.BallotNode} exists only for a ciphertext that
     *       {@link OnChainVoteService#getBallots} read from the inline datum of a node of this
     *       election's vote list (walked from its one-shot root, every list UTxO covered), a node
     *       holding exactly one nullifier token minted under {@code node.ballotPolicyId()}. Its
     *       constructor is private, so this verifier cannot be reached with any other
     *       ciphertext.</li>
     *   <li>The ledger mints that token only if the ballot policy succeeds. The policy succeeds only
     *       after verifying {@code R_ballot}, which embeds {@code R_enc(1)}, with the election key
     *       fixed in its parameters and the {@code (A, B)} in the datum of the one output holding
     *       the token. The list validator keeps that datum unchanged afterwards (ADR-0005 V3, V5).</li>
     *   <li>{@code ballotPolicyId} is the hash the caller recomputed from the manifest (election
     *       id, voter root, election key, deadline, ballot verification key), so the policy that
     *       minted the token is the one with this key and this circuit.</li>
     * </ul>
     * The verifier therefore returns {@code true} only for the statement that policy verified:
     * width 1, the policy's key, and exactly the node's ciphertext.
     *
     * @throws IllegalArgumentException if any ballot is refused
     */
    private static List<ElGamalCiphertext> admitBallots(List<OnChainVoteService.BallotNode> ballots,
                                                        NOfNKeyContext context, ElGamalPublicKey policyKey,
                                                        String ballotPolicyId) {
        List<ElGamalCiphertext> admitted = new ArrayList<>(ballots.size());
        for (OnChainVoteService.BallotNode node : ballots) {
            admitted.add(ElGamal.admit(node.ciphertext(), context, BALLOT_MESSAGE_BITS, statement ->
                    statement.width() == BALLOT_MESSAGE_BITS
                            && node.ballotPolicyId().equals(ballotPolicyId)
                            && statement.key().equals(policyKey)
                            && statement.ciphertextPublicInputs().equals(node.ciphertext().publicInputs())));
        }
        return admitted;
    }

    /**
     * Accepts a published share for the admitted {@code total} only if its proof verifies for the
     * DLEQ statement the library builds: {@code X = ΣA} of {@code total}, {@code P} = the
     * trustee's registered key, {@code D} = the published share (spec §10.2).
     *
     * @throws IllegalArgumentException if the trustee is unknown or the share or proof is rejected
     */
    private VerifiedDecryptionShare verifiedShare(ElGamalCiphertext total, ElGamalPublicKey trusteeKey, Share share) {
        if (trusteeKey == null) {
            throw new IllegalArgumentException("share from an unknown trustee: " + share.trustee());
        }
        return VerifiedDecryptionShare.verify(total, trusteeKey, HexUtil.decodeHexString(share.shareHex()),
                statement -> statement.kind() == DleqStatement.Kind.DECRYPTION_SHARE
                        && circuitService.verifyDleq(share.proofJson(), statement.publicInputs()));
    }

    private static final byte[] DIGEST_TAG =
            "zeroj.private-voting.ballot-set.v1".getBytes(StandardCharsets.UTF_8);

    /**
     * {@code blake2b_256(tag ‖ I2OSP32(electionId) ‖ listPolicyId ‖ entries)}, the entries sorted by
     * nullifier, each {@code I2OSP32(N) ‖ I2OSP32(A.u) ‖ I2OSP32(A.v) ‖ I2OSP32(B.u) ‖ I2OSP32(B.v)}.
     * Domain-separated and bound to the election and its list, so a digest cannot be replayed for
     * another election.
     */
    public static String ballotSetDigest(BigInteger electionId, String listPolicyId,
                                         List<OnChainVoteService.BallotNode> ballots) {
        var sorted = new ArrayList<>(ballots);
        sorted.sort((a, b) -> Arrays.compareUnsigned(a.nullifier(), b.nullifier()));
        var buf = new ByteArrayOutputStream();
        buf.writeBytes(DIGEST_TAG);
        buf.writeBytes(OnChainVoteService.toFixedWidth(electionId, 32));
        buf.writeBytes(HexUtil.decodeHexString(listPolicyId));
        for (var n : sorted) {
            buf.writeBytes(OnChainVoteService.toFixedWidth(new BigInteger(1, n.nullifier()), 32));
            for (BigInteger c : n.ciphertext().publicInputs()) {
                buf.writeBytes(OnChainVoteService.toFixedWidth(c, 32));
            }
        }
        return HexUtil.encodeHexString(Blake2bUtil.blake2bHash256(buf.toByteArray()));
    }
}
