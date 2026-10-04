package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.voting.crypto.JubjubElGamal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The homomorphic tally (ADR-0005).
 *
 * <p>No ballot is ever decrypted. After the voting deadline, the ballots in the vote list are
 * added together, {@code (ΣA, ΣB)}; each trustee publishes {@code D_j = [sk_j]·ΣA} with a proof
 * that it used the secret behind its published key; and {@code ΣB − Σ D_j = [T]·G} gives the
 * number of YES votes {@code T}.
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

    /** One trustee's published decryption share and its proof. */
    public record Share(String trustee, JubjubPoint publicKey, JubjubPoint share, String proofJson) {}

    /**
     * The tally as published. {@code yes}/{@code no} are {@code null} while voting is open.
     * Everything needed to re-check the result is here or on-chain.
     */
    public record TallyResult(BigInteger electionId, boolean decrypted, long votingDeadlineMillis,
                              int ballots, Integer yes, Integer no,
                              JubjubElGamal.Ciphertext aggregate, List<Share> shares,
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
        var aggregate = JubjubElGamal.sum(ballots.stream().map(OnChainVoteService.BallotNode::ciphertext).toList());
        String digest = ballotSetDigest(config.electionId(), onChainVoteService.scriptBinding(config).listPolicyId(), ballots);
        if (now < config.votingDeadlineMillis() + settleSeconds * 1000) {
            return new TallyResult(config.electionId(), false, config.votingDeadlineMillis(),
                    ballots.size(), null, null, aggregate, List.of(), ballots, digest);
        }

        log.info("Voting closed; decrypting the sum of {} ballots (once)...", ballots.size());
        List<Share> shares = new ArrayList<>();
        for (var trustee : electionService.trustees()) {
            JubjubPoint d = JubjubElGamal.decryptionShare(trustee.secretShare(), aggregate.handle());
            var proof = circuitService.proveDleq(aggregate.handle(), trustee.secretShare());
            shares.add(new Share(trustee.label(), trustee.publicKey(), d, proof.proofJson()));
        }
        int yes = combine(aggregate, shares, ballots.size());
        var result = new TallyResult(config.electionId(), true, config.votingDeadlineMillis(),
                ballots.size(), yes, ballots.size() - yes, aggregate, List.copyOf(shares), ballots, digest);
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
     * Re-checks a published tally the way any observer could:
     * <ol>
     *   <li>check the manifest: the election key is the sum of the trustee keys, the script
     *       hashes recompute from the manifest's parameters, and the list root was created by
     *       spending the manifest's seed;</li>
     *   <li>re-walk the vote list, recompute the ballot-set digest and {@code (ΣA, ΣB)};</li>
     *   <li>check each trustee's key proof (base {@code G}) against the election manifest;</li>
     *   <li>check each decryption-share proof with base {@code ΣA} <i>as recomputed here</i>, the
     *       trustee's manifest key and the published share;</li>
     *   <li>check {@code ΣB − Σ D_j = [yes]·G}.</li>
     * </ol>
     * Uses only public data: the trustees' secrets are not consulted.
     */
    public Verification verify(TallyResult result) throws Exception {
        var config = electionService.getConfig();
        List<String> checks = new ArrayList<>();
        boolean ok = result.decrypted() && config != null && config.electionId().equals(result.electionId());
        if (!ok) return new Verification(false, List.of("no decrypted tally for the current election"));

        // The manifest: the joint key is the sum of the proved trustee keys, and the scripts the
        // ballots were cast under are the ones the manifest's parameters produce (V12).
        boolean keyOk;
        try {
            keyOk = JubjubElGamal.jointKey(config.trustees().stream().map(ElectionService.TrusteeInfo::publicKey).toList())
                    .projectiveEquals(config.electionKey());
        } catch (IllegalArgumentException e) {
            keyOk = false;
        }
        checks.add((keyOk ? "ok" : "FAIL") + ": election key = Σ trustee keys");
        var binding = onChainVoteService.scriptBinding(config);
        boolean scriptsOk = binding.ballotPolicyId().equals(onChainVoteService.recomputeBallotPolicyId(config))
                && binding.listPolicyId().equals(onChainVoteService.recomputeListPolicyId(config,
                        HexUtil.decodeHexString(binding.seedRef())));
        checks.add((scriptsOk ? "ok" : "FAIL") + ": script hashes recomputed from the manifest");
        boolean seedOk = onChainVoteService.rootSpendsSeed(config);
        checks.add((seedOk ? "ok" : "FAIL") + ": list root created by spending the manifest's seed");
        ok &= keyOk && scriptsOk && seedOk;

        var ballots = onChainVoteService.getBallots(config);
        var aggregate = JubjubElGamal.sum(ballots.stream().map(OnChainVoteService.BallotNode::ciphertext).toList());
        boolean sameDigest = ballotSetDigest(config.electionId(), binding.listPolicyId(), ballots)
                .equals(result.ballotSetDigest());
        checks.add((sameDigest ? "ok" : "FAIL") + ": ballot-set digest " + result.ballotSetDigest().substring(0, 16) + "...");
        ok &= sameDigest;
        boolean sameSet = ballots.size() == result.ballots()
                && aggregate.handle().projectiveEquals(result.aggregate().handle())
                && aggregate.ballot().projectiveEquals(result.aggregate().ballot());
        checks.add((sameSet ? "ok" : "FAIL") + ": aggregate recomputed from " + ballots.size() + " on-chain ballots");
        ok &= sameSet;

        if (result.shares().size() != config.trustees().size()) {
            checks.add("FAIL: expected " + config.trustees().size() + " shares, got " + result.shares().size());
            return new Verification(false, checks);
        }
        List<JubjubPoint> shares = new ArrayList<>();
        for (int j = 0; j < config.trustees().size(); j++) {
            var trustee = config.trustees().get(j);
            var share = result.shares().get(j);
            boolean keyProof = circuitService.verifyDleq(trustee.keyProofJson(),
                    JubjubElGamal.G, trustee.publicKey(), trustee.publicKey());
            boolean shareProof = trustee.label().equals(share.trustee())
                    && circuitService.verifyDleq(share.proofJson(), aggregate.handle(), trustee.publicKey(), share.share());
            checks.add((keyProof ? "ok" : "FAIL") + ": " + trustee.label() + " key proof");
            checks.add((shareProof ? "ok" : "FAIL") + ": " + trustee.label() + " decryption-share proof");
            ok &= keyProof && shareProof;
            shares.add(share.share());
        }

        JubjubPoint m = JubjubElGamal.unmask(aggregate.ballot(), shares);
        boolean totalOk = result.yes() != null && result.no() != null
                && result.yes() >= 0 && result.no() >= 0
                && result.yes() + result.no() == ballots.size()
                && JubjubElGamal.G.scalarMul(BigInteger.valueOf(result.yes())).projectiveEquals(m);
        checks.add((totalOk ? "ok" : "FAIL") + ": ΣB − ΣD = [" + result.yes() + "]·G");
        ok &= totalOk;
        return new Verification(ok, checks);
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
            for (BigInteger c : List.of(n.ciphertext().handle().affineU(), n.ciphertext().handle().affineV(),
                    n.ciphertext().ballot().affineU(), n.ciphertext().ballot().affineV())) {
                buf.writeBytes(OnChainVoteService.toFixedWidth(c, 32));
            }
        }
        return HexUtil.encodeHexString(Blake2bUtil.blake2bHash256(buf.toByteArray()));
    }

    private static int combine(JubjubElGamal.Ciphertext aggregate, List<Share> shares, int ballots) {
        JubjubPoint m = JubjubElGamal.unmask(aggregate.ballot(), shares.stream().map(Share::share).toList());
        OptionalInt t = JubjubElGamal.discreteLog(m, ballots);
        if (t.isEmpty()) {
            throw new IllegalStateException("decrypted sum is not [t]·G for any t in [0, " + ballots + "]");
        }
        return t.getAsInt();
    }
}
