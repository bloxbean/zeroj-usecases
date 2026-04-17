package com.bloxbean.cardano.zeroj.usecases.voting.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Tallies votes from on-chain commitments.
 * <p>
 * Each vote node stores commitment = Poseidon(vote, nullifier).
 * Since vote is 0 or 1, we compute both possibilities and match.
 */
@Service
public class TallyService {

    private static final Logger log = LoggerFactory.getLogger(TallyService.class);

    private final OnChainVoteService onChainVoteService;
    private final VoteCircuitService circuitService;

    public TallyService(OnChainVoteService onChainVoteService, VoteCircuitService circuitService) {
        this.onChainVoteService = onChainVoteService;
        this.circuitService = circuitService;
    }

    public TallyResult tally() throws Exception {
        var nodes = onChainVoteService.getVoteNodes();
        int yes = 0, no = 0, unknown = 0;
        List<VoteDetail> details = new ArrayList<>();

        for (var node : nodes) {
            BigInteger nullifier = new BigInteger(1, node.fullNullifier());
            BigInteger commitment = node.commitment();

            // Compute expected commitments for YES and NO
            BigInteger commitYes = circuitService.computeCommitment(BigInteger.ONE, nullifier);
            BigInteger commitNo = circuitService.computeCommitment(BigInteger.ZERO, nullifier);

            String vote;
            if (commitment.equals(commitYes)) {
                yes++;
                vote = "YES";
            } else if (commitment.equals(commitNo)) {
                no++;
                vote = "NO";
            } else {
                unknown++;
                vote = "UNKNOWN";
            }

            details.add(new VoteDetail(nullifier.toString(16).substring(0, 12) + "...", vote));
        }

        log.info("Tally: YES={}, NO={}, total={}", yes, no, yes + no + unknown);
        return new TallyResult(yes, no, unknown, yes + no + unknown, details);
    }

    public record TallyResult(int yes, int no, int unknown, int total, List<VoteDetail> votes) {}
    public record VoteDetail(String nullifierPrefix, String vote) {}
}
