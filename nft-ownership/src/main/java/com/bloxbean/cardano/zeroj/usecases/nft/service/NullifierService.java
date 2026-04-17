package com.bloxbean.cardano.zeroj.usecases.nft.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * In-memory nullifier tracking. Active when {@code nullifier.mode=in-memory} (default).
 */
@Service
@ConditionalOnProperty(name = "nullifier.mode", havingValue = "in-memory", matchIfMissing = true)
public class NullifierService implements NullifierTracker {

    private static final Logger log = LoggerFactory.getLogger(NullifierService.class);

    private final Set<BigInteger> usedNullifiers = Collections.synchronizedSet(new LinkedHashSet<>());

    /**
     * Check if a nullifier has already been used.
     */
    public boolean isUsed(BigInteger nullifier) {
        return usedNullifiers.contains(nullifier);
    }

    /**
     * Record a nullifier as used. Returns false if already used (double-spend attempt).
     */
    public boolean recordNullifier(BigInteger nullifier) {
        boolean added = usedNullifiers.add(nullifier);
        if (added) {
            log.info("Nullifier recorded: {}", nullifier.toString(16).substring(0, 8));
        } else {
            log.warn("Duplicate nullifier rejected: {}", nullifier.toString(16).substring(0, 8));
        }
        return added;
    }

    /**
     * Get all used nullifiers (for admin dashboard).
     */
    public Set<BigInteger> getUsedNullifiers() {
        return Collections.unmodifiableSet(usedNullifiers);
    }

    public int getUsedCount() {
        return usedNullifiers.size();
    }

    /**
     * Reset all nullifiers (for testing).
     */
    public void reset() {
        usedNullifiers.clear();
    }
}
