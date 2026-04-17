package com.bloxbean.cardano.zeroj.usecases.nft.service;

import java.math.BigInteger;

/**
 * Common interface for nullifier tracking — supports both in-memory and on-chain modes.
 */
public interface NullifierTracker {
    boolean isUsed(BigInteger nullifier);
    boolean recordNullifier(BigInteger nullifier);
    int getUsedCount();
}
