package com.bloxbean.cardano.zeroj.usecases.nft.service;

import java.math.BigInteger;

/**
 * Reads token holdings from the chain, for the snapshot's holder authentication (ADR-0009 D2).
 */
public interface HolderLookup {

    /**
     * The quantity of {@code unit} (policy id ‖ asset name, hex) held at {@code address}, read
     * from the chain indexer.
     *
     * @throws Exception when the indexer cannot answer; callers fail closed
     */
    BigInteger quantityAt(String address, String unit) throws Exception;
}
