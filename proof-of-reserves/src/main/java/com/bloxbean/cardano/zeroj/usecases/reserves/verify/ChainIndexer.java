package com.bloxbean.cardano.zeroj.usecases.reserves.verify;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * The chain data the customer check reads (ADR-0009 D4.3): from an independent indexer such as
 * Yaci Store, never from the custodian's API. Any failure throws, and the check fails closed.
 */
public interface ChainIndexer {

    /** The latest block's time, POSIX milliseconds. */
    long latestBlockTimeMs() throws IOException;

    /** The unspent outputs that hold {@code unit} (first page, at most {@code count}). */
    List<UtxoView> assetUtxos(String unit, int count) throws IOException;

    /**
     * One page of {@code unit}'s mint and burn history. Pages are numbered from 1; a page shorter
     * than {@code count} is the last.
     */
    List<HistoryEntry> assetHistory(String unit, int page, int count) throws IOException;

    /** An unspent output: bech32 address, quantities by unit, and the inline datum (hex CBOR, or null). */
    record UtxoView(String txHash, int outputIndex, String address, Map<String, BigInteger> amounts,
                    String inlineDatum) {}

    /** One mint (positive quantity) or burn (negative quantity) of a unit. {@code unit} may be null. */
    record HistoryEntry(String txHash, String unit, BigInteger quantity) {}
}
