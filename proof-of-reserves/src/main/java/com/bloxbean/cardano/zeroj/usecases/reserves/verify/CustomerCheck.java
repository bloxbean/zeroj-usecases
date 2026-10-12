package com.bloxbean.cardano.zeroj.usecases.reserves.verify;

import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.AttestationPeriods;
import com.bloxbean.cardano.zeroj.usecases.reserves.service.ReserveLeaves;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The customer's inclusion check against the chain (ADR-0009 D4.3, invariant I7). The browser UI
 * ({@code frontend/src/lib/customerCheck.js}) implements the same steps and both run the shared
 * fixtures in {@code src/test/resources/customer-check-fixtures.json}.
 *
 * <ol>
 *   <li>Recompute the root from the customer's id, salt, balance, leaf index and sibling path.</li>
 *   <li>Take the current period from the indexer's latest block time and the published
 *       {@code genesisMs} and {@code periodMs}.</li>
 *   <li>Find the unspent output holding {@code policyId ‖ I2OSP8(period)}: exactly one, at the
 *       script's enterprise address (payment credential = the policy id, no stake part), with an
 *       inline datum {@code Attestation(period, root, totalLiabilities, totalReserves)} for that
 *       period.</li>
 *   <li>Read the token's whole mint history, page by page: exactly one mint of quantity 1 and no
 *       burn. A second mint, also after a burn, refuses the period. An unavailable, inconsistent
 *       or over-long history fails closed.</li>
 *   <li>Compare the attested root with the recomputed one.</li>
 * </ol>
 *
 * <p>The check proves inclusion in a tree whose solvency statement the script verified when it
 * minted the token. It does not show the balances are true, nor that {@code totalReserves} is held.
 */
public final class CustomerCheck {

    public static final int HISTORY_PAGE_SIZE = 100;
    public static final int MAX_HISTORY_PAGES = 20;
    public static final int MAX_DEPTH = 32;

    private static final BigInteger FR = new BigInteger(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513");
    private static final BigInteger UINT64 = BigInteger.ONE.shiftLeft(64);
    private static final Pattern POLICY = Pattern.compile("[0-9a-f]{56}");

    public enum Outcome {
        VERIFIED, BAD_INPUT, INDEXER_UNAVAILABLE, BEFORE_GENESIS, NO_ATTESTATION, DUPLICATE_ATTESTATION,
        NOT_AT_SCRIPT_ADDRESS, BAD_DATUM, WRONG_PERIOD, HISTORY_INCOMPLETE, ROOT_MISMATCH
    }

    /** What {@code /verify/{id}} returns, plus the id the customer typed. */
    public record Inclusion(String accountId, BigInteger salt, BigInteger balance, long leafIndex,
                            List<BigInteger> siblings) {}

    /** The published attestation policy and clock; the customer pins these. */
    public record Deployment(String policyId, long genesisMs, long periodMs) {}

    public record Attestation(long period, BigInteger liabilitiesRoot, BigInteger totalLiabilities,
                              BigInteger totalReserves) {}

    public record Result(Outcome outcome, String detail, Long period, BigInteger computedRoot,
                         Attestation attestation) {
        public boolean verified() {
            return outcome == Outcome.VERIFIED;
        }
    }

    private CustomerCheck() {}

    public static Result check(Inclusion in, Deployment d, ChainIndexer indexer) {
        return check(in, d, indexer, HISTORY_PAGE_SIZE);
    }

    public static Result check(Inclusion in, Deployment d, ChainIndexer indexer, int pageSize) {
        String inputError = inputError(in, d);
        if (inputError != null) return new Result(Outcome.BAD_INPUT, inputError, null, null, null);
        BigInteger root = recomputeRoot(in);

        long now;
        try {
            now = indexer.latestBlockTimeMs();
        } catch (Exception e) {
            return new Result(Outcome.INDEXER_UNAVAILABLE, "chain time: " + e.getMessage(), null, root, null);
        }
        if (now < d.genesisMs()) return new Result(Outcome.BEFORE_GENESIS, "no period has started", null, root, null);
        long period = new AttestationPeriods(d.genesisMs(), d.periodMs()).periodAt(now);
        String unit = AttestationPeriods.unit(d.policyId(), period);

        List<ChainIndexer.UtxoView> utxos;
        try {
            utxos = indexer.assetUtxos(unit, HISTORY_PAGE_SIZE);
        } catch (Exception e) {
            return new Result(Outcome.INDEXER_UNAVAILABLE, "token outputs: " + e.getMessage(), period, root, null);
        }
        if (utxos == null || utxos.isEmpty()) {
            return new Result(Outcome.NO_ATTESTATION, "no attestation token for period " + period, period, root, null);
        }
        if (utxos.size() != 1) {
            return new Result(Outcome.DUPLICATE_ATTESTATION, utxos.size() + " outputs hold the period's token", period, root, null);
        }
        var utxo = utxos.getFirst();
        BigInteger held = utxo.amounts() == null ? null : utxo.amounts().get(unit);
        if (held == null || held.compareTo(BigInteger.ONE) != 0) {
            return new Result(Outcome.DUPLICATE_ATTESTATION, "the output holds " + held + " of the token", period, root, null);
        }
        if (!atScriptAddress(utxo.address(), d.policyId())) {
            return new Result(Outcome.NOT_AT_SCRIPT_ADDRESS, "token output is not at the attestation script address",
                    period, root, null);
        }
        Attestation a = decodeDatum(utxo.inlineDatum());
        if (a == null) return new Result(Outcome.BAD_DATUM, "the inline datum is not an Attestation", period, root, null);
        if (a.period() != period) {
            return new Result(Outcome.WRONG_PERIOD, "datum period " + a.period() + " != " + period, period, root, a);
        }

        Outcome history = history(indexer, unit, pageSize);
        if (history != Outcome.VERIFIED) {
            String detail = history == Outcome.DUPLICATE_ATTESTATION
                    ? "the period's token was minted more than once"
                    : "the token's mint history is unavailable or incomplete";
            return new Result(history, detail, period, root, a);
        }
        if (!a.liabilitiesRoot().equals(root)) {
            return new Result(Outcome.ROOT_MISMATCH, "the attested root differs from your recomputed root", period, root, a);
        }
        return new Result(Outcome.VERIFIED, "included in the attested tree for period " + period, period, root, a);
    }

    /** {@code leaf = Poseidon(Poseidon(idTag, salt), balance)}, then up the path; bit i of the index is the side. */
    public static BigInteger recomputeRoot(Inclusion in) {
        BigInteger node = ReserveLeaves.leaf(ReserveLeaves.saltedId(in.accountId(), in.salt()), in.balance());
        long index = in.leafIndex();
        for (BigInteger sibling : in.siblings()) {
            node = (index & 1) == 0 ? ReserveLeaves.node(node, sibling) : ReserveLeaves.node(sibling, node);
            index >>= 1;
        }
        return node;
    }

    private static Outcome history(ChainIndexer indexer, String unit, int pageSize) {
        int mints = 0;
        int burns = 0;
        BigInteger minted = BigInteger.ZERO;
        boolean complete = false;
        try {
            for (int page = 1; page <= MAX_HISTORY_PAGES; page++) {
                List<ChainIndexer.HistoryEntry> entries = indexer.assetHistory(unit, page, pageSize);
                if (entries == null || entries.size() > pageSize) return Outcome.HISTORY_INCOMPLETE;
                for (var e : entries) {
                    if (e == null || e.quantity() == null || e.quantity().signum() == 0
                            || (e.unit() != null && !e.unit().equals(unit))) {
                        return Outcome.HISTORY_INCOMPLETE;
                    }
                    if (e.quantity().signum() > 0) {
                        mints++;
                        minted = minted.add(e.quantity());
                    } else {
                        burns++;
                    }
                }
                if (entries.size() < pageSize) {
                    complete = true;
                    break;
                }
            }
        } catch (Exception e) {
            return Outcome.HISTORY_INCOMPLETE;
        }
        if (!complete || mints == 0) return Outcome.HISTORY_INCOMPLETE;
        if (mints != 1 || minted.compareTo(BigInteger.ONE) != 0 || burns != 0) return Outcome.DUPLICATE_ATTESTATION;
        return Outcome.VERIFIED;
    }

    /** Header type 7 (script payment credential, no stake credential) and the policy id as the hash. */
    static boolean atScriptAddress(String bech32, String policyId) {
        try {
            byte[] bytes = new Address(bech32).getBytes();
            return bytes.length == 29 && ((bytes[0] & 0xff) >> 4) == 7
                    && Arrays.equals(Arrays.copyOfRange(bytes, 1, 29), HexUtil.decodeHexString(policyId));
        } catch (Exception e) {
            return false;
        }
    }

    /** {@code Constr 0 [I, I, I, I]} with the validator's ranges, or null. */
    static Attestation decodeDatum(String hex) {
        if (hex == null || hex.isEmpty()) return null;
        try {
            PlutusData d = PlutusData.deserialize(HexUtil.decodeHexString(hex));
            if (!(d instanceof ConstrPlutusData c) || c.getAlternative() != 0) return null;
            List<PlutusData> f = c.getData().getPlutusDataList();
            if (f.size() != 4) return null;
            BigInteger[] v = new BigInteger[4];
            for (int i = 0; i < 4; i++) {
                if (!(f.get(i) instanceof BigIntPlutusData b)) return null;
                v[i] = b.getValue();
            }
            if (!uint64(v[0]) || v[0].bitLength() > 63 || !inField(v[1]) || !uint64(v[2]) || !uint64(v[3])) return null;
            return new Attestation(v[0].longValueExact(), v[1], v[2], v[3]);
        } catch (Exception e) {
            return null;
        }
    }

    private static String inputError(Inclusion in, Deployment d) {
        if (in == null || d == null) return "missing input";
        if (d.policyId() == null || !POLICY.matcher(d.policyId()).matches()) return "policy id must be 56 lowercase hex characters";
        if (d.genesisMs() < 0 || d.periodMs() <= 0) return "invalid attestation clock";
        if (in.accountId() == null) return "missing account id";
        if (in.salt() == null || in.salt().signum() < 0 || in.salt().bitLength() > ReserveLeaves.SALT_BITS) return "invalid salt";
        if (!uint64(in.balance())) return "invalid balance";
        List<BigInteger> s = in.siblings();
        if (s == null || s.isEmpty() || s.size() > MAX_DEPTH) return "invalid path length";
        for (BigInteger x : s) if (!inField(x)) return "invalid sibling";
        if (in.leafIndex() < 0 || in.leafIndex() >= (1L << s.size())) return "leaf index out of range";
        return null;
    }

    private static boolean uint64(BigInteger v) {
        return v != null && v.signum() >= 0 && v.compareTo(UINT64) < 0;
    }

    private static boolean inField(BigInteger v) {
        return v != null && v.signum() >= 0 && v.compareTo(FR) < 0;
    }
}
