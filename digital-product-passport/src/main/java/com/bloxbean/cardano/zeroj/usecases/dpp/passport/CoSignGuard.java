package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.function.TxSigner;
import com.bloxbean.cardano.client.transaction.spec.Transaction;
import com.bloxbean.cardano.client.transaction.spec.TransactionInput;
import com.bloxbean.cardano.client.transaction.util.TransactionUtil;

import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * The auditor's once-per-product rule (ADR-0009 D1 uniqueness), enforced at the moment of
 * signing, with the reservation pattern of the airdrop's paid-nullifier ledger:
 * <ol>
 *   <li>check the finished transaction against the auditor's report
 *       ({@link PassportTransactions#check}), and require a finite validity upper bound (TTL);</li>
 *   <li>refuse unless the policy's mint history for the product is empty
 *       ({@link PassportReader.Status#NONE}); an unavailable history fails closed, which also
 *       covers a lost local database;</li>
 *   <li>atomically reserve the product for this transaction's body hash (a compare-and-set that
 *       succeeds only if no reservation exists); only then sign.</li>
 * </ol>
 * A reservation is never released early. Before a new attempt, an old reservation is reconciled
 * against the chain: if its transaction is on chain it is confirmed (and the product stays
 * co-signed); if it is not, it is released only after its TTL has passed, when the ledger can no
 * longer accept it. A submission whose outcome is unknown (a timeout, a lost response) therefore
 * keeps the product reserved, and a retry cannot obtain a second signature.
 */
public final class CoSignGuard {

    /** The auditor's durable reservations, one per product; every operation is atomic. */
    public interface Reservations {
        /** Reserves {@code serial} for {@code txHash} if it holds no reservation; true if reserved now. */
        boolean reserve(String serial, String txHash, long ttlSlot);

        Optional<Reservation> find(String serial);

        void confirm(String serial, String txHash);

        /** Releases the reservation if it still holds {@code txHash} and is not confirmed. */
        void release(String serial, String txHash);
    }

    public record Reservation(String txHash, long ttlSlot, boolean confirmed) {}

    /** What the auditor reads from the chain. Any failure throws, so the guard fails closed. */
    public interface Chain {
        List<PassportReader.MintEvent> mintHistory(byte[] productId);

        boolean txOnChain(String txHash);

        long currentSlot();
    }

    private final Reservations reservations;
    private final Chain chain;

    public CoSignGuard(Reservations reservations, Chain chain) {
        this.reservations = reservations;
        this.chain = chain;
    }

    /**
     * The auditor's signer for one product's passport transaction. Inputs are resolved to their
     * addresses through the builder's UTxO supplier; an unresolvable input is refused.
     */
    public TxSigner signer(Account auditor, String serial, PassportScript script, PassportDatum expected) {
        return (context, transaction) -> {
            authorize(serial, script, expected, transaction, input -> context.getUtxoSupplier()
                    .getTxOutput(input.getTransactionId(), input.getIndex()).map(Utxo::getAddress));
            return auditor.sign(transaction);
        };
    }

    /** Steps 1–3 above; throws {@link IllegalStateException} instead of authorising. */
    public void authorize(String serial, PassportScript script, PassportDatum expected, Transaction transaction,
                          Function<TransactionInput, Optional<String>> addressOf) {
        PassportTransactions.check(transaction, script, expected, addressOf);
        long ttl = transaction.getBody().getTtl();
        if (ttl <= 0) throw new IllegalStateException("auditor refuses to co-sign: the transaction has no TTL");
        reconcile(serial);
        PassportReader.Status status = PassportReader.status(chain.mintHistory(expected.productId()));
        if (status != PassportReader.Status.NONE) {
            throw new IllegalStateException("auditor refuses to co-sign: the policy's mint history for " + serial
                    + " is " + status);
        }
        String hash = TransactionUtil.getTxHash(transaction);
        if (!reservations.reserve(serial, hash, ttl)) {
            throw new IllegalStateException("auditor refuses to co-sign: it already co-signed, or is co-signing, a passport for "
                    + serial + " (" + reservations.find(serial).map(Reservation::txHash).orElse("?") + ")");
        }
    }

    /**
     * Brings a product's reservation up to date with the chain: confirms it if its transaction is
     * on chain, releases it if its TTL has passed and it is not, and otherwise leaves it.
     */
    public void reconcile(String serial) {
        Optional<Reservation> r = reservations.find(serial);
        if (r.isEmpty() || r.get().confirmed()) return;
        if (chain.txOnChain(r.get().txHash())) {
            reservations.confirm(serial, r.get().txHash());
        } else if (chain.currentSlot() > r.get().ttlSlot() && !chain.txOnChain(r.get().txHash())) {
            reservations.release(serial, r.get().txHash());
        }
    }

    /** Called after a successful submission and confirmation. */
    public void confirmed(String serial, String txHash) {
        reservations.confirm(serial, txHash);
    }
}
