package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.api.UtxoSupplier;
import com.bloxbean.cardano.client.api.common.OrderEnum;
import com.bloxbean.cardano.client.api.model.ProtocolParams;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.function.TxBuilderContext;
import com.bloxbean.cardano.client.transaction.spec.Transaction;
import com.bloxbean.cardano.client.transaction.spec.TransactionInput;
import com.bloxbean.cardano.client.transaction.util.TransactionUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The auditor's once-per-product rule at signing time (ADR-0009 D1): concurrent or retried
 * co-sign requests yield at most one signature; a reservation is released only after its TTL
 * when its transaction is not on chain; a non-empty or unavailable mint history refuses.
 */
class CoSignGuardTest {

    /** A chain the test controls. */
    static final class StubChain implements CoSignGuard.Chain {
        final List<PassportReader.MintEvent> history = new ArrayList<>();
        final Set<String> onChain = new HashSet<>();
        long slot = 500;
        boolean unavailable;

        @Override
        public List<PassportReader.MintEvent> mintHistory(byte[] productId) {
            if (unavailable) throw new IllegalStateException("mint history unavailable");
            return history;
        }

        @Override
        public boolean txOnChain(String txHash) {
            if (unavailable) throw new IllegalStateException("indexer unavailable");
            return onChain.contains(txHash);
        }

        @Override
        public long currentSlot() {
            return slot;
        }
    }

    @Test
    @DisplayName("Two concurrent co-sign requests for one product: exactly one is authorised")
    void concurrentRequests() throws Exception {
        try (ExecutorService pool = Executors.newFixedThreadPool(2)) {
            for (int round = 0; round < 50; round++) {
                var f = new PassportTxFixture("BAT-SN001");
                var guard = new CoSignGuard(new MemoryReservations(), new StubChain());
                Transaction a = tx(f, 1_000);
                Transaction b = tx(f, 1_001);
                CountDownLatch start = new CountDownLatch(1);
                AtomicInteger authorised = new AtomicInteger();
                List<Future<?>> futures = new ArrayList<>();
                for (Transaction t : List.of(a, b)) {
                    futures.add(pool.submit(() -> {
                        start.await();
                        try {
                            guard.authorize(f.serial, f.script, f.expected, t, f.addressOf());
                            authorised.incrementAndGet();
                        } catch (IllegalStateException refused) {
                            // the other request holds the reservation
                        }
                        return null;
                    }));
                }
                start.countDown();
                for (Future<?> fu : futures) fu.get();
                assertEquals(1, authorised.get(), "round " + round);
            }
        }
    }

    @Test
    @DisplayName("A retry after an unknown outcome gets no second signature until the TTL has passed off-chain")
    void retryAfterTimeout() {
        var f = new PassportTxFixture("BAT-SN001");
        var chain = new StubChain();
        var reservations = new MemoryReservations();
        var guard = new CoSignGuard(reservations, chain);
        Transaction first = tx(f, 1_000);
        guard.authorize(f.serial, f.script, f.expected, first, f.addressOf());
        // The submission timed out: the outcome is unknown. Neither a new transaction nor the same one is signed again.
        assertThrows(IllegalStateException.class, () -> guard.authorize(f.serial, f.script, f.expected, tx(f, 1_100), f.addressOf()));
        assertThrows(IllegalStateException.class, () -> guard.authorize(f.serial, f.script, f.expected, first, f.addressOf()));
        // Still within the TTL: still refused.
        chain.slot = 1_000;
        assertThrows(IllegalStateException.class, () -> guard.authorize(f.serial, f.script, f.expected, tx(f, 1_100), f.addressOf()));
        // The TTL has passed and the transaction never reached the chain: released, and a new one is signed.
        chain.slot = 1_001;
        assertDoesNotThrow(() -> guard.authorize(f.serial, f.script, f.expected, tx(f, 2_000), f.addressOf()));
    }

    @Test
    @DisplayName("A reserved transaction that reached the chain is confirmed and never released")
    void landedTransactionIsConfirmed() {
        var f = new PassportTxFixture("BAT-SN001");
        var chain = new StubChain();
        var reservations = new MemoryReservations();
        var guard = new CoSignGuard(reservations, chain);
        Transaction first = tx(f, 1_000);
        guard.authorize(f.serial, f.script, f.expected, first, f.addressOf());
        chain.onChain.add(TransactionUtil.getTxHash(first));
        chain.slot = 5_000;   // long after the TTL
        assertThrows(IllegalStateException.class, () -> guard.authorize(f.serial, f.script, f.expected, tx(f, 6_000), f.addressOf()));
        assertTrue(reservations.find(f.serial).orElseThrow().confirmed());
    }

    @Test
    @DisplayName("A product with a passport in the mint history is refused even with no local record (lost database)")
    void mintHistoryRefuses() {
        var f = new PassportTxFixture("BAT-SN001");
        var chain = new StubChain();
        chain.history.add(new PassportReader.MintEvent("tx", BigInteger.ONE));
        var reservations = new MemoryReservations();
        var guard = new CoSignGuard(reservations, chain);
        assertThrows(IllegalStateException.class, () -> guard.authorize(f.serial, f.script, f.expected, tx(f, 1_000), f.addressOf()));
        // Revoked (minted once, burned once): still refused, a second passport would be a duplicate.
        chain.history.add(new PassportReader.MintEvent("tx2", BigInteger.ONE.negate()));
        assertThrows(IllegalStateException.class, () -> guard.authorize(f.serial, f.script, f.expected, tx(f, 1_000), f.addressOf()));
        assertTrue(reservations.find(f.serial).isEmpty(), "no reservation taken");
    }

    @Test
    @DisplayName("An unavailable chain fails closed, and a transaction without a TTL is refused")
    void failsClosed() {
        var f = new PassportTxFixture("BAT-SN001");
        var chain = new StubChain();
        chain.unavailable = true;
        var reservations = new MemoryReservations();
        var guard = new CoSignGuard(reservations, chain);
        assertThrows(IllegalStateException.class, () -> guard.authorize(f.serial, f.script, f.expected, tx(f, 1_000), f.addressOf()));
        assertTrue(reservations.find(f.serial).isEmpty());
        chain.unavailable = false;
        assertThrows(IllegalStateException.class, () -> guard.authorize(f.serial, f.script, f.expected, tx(f, 0), f.addressOf()));
    }

    @Test
    @DisplayName("The signer signs once, resolving inputs through the builder's UTxO supplier")
    void signerSignsOnce() {
        var f = new PassportTxFixture("BAT-SN001");
        var guard = new CoSignGuard(new MemoryReservations(), new StubChain());
        var signer = guard.signer(f.auditor, f.serial, f.script, f.expected);
        UtxoSupplier supplier = new UtxoSupplier() {
            @Override
            public List<Utxo> getPage(String address, Integer nrOfItems, Integer page, OrderEnum order) {
                return List.of();
            }

            @Override
            public Optional<Utxo> getTxOutput(String txHash, int outputIndex) {
                return f.addressOf().apply(new TransactionInput(txHash, outputIndex))
                        .map(at -> Utxo.builder().txHash(txHash).outputIndex(outputIndex).address(at).build());
            }
        };
        TxBuilderContext context = TxBuilderContext.init(supplier, new ProtocolParams());
        Transaction signed = signer.sign(context, tx(f, 1_000));
        assertEquals(1, signed.getWitnessSet().getVkeyWitnesses().size());
        assertThrows(IllegalStateException.class, () -> signer.sign(context, tx(f, 1_001)));
        assertFalse(signed.getWitnessSet().getVkeyWitnesses().isEmpty());
    }

    private static Transaction tx(PassportTxFixture f, long ttl) {
        var body = f.body();
        body.ttl = ttl;
        return body.build();
    }
}
