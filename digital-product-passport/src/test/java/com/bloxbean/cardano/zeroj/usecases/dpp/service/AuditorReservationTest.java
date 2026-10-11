package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.client.transaction.spec.Transaction;
import com.bloxbean.cardano.client.transaction.util.TransactionUtil;
import com.bloxbean.cardano.zeroj.usecases.dpp.DppSpringTestBase;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.AuditRecordRepository;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.CoSignGuard;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportReader;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportTxFixture;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.RoleKeys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The auditor's reservation in its database (ADR-0009 D1): concurrent co-sign requests for one
 * product race on one atomic update, and exactly one wins; a retry gets no second signature.
 */
class AuditorReservationTest extends DppSpringTestBase {

    @Autowired AuditorService auditorService;
    @Autowired ProductService productService;
    @Autowired OnChainDppService onChainService;
    @Autowired AuditRecordRepository records;
    @Autowired RoleKeys roleKeys;

    /** No passport on chain, nothing confirmed, well within every TTL. */
    private static final CoSignGuard.Chain EMPTY_CHAIN = new CoSignGuard.Chain() {
        @Override public List<PassportReader.MintEvent> mintHistory(byte[] productId) { return List.of(); }
        @Override public boolean txOnChain(String txHash) { return false; }
        @Override public long currentSlot() { return 10; }
    };

    @Test
    @DisplayName("Two concurrent co-sign requests: exactly one reserves the product; a retry is refused")
    void concurrentCoSign() throws Exception {
        String serial = "BAT-SN002";
        auditorService.attest(productService.find(serial).orElseThrow());
        var f = new PassportTxFixture(serial, roleKeys.manufacturer(), roleKeys.auditor(), onChainService.script(),
                auditorService.expectedDatum(serial, RoleKeys.pkh(roleKeys.manufacturer())));
        CoSignGuard guard = auditorService.guard(EMPTY_CHAIN);
        List<Transaction> txs = List.of(tx(f, 1_000), tx(f, 1_001), tx(f, 1_002), tx(f, 1_003));
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger authorised = new AtomicInteger();
        List<String> winners = new ArrayList<>();
        try (ExecutorService pool = Executors.newFixedThreadPool(txs.size())) {
            List<Future<?>> futures = new ArrayList<>();
            for (Transaction t : txs) {
                futures.add(pool.submit(() -> {
                    start.await();
                    try {
                        guard.authorize(serial, f.script, f.expected, t, f.addressOf());
                        authorised.incrementAndGet();
                        synchronized (winners) { winners.add(TransactionUtil.getTxHash(t)); }
                    } catch (IllegalStateException refused) {
                        // another request holds the reservation
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> fu : futures) fu.get();
        }
        assertEquals(1, authorised.get());
        assertEquals(winners.get(0), records.findById(serial).orElseThrow().getCosignedTx());
        // A retry (the first submission's outcome unknown) is refused.
        assertThrows(IllegalStateException.class, () -> guard.authorize(serial, f.script, f.expected, tx(f, 1_100), f.addressOf()));
    }

    private static Transaction tx(PassportTxFixture f, long ttl) {
        var body = f.body();
        body.ttl = ttl;
        return body.build();
    }
}
