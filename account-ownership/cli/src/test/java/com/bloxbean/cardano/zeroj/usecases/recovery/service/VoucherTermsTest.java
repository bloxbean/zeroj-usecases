package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.util.HexUtil;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Voucher creation refuses terms the validator would reject (ADR-0009 D6). */
class VoucherTermsTest {

    private static final long VOUCHER = 10_000_000L;
    private static final long MIN_UTXO = 1_100_000L;

    @Test
    void demo_terms_leave_a_spendable_remainder() {
        assertEquals(6_000_000L, OnChainOwnershipService.checkVoucherTerms(VOUCHER,
                OnChainOwnershipService.DEMO_REFUND_LOVELACE, OnChainOwnershipService.DEMO_MAX_FEE_LOVELACE, MIN_UTXO));
    }

    @Test
    void zero_remainder_is_allowed() {
        assertEquals(0L, OnChainOwnershipService.checkVoucherTerms(VOUCHER, 8_000_000L, 2_000_000L, MIN_UTXO));
    }

    @Test
    void positive_remainder_below_min_utxo_is_refused() {
        assertThrows(IllegalArgumentException.class,
                () -> OnChainOwnershipService.checkVoucherTerms(VOUCHER, 7_000_000L, 2_000_000L, MIN_UTXO));
        assertEquals(MIN_UTXO, OnChainOwnershipService.checkVoucherTerms(VOUCHER, 2_000_000L,
                VOUCHER - 2_000_000L - MIN_UTXO, MIN_UTXO));
    }

    @Test
    void out_of_range_terms_are_refused() {
        assertThrows(IllegalArgumentException.class,
                () -> OnChainOwnershipService.checkVoucherTerms(VOUCHER, -1, 2_000_000L, MIN_UTXO));
        assertThrows(IllegalArgumentException.class,
                () -> OnChainOwnershipService.checkVoucherTerms(VOUCHER, 2_000_000L, -1, MIN_UTXO));
        assertThrows(IllegalArgumentException.class,
                () -> OnChainOwnershipService.checkVoucherTerms(VOUCHER, 8_000_001L, 2_000_000L, MIN_UTXO));
    }

    @Test
    void tag_is_the_outref_as_data() {
        String txHash = "ab".repeat(32);
        var tag = OnChainOwnershipService.outRefTag(txHash, 3);
        assertEquals(0, tag.getAlternative());
        assertArrayEquals(HexUtil.decodeHexString(txHash),
                ((BytesPlutusData) tag.getData().getPlutusDataList().get(0)).getValue());
        assertEquals(BigInteger.valueOf(3), ((BigIntPlutusData) tag.getData().getPlutusDataList().get(1)).getValue());
    }
}
