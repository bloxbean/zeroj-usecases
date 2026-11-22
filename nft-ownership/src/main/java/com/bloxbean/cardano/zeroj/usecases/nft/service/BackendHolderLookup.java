package com.bloxbean.cardano.zeroj.usecases.nft.service;

import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.util.List;

/**
 * {@link HolderLookup} over the Blockfrost-compatible backend (Yaci Store on DevKit): the UTxOs
 * at the address that carry the unit, read across pages.
 */
@Component
public class BackendHolderLookup implements HolderLookup {

    private static final int PAGE_SIZE = 100;

    private final BackendService backendService;

    public BackendHolderLookup(BackendService backendService) {
        this.backendService = backendService;
    }

    @Override
    public BigInteger quantityAt(String address, String unit) throws Exception {
        BigInteger total = BigInteger.ZERO;
        for (int page = 1; ; page++) {
            var result = backendService.getUtxoService().getUtxos(address, unit, PAGE_SIZE, page);
            if (!result.isSuccessful()) {
                // An address without the unit answers "not found" on some indexers.
                if (page == 1 && result.code() == 404) return BigInteger.ZERO;
                throw new IllegalStateException("holder lookup failed: " + result.getResponse());
            }
            List<Utxo> utxos = result.getValue();
            if (utxos == null || utxos.isEmpty()) return total;
            for (Utxo utxo : utxos) {
                if (utxo.getAmount() == null) continue;
                for (Amount amount : utxo.getAmount()) {
                    if (unit.equals(amount.getUnit())) total = total.add(amount.getQuantity());
                }
            }
            if (utxos.size() < PAGE_SIZE) return total;
        }
    }
}
