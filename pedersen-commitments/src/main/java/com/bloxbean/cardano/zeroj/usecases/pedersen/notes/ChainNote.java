package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.util.HexUtil;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A note as anyone reads it from the chain (ADR-0007 N2): the UTxO and its parsed datum. Only
 * <b>authenticated</b> notes are returned: at the ledger's exact address, holding exactly lovelace
 * and one note token, with a datum of exactly the note shape. Anything else paid to the address
 * (including the ledger's own reference-script output) is ignored.
 */
public record ChainNote(Utxo utxo, byte[] owner, BigInteger u, BigInteger v, long generation,
                        List<BigInteger> audit, List<byte[]> deliveries) {

    public String ref() {
        return utxo.getTxHash() + "#" + utxo.getOutputIndex();
    }

    /** Every authenticated note of {@code ledger} on chain. */
    public static List<ChainNote> all(BackendService backend, NoteLedgerScript ledger) {
        List<ChainNote> out = new ArrayList<>();
        try {
            for (int page = 1; ; page++) {
                var r = backend.getUtxoService().getUtxos(ledger.address(), 100, page);
                if (!r.isSuccessful() || r.getValue() == null || r.getValue().isEmpty()) break;
                for (Utxo u : r.getValue()) parse(u, ledger).ifPresent(out::add);
                if (r.getValue().size() < 100) break;
            }
        } catch (Exception e) {
            throw new IllegalStateException("could not read the ledger: " + e.getMessage(), e);
        }
        return out;
    }

    /** The authenticated notes among {@code utxos} (for example a transaction's outputs). */
    public static List<ChainNote> of(List<Utxo> utxos, NoteLedgerScript ledger) {
        List<ChainNote> out = new ArrayList<>();
        for (Utxo u : utxos) parse(u, ledger).ifPresent(out::add);
        return out;
    }

    /** The note in {@code utxo}, if it is an authenticated note of {@code ledger}. */
    public static Optional<ChainNote> parse(Utxo utxo, NoteLedgerScript ledger) {
        if (!ledger.address().equals(utxo.getAddress())) return Optional.empty();
        boolean oneToken = false;
        for (Amount a : utxo.getAmount()) {
            if (a.getUnit().equals("lovelace")) continue;
            if (oneToken || !a.getUnit().equals(ledger.unit()) || !a.getQuantity().equals(BigInteger.ONE)) {
                return Optional.empty();
            }
            oneToken = true;
        }
        if (!oneToken || utxo.getInlineDatum() == null || utxo.getInlineDatum().isEmpty()) return Optional.empty();
        try {
            var d = PlutusData.deserialize(HexUtil.decodeHexString(utxo.getInlineDatum()));
            if (!(d instanceof ConstrPlutusData c) || c.getAlternative() != 0) return Optional.empty();
            List<PlutusData> f = c.getData().getPlutusDataList();
            if (f.size() != 6) return Optional.empty();
            byte[] owner = ((BytesPlutusData) f.get(0)).getValue();
            List<BigInteger> audit = new ArrayList<>();
            for (PlutusData x : ((ListPlutusData) f.get(4)).getPlutusDataList()) audit.add(((BigIntPlutusData) x).getValue());
            List<byte[]> deliveries = new ArrayList<>();
            for (PlutusData x : ((ListPlutusData) f.get(5)).getPlutusDataList()) deliveries.add(((BytesPlutusData) x).getValue());
            if (owner.length != 28 || audit.size() != 8 || deliveries.size() != 2) return Optional.empty();
            return Optional.of(new ChainNote(utxo, owner, ((BigIntPlutusData) f.get(1)).getValue(),
                    ((BigIntPlutusData) f.get(2)).getValue(), ((BigIntPlutusData) f.get(3)).getValue().longValueExact(),
                    audit, deliveries));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
