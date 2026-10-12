package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory {@link CoSignGuard.Reservations} for tests: atomic per product, not durable. */
public final class MemoryReservations implements CoSignGuard.Reservations {

    private final Map<String, CoSignGuard.Reservation> map = new ConcurrentHashMap<>();

    @Override
    public boolean reserve(String serial, String txHash, long ttlSlot) {
        return map.putIfAbsent(serial, new CoSignGuard.Reservation(txHash, ttlSlot, false)) == null;
    }

    @Override
    public Optional<CoSignGuard.Reservation> find(String serial) {
        return Optional.ofNullable(map.get(serial));
    }

    @Override
    public void confirm(String serial, String txHash) {
        map.computeIfPresent(serial, (k, r) -> r.txHash().equals(txHash) ? new CoSignGuard.Reservation(txHash, r.ttlSlot(), true) : r);
    }

    @Override
    public void release(String serial, String txHash) {
        map.computeIfPresent(serial, (k, r) -> r.txHash().equals(txHash) && !r.confirmed() ? null : r);
    }
}
