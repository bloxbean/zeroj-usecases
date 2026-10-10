package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import org.julclang.core.PlutusData;

/** A registry entry as Julc data, for VM tests outside this package. */
public final class RegistryTestData {

    private RegistryTestData() {}

    public static PlutusData datum(RegistryEntry entry) {
        return AuditorRegistryVmTest.datum(entry);
    }
}
