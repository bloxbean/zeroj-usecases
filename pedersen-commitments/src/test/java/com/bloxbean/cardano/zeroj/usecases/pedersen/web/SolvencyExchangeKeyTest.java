package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.zeroj.usecases.pedersen.common.RoleWallet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0009 D11 for the solvency exchange: the service loads its persisted key before serving, so
 * a restart keeps the vault parameter, and a lost key with deployment state stops the service.
 */
class SolvencyExchangeKeyTest {

    @TempDir
    Path dir;

    @Test
    @DisplayName("The exchange key survives a restart; a deleted key with deployment state fails closed")
    void exchangeKeyLifecycle() throws Exception {
        byte[] first = start().exchangeKeyHash();
        assertArrayEquals(first, start().exchangeKeyHash(), "a restart keeps the exchange (the vault's parameter)");

        Files.delete(RoleWallet.keyFile(dir, SolvencyService.EXCHANGE_ROLE));
        assertThrows(IllegalStateException.class, this::start);
        assertFalse(Files.exists(RoleWallet.keyFile(dir, SolvencyService.EXCHANGE_ROLE)), "no new key");
    }

    /** One app start: the service with the data directory Spring would inject, after its post-construct. */
    private SolvencyService start() throws Exception {
        var service = new SolvencyService(null, null);
        var field = SolvencyService.class.getDeclaredField("dataDir");
        field.setAccessible(true);
        field.set(service, dir.toString());
        service.loadExchangeKey();
        return service;
    }
}
