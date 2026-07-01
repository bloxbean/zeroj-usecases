package com.bloxbean.cardano.zeroj.usecases.plonk.reserves;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.usecases.plonk.reserves.service.PlonkReserveOnChainService;
import com.bloxbean.cardano.zeroj.usecases.plonk.reserves.service.PlonkReserveProofService;
import com.bloxbean.cardano.zeroj.usecases.plonk.reserves.service.YaciDevKit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class PlonkReserveYaciE2ETest {
    private static final String YACI_BASE_URL = "http://localhost:8080/api/v1/";
    private static final String YACI_ADMIN_URL = "http://localhost:10000";
    private static final String YACI_MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";

    @Test
    @EnabledIfEnvironmentVariable(named = "ZEROJ_YACI_E2E", matches = "true")
    void verifiesReserveProofOnYaciDevKit() throws Exception {
        var account = new Account(Networks.testnet(), YACI_MNEMONIC);
        YaciDevKit.topUp(YACI_ADMIN_URL, account.baseAddress(), BigDecimal.valueOf(1000));

        var prover = new PlonkReserveProofService(SampleReserveStatement.ACCOUNT_COUNT, 10);
        var bundle = prover.prove(SampleReserveStatement.solventFixture().inputs());
        var backend = new BFBackendService(YACI_BASE_URL, "");
        var service = new PlonkReserveOnChainService(backend, account);

        var result = service.verifyOnChain(bundle);

        assertNotNull(result.lockTxHash());
        assertNotNull(result.unlockTxHash());
    }
}
