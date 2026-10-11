package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.reserves.config.CustodianKeyStore;
import com.bloxbean.cardano.zeroj.usecases.reserves.config.DeploymentState;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0009 D11 for the attestation deployment: a restart reproduces the deployed policy, and state
 * that the current key or verification key cannot reproduce stops startup.
 */
class ReserveDeploymentTest {

    @TempDir
    static Path setupDir;

    private static final long CHAIN_TIP_MS = 1_790_000_000_000L;
    private static ReserveCircuitService circuit;

    @TempDir
    Path dir;

    @BeforeAll
    static void setup() {
        circuit = new ReserveCircuitService();
        ReflectionTestUtils.setField(circuit, "treeDepth", 1);
        ReflectionTestUtils.setField(circuit, "potPower", 12);
        ReflectionTestUtils.setField(circuit, "dataDir", setupDir.toString());
        circuit.init();
    }

    private OnChainReserveService service(Account custodian, long periodMs) throws Exception {
        var s = new OnChainReserveService(null, custodian, circuit, dir.toString(), periodMs,
                "http://localhost:1/", "http://localhost:1", false);
        s.useGenesisClock(() -> CHAIN_TIP_MS);
        s.initialize();
        return s;
    }

    @Test
    void restartReproducesTheDeployment() throws Exception {
        Account custodian = CustodianKeyStore.loadOrCreate(dir, Networks.testnet(), new SecureRandom());
        var first = service(custodian, 300_000L);
        var state = DeploymentState.read(dir);
        assertEquals(first.getPolicyId(), state.policyId());
        assertEquals(CustodianKeyStore.keyHash(custodian), state.custodianPkh());
        assertEquals(CHAIN_TIP_MS, state.genesisMs(), "genesis comes from the chain tip");

        Account reloaded = CustodianKeyStore.loadOrCreate(dir, Networks.testnet(), new SecureRandom());
        // A changed period setting does not change a deployed script.
        var second = service(reloaded, 60_000L);
        assertEquals(first.getPolicyId(), second.getPolicyId());
        assertEquals(300_000L, second.deployment().periodMs());
    }

    @Test
    void stateThatDoesNotReproduceThePolicyFailsClosed() throws Exception {
        Account custodian = CustodianKeyStore.loadOrCreate(dir, Networks.testnet(), new SecureRandom());
        var deployed = service(custodian, 300_000L).deployment();
        new DeploymentState(deployed.custodianPkh(), deployed.genesisMs() + 1, deployed.periodMs(), deployed.policyId())
                .write(dir);
        assertThrows(IllegalStateException.class, () -> service(custodian, 300_000L));
        new DeploymentState(deployed.custodianPkh(), deployed.genesisMs(), deployed.periodMs(), "00".repeat(28)).write(dir);
        assertThrows(IllegalStateException.class, () -> service(custodian, 300_000L));
    }

    @Test
    void anotherKeyCannotTakeOverTheDeployment() throws Exception {
        Account custodian = CustodianKeyStore.loadOrCreate(dir, Networks.testnet(), new SecureRandom());
        service(custodian, 300_000L);
        Account stranger = new Account(Networks.testnet());
        assertThrows(IllegalStateException.class, () -> service(stranger, 300_000L));
    }

    @Test
    void periodTokenNamesAreEightByteBigEndian() {
        assertEquals("0000000000000000", hex(AttestationPeriods.tokenName(0)));
        assertEquals("000000000000000c", hex(AttestationPeriods.tokenName(12)));
        assertEquals("7fffffffffffffff", hex(AttestationPeriods.tokenName(Long.MAX_VALUE)));
        var clock = new AttestationPeriods(1_000L, 300L);
        assertEquals(0, clock.periodAt(1_000L));
        assertEquals(0, clock.periodAt(1_299L));
        assertEquals(1, clock.periodAt(1_300L));
        assertEquals(1_300L, clock.end(0));
        assertThrows(IllegalArgumentException.class, () -> clock.periodAt(999L));
        assertThrows(IllegalArgumentException.class, () -> new AttestationPeriods(0, 0));
    }

    private static String hex(byte[] b) {
        return HexUtil.encodeHexString(b);
    }
}
