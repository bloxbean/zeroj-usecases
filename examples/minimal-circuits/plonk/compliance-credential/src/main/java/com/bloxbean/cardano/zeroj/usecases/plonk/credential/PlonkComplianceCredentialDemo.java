package com.bloxbean.cardano.zeroj.usecases.plonk.credential;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.usecases.plonk.credential.service.PlonkCredentialOnChainService;
import com.bloxbean.cardano.zeroj.usecases.plonk.credential.service.PlonkCredentialProofService;
import com.bloxbean.cardano.zeroj.usecases.plonk.credential.service.YaciDevKit;

import java.math.BigDecimal;
import java.util.Arrays;

public final class PlonkComplianceCredentialDemo {
    private static final String DEFAULT_YACI_BASE_URL = "http://localhost:8080/api/v1/";
    private static final String DEFAULT_YACI_ADMIN_URL = "http://localhost:10000";
    private static final String YACI_MNEMONIC = "test test test test test test test test test test test test "
            + "test test test test test test test test test test test sauce";
    private static final int POT_POWER = 10;

    private PlonkComplianceCredentialDemo() {
    }

    public static void main(String[] args) throws Exception {
        boolean submitToYaci = Arrays.asList(args).contains("--yaci");
        var fixture = SampleComplianceCredential.validFixture();

        System.out.println("Compiling annotated BLS12-381 PlonK compliance credential circuit...");
        var prover = new PlonkCredentialProofService(POT_POWER);
        System.out.println("Circuit: " + fixture.inputs().schema().name());
        System.out.println("PlonK gates: " + prover.constraintSystem().numGates());
        System.out.println("Public inputs: " + fixture.inputs().publicValues());

        System.out.println("Generating Cardano-profile PlonK MPI proof...");
        var bundle = prover.prove(fixture.inputs());
        var offChain = prover.verifyOffChain(bundle);
        if (!offChain.proofValid()) {
            throw new IllegalStateException("Off-chain PlonK verification failed: " + offChain);
        }
        System.out.println("Off-chain PlonK verification: OK");

        if (!submitToYaci) {
            System.out.println("Run with --args='--yaci' to submit the PlonK verifier transaction to Yaci DevKit.");
            return;
        }

        var account = new Account(Networks.testnet(), YACI_MNEMONIC);
        System.out.println("Top-up Yaci admin address: " + account.baseAddress());
        YaciDevKit.topUp(yaciAdminUrl(), account.baseAddress(), BigDecimal.valueOf(1000));

        var backend = new BFBackendService(yaciBaseUrl(), "");
        var onChain = new PlonkCredentialOnChainService(backend, account);
        var result = onChain.verifyOnChain(bundle);
        System.out.println("On-chain PlonK verification: OK");
        System.out.println("Script address: " + result.scriptAddress());
        System.out.println("Lock tx: " + result.lockTxHash());
        System.out.println("Unlock tx: " + result.unlockTxHash());
    }

    private static String yaciBaseUrl() {
        String baseUrl = config("YACI_BASE_URL", DEFAULT_YACI_BASE_URL);
        return baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";
    }

    private static String yaciAdminUrl() {
        String adminUrl = config("YACI_ADMIN_URL", DEFAULT_YACI_ADMIN_URL);
        while (adminUrl.endsWith("/")) {
            adminUrl = adminUrl.substring(0, adminUrl.length() - 1);
        }
        return adminUrl;
    }

    private static String config(String key, String defaultValue) {
        String systemValue = System.getProperty(key);
        if (systemValue != null && !systemValue.isBlank()) {
            return systemValue;
        }
        String envValue = System.getenv(key);
        return envValue == null || envValue.isBlank() ? defaultValue : envValue;
    }
}
