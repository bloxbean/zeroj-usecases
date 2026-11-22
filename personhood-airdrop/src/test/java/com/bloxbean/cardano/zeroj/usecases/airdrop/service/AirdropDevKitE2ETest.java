package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.address.Credential;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.exception.TxBuildException;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The airdrop on Yaci DevKit (ADR-0009 D3, milestone M3):
 * <ol>
 *   <li>the faucet deploys with a fresh admin key and a seed outref from it;</li>
 *   <li>Alice enrols with a holder-chosen identifier and claims to a fresh key address, which
 *       receives the payout;</li>
 *   <li>a second claim with her nullifier is refused, also after a restart, and also by a
 *       faucet that lost its paid-nullifier record (the on-chain receipt check);</li>
 *   <li>a direct replay that spends a faucet-owned input without the admin's signature is
 *       refused by the ledger;</li>
 *   <li>a receipt sent to the receipt script with a stake credential is refused by the policy;</li>
 *   <li>a replay that re-mints a receipt with the claimant's own funds succeeds (receipt
 *       uniqueness on-chain is deferred), but takes no faucet payout.</li>
 * </ol>
 *
 * <p>Runs only with {@code ZEROJ_YACI_E2E=true} and DevKit reachable.
 */
class AirdropDevKitE2ETest {

    private static final String STORE_URL = env("ZEROJ_YACI_STORE_URL", "http://localhost:8080/api/v1/");
    private static final String ADMIN_URL = env("ZEROJ_YACI_ADMIN_URL", "http://localhost:10000");

    @Test
    void airdropOnDevKit(@TempDir Path dir) throws Exception {
        assumeTrue(Boolean.getBoolean("zeroj.yaci.e2e") && reachable(), "Set ZEROJ_YACI_E2E=true with DevKit running");
        BackendService backend = new BFBackendService(STORE_URL, "");
        var prover = new AirdropProofService(14, Path.of("build", "airdrop-test-setup").toString());
        prover.init();

        var data = new AirdropDataDir(dir);
        var keys = new AirdropKeys(data);
        var issuer = new PersonhoodIssuerService(keys, data);
        var wallet = new HolderWallet(issuer, data);
        var faucet = new OnChainAirdropService(backend, keys, prover, issuer, new PaidNullifierLedger(data), data,
                1, 2, true, ADMIN_URL, 1000, "", STORE_URL);
        faucet.initialize();
        assertNotNull(faucet.getPolicyId(), "the faucet deployed");
        assertTrue(Files.exists(data.deployment()));

        // Alice enrols and claims to a fresh key address.
        var alice = wallet.enroll("Alice");
        var recipient = new Account(Networks.testnet());
        byte[] recipientPkh = OnChainAirdropService.recipientKeyHash(recipient.baseAddress());
        BigInteger epoch = faucet.getPolicyEpoch();
        var claim = prover.prove(issuer.publicKey(), alice.signature(), alice.personhoodId(), epoch,
                new BigInteger(1, recipientPkh));
        String tx = faucet.submitClaim(claim.proof(), claim.nullifier(), recipient.baseAddress());
        waitForTx(backend, tx);
        assertTrue(lovelaceAt(backend, recipient.baseAddress()) >= faucet.getPayoutLovelace(), "the recipient was paid");

        // Same nullifier again: refused, also after a restart.
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class,
                () -> faucet.submitClaim(claim.proof(), claim.nullifier(), recipient.baseAddress()));
        var restarted = new OnChainAirdropService(backend, new AirdropKeys(new AirdropDataDir(dir)), prover,
                new PersonhoodIssuerService(new AirdropKeys(new AirdropDataDir(dir)), new AirdropDataDir(dir)),
                new PaidNullifierLedger(new AirdropDataDir(dir)), new AirdropDataDir(dir), 1, 2, false, ADMIN_URL, 0, "", STORE_URL);
        restarted.initialize();
        assertEquals(faucet.getPolicyId(), restarted.getPolicyId());
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class,
                () -> restarted.submitClaim(claim.proof(), claim.nullifier(), recipient.baseAddress()));

        // A faucet whose paid-nullifier record is gone still refuses: the receipt's mint history
        // (Yaci Store assets/{unit}/history) shows it was minted.
        Path forgetful = dir.resolve("forgetful");
        Files.createDirectories(forgetful);
        for (Path p : List.of(data.issuerKey(), data.adminKey(), data.deployment())) {
            Files.copy(p, forgetful.resolve(p.getFileName()));
        }
        var fData = new AirdropDataDir(forgetful);
        var fKeys = new AirdropKeys(fData);
        var fFaucet = new OnChainAirdropService(backend, fKeys, prover, new PersonhoodIssuerService(fKeys, fData),
                new PaidNullifierLedger(fData), fData, 1, 2, false, ADMIN_URL, 0, "", STORE_URL);
        fFaucet.initialize();
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class,
                () -> fFaucet.submitClaim(claim.proof(), claim.nullifier(), recipient.baseAddress()));

        // Mallory replays Alice's claim.
        var mallory = new Account(Networks.testnet());
        topUp(mallory.baseAddress(), 100);
        var compressed = ProverToCardano.compressProof(claim.proof());

        // (a) spending a faucet-owned input without the admin's signature: refused by the ledger.
        List<Utxo> adminUtxos = utxos(backend, keys.admin().baseAddress());
        Utxo faucetInput = adminUtxos.getFirst();
        var direct = new QuickTxBuilder(backend)
                .compose(faucet.claimTx(compressed, claim.nullifier(), recipientPkh, recipient.baseAddress())
                        .collectFrom(faucetInput))
                .withTxEvaluator(LocalJulcEvaluator.create(backend))
                .withSigner(SignerProviders.signerFrom(mallory))
                .feePayer(mallory.baseAddress())
                .collateralPayer(mallory.baseAddress())
                .complete();
        System.out.println("Direct replay without the admin's signature: " + direct.getResponse());
        assertFalse(direct.isSuccessful(), "a replay spending the faucet's input without its key must be refused");
        Thread.sleep(3_000);
        assertTrue(outrefs(utxos(backend, keys.admin().baseAddress())).contains(outref(faucetInput)),
                "the faucet's input is still unspent");

        // (b) a receipt at the receipt script with a stake credential: refused by the policy, so
        //     every receipt sits at the one receipt address.
        String stakedReceipt = AddressProvider.getBaseAddress(
                Credential.fromScript(faucet.mintingScript().getScriptHash()),
                Credential.fromKey(mallory.stakeHdKeyPair().getPublicKey().getKeyHash()), Networks.testnet()).toBech32();
        // The policy refuses it while the transaction is built (local evaluation of Mint[0]), so the
        // builder throws instead of returning a failed result; either form counts as a refusal.
        try {
            var staked = new QuickTxBuilder(backend)
                    .compose(faucet.claimTx(compressed, claim.nullifier(), recipientPkh, recipient.baseAddress(), stakedReceipt))
                    .withTxEvaluator(LocalJulcEvaluator.create(backend))
                    .withSigner(SignerProviders.signerFrom(mallory))
                    .feePayer(mallory.baseAddress())
                    .collateralPayer(mallory.baseAddress())
                    .complete();
            System.out.println("Receipt with a stake credential: " + staked.getResponse());
            assertFalse(staked.isSuccessful(), "a receipt outside the exact receipt address must be refused");
        } catch (TxBuildException e) {
            String why = String.valueOf(e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
            System.out.println("Receipt with a stake credential, refused at evaluation: " + why.lines().findFirst().orElse(""));
            assertTrue(why.contains("Mint[0]"), "the faucet policy must be the script that refused it: " + why);
        }

        // (c) re-minting a receipt with Mallory's own funds: possible, but no faucet payout.
        Set<String> adminBefore = outrefs(utxos(backend, keys.admin().baseAddress()));
        var ownFunds = new QuickTxBuilder(backend)
                .compose(faucet.claimTx(compressed, claim.nullifier(), recipientPkh, recipient.baseAddress()))
                .withTxEvaluator(LocalJulcEvaluator.create(backend))
                .withSigner(SignerProviders.signerFrom(mallory))
                .feePayer(mallory.baseAddress())
                .collateralPayer(mallory.baseAddress())
                .complete();
        assertTrue(ownFunds.isSuccessful(), "receipt uniqueness on-chain is deferred: " + ownFunds.getResponse());
        waitForTx(backend, ownFunds.getValue());
        assertEquals(adminBefore, outrefs(utxos(backend, keys.admin().baseAddress())),
                "the replay took nothing from the faucet");
        assertThrows(PaidNullifierLedger.AlreadyPaidException.class,
                () -> faucet.submitClaim(claim.proof(), claim.nullifier(), recipient.baseAddress()));
        System.out.println("Airdrop on DevKit: policy " + faucet.getPolicyId() + ", claim " + tx
                + ", own-funds replay " + ownFunds.getValue());
    }

    private static List<Utxo> utxos(BackendService backend, String address) throws Exception {
        List<Utxo> out = new ArrayList<>();
        for (int page = 1; ; page++) {
            var result = backend.getUtxoService().getUtxos(address, 100, page);
            if (!result.isSuccessful() || result.getValue() == null || result.getValue().isEmpty()) break;
            out.addAll(result.getValue());
            if (result.getValue().size() < 100) break;
        }
        return out;
    }

    private static long lovelaceAt(BackendService backend, String address) throws Exception {
        long total = 0;
        for (Utxo u : utxos(backend, address)) {
            for (var a : u.getAmount()) {
                if (a.getUnit().equals("lovelace")) total += a.getQuantity().longValueExact();
            }
        }
        return total;
    }

    private static Set<String> outrefs(List<Utxo> utxos) {
        return utxos.stream().map(AirdropDevKitE2ETest::outref).collect(Collectors.toSet());
    }

    private static String outref(Utxo u) {
        return u.getTxHash() + "#" + u.getOutputIndex();
    }

    private static void waitForTx(BackendService backend, String txHash) throws InterruptedException {
        for (int i = 0; i < 40; i++) {
            Thread.sleep(1_500);
            try {
                var r = backend.getTransactionService().getTransaction(txHash);
                if (r.isSuccessful() && r.getValue() != null) return;
            } catch (Exception ignored) {
                // not indexed yet
            }
        }
        throw new IllegalStateException("transaction not confirmed: " + txHash);
    }

    private static void topUp(String address, int ada) throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create(ADMIN_URL + "/local-cluster/api/addresses/topup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"address\":\"" + address + "\",\"adaAmount\":" + ada + "}"))
                .build();
        HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        Thread.sleep(3_000);
    }

    private static boolean reachable() {
        try {
            var request = HttpRequest.newBuilder().uri(URI.create(STORE_URL + "blocks/latest"))
                    .timeout(Duration.ofSeconds(3)).GET().build();
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()).statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }
}
