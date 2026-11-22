package com.bloxbean.cardano.zeroj.usecases.dpp;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ApprovedSets;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.BackendChain;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.Claim;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ClaimOpening;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.CoSignGuard;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.DppCircuits;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.LocalJulcEvaluator;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.MemoryReservations;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportDatum;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportReader;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportScript;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportTransactions;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.RoleKeys;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Product passports on Yaci DevKit (ADR-0009 D1, M6 E2E). The manufacturer builds the passport
 * transaction and the auditor co-signs it; the policy verifies the carbon proof against the
 * commitment in the passport datum. Refused by the script (local Julc evaluation, as the node
 * would run it): a mint without the auditor, another manufacturer's policy replaying the proof,
 * a proof against a threshold the manufacturer chose, a transfer of the passport, and a revoke
 * by anyone but the auditor. The auditor refuses to co-sign a datum that differs from its report.
 * The auditor refuses a second passport for the product. The auditor then revokes; the reader
 * sees the mint history and the revocation.
 *
 * <p>Runs only with {@code ZEROJ_YACI_E2E=true}.
 */
class DppPassportDevKitE2ETest {

    private static final String STORE_URL = env("ZEROJ_YACI_STORE_URL", "http://localhost:8080/api/v1/");
    private static final String ADMIN_URL = env("ZEROJ_YACI_ADMIN_URL", "http://localhost:10000");

    @Test
    void passportOnDevKit() throws Exception {
        assumeTrue(Boolean.getBoolean("zeroj.yaci.e2e") && reachable(), "Set ZEROJ_YACI_E2E=true with DevKit running");
        BackendService backend = new BFBackendService(STORE_URL, "");
        Account manufacturer = new Account(Networks.testnet());
        Account auditor = new Account(Networks.testnet());
        Account mallory = new Account(Networks.testnet());
        for (Account a : List.of(manufacturer, auditor, mallory)) topUp(a.baseAddress(), 500);

        DppCircuits circuits = DppCircuits.compile();
        var vk = circuits.circuit(Claim.CARBON).compressedVk();
        PassportScript script = new PassportScript(RoleKeys.pkh(manufacturer), RoleKeys.pkh(auditor), Claim.CARBON, 50, vk,
                Networks.testnet());
        PassportScript malloryScript = new PassportScript(RoleKeys.pkh(mallory), RoleKeys.pkh(auditor), Claim.CARBON, 50, vk,
                Networks.testnet());

        // The auditor measures and commits; the openings go to the manufacturer.
        byte[] productId = ("E2E-" + System.currentTimeMillis() % 1_000_000).getBytes(StandardCharsets.UTF_8);
        List<ClaimOpening> openings = List.of(ClaimOpening.fresh(Claim.CARBON, 7), ClaimOpening.fresh(Claim.RECYCLED, 45),
                ClaimOpening.fresh(Claim.ORIGIN, 276),
                ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1_717_000_000L, 13, 1_717_086_400L, 11, 1_717_172_800L));
        PassportDatum datum = PassportDatum.of(productId, RoleKeys.pkh(manufacturer), openings);
        var proof = circuits.prove(openings.get(0), BigInteger.valueOf(50));
        String serial = new String(productId, StandardCharsets.UTF_8);
        CoSignGuard guard = new CoSignGuard(new MemoryReservations(), new BackendChain(backend, STORE_URL, script));
        var auditorSigner = guard.signer(auditor, serial, script, datum);

        // Without the auditor: refused by the policy.
        assertScriptRejected(PassportTransactions.issue(backend, script, manufacturer, (ctx, tx) -> tx, datum, proof,
                RoleKeys.pkh(manufacturer)), "a passport without the auditor");
        // Mallory replays the manufacturer's commitments and proof under her own policy: no auditor.
        PassportDatum malloryDatum = PassportDatum.of(productId, RoleKeys.pkh(mallory), openings);
        assertScriptRejected(PassportTransactions.issue(backend, malloryScript, mallory, (ctx, tx) -> tx, malloryDatum, proof,
                RoleKeys.pkh(mallory)), "another manufacturer's policy replaying the proof");
        // A 65 kg product proved against a threshold the manufacturer chose: refused.
        List<ClaimOpening> high = List.of(ClaimOpening.fresh(Claim.CARBON, 65));
        PassportDatum highDatum = PassportDatum.of(productId, RoleKeys.pkh(manufacturer), high);
        assertScriptRejected(PassportTransactions.issue(backend, script, manufacturer,
                new CoSignGuard(new MemoryReservations(), new BackendChain(backend, STORE_URL, script))
                        .signer(auditor, serial, script, highDatum), highDatum,
                circuits.prove(high.get(0), BigInteger.valueOf(65_535))), "a proof against the manufacturer's own threshold");
        // The auditor refuses to co-sign a datum that is not its report: here the policy would
        // accept it (a valid carbon proof, the other claims dropped), but the auditor attested four.
        PassportDatum notTheReport = PassportDatum.of(productId, RoleKeys.pkh(manufacturer), openings.subList(0, 1));
        Result<String> refused = PassportTransactions.issue(backend, script, manufacturer, auditorSigner, notTheReport, proof);
        assertFalse(refused.isSuccessful(), "the auditor must refuse");
        assertTrue(String.valueOf(refused.getResponse()).contains("auditor refuses"), String.valueOf(refused.getResponse()));

        // The passport: one transaction, both signatures.
        Result<String> issued = PassportTransactions.issue(backend, script, manufacturer, auditorSigner, datum, proof);
        assertTrue(issued.isSuccessful(), "issue: " + issued.getResponse());
        waitForTx(backend, issued.getValue());
        Utxo passport = passportAt(backend, script, productId).orElseThrow();
        assertEquals(datum, PassportDatum.fromPlutusData(PlutusData.deserialize(HexUtil.decodeHexString(passport.getInlineDatum()))));
        assertEquals(PassportReader.Status.ACTIVE, PassportReader.status(PassportReader.fetchHistory(STORE_URL, script.unit(productId))));
        // A second passport for the product: the auditor refuses (reserved, and the mint history is no longer empty).
        Result<String> second = PassportTransactions.issue(backend, script, manufacturer, auditorSigner, datum, proof);
        assertFalse(second.isSuccessful(), "a second passport must be refused");
        assertTrue(String.valueOf(second.getResponse()).contains("auditor refuses"), String.valueOf(second.getResponse()));

        // Off-chain claims verify against the on-chain commitments, σ from the reader's registry.
        var registry = PassportReader.SchemaRegistry.demo();
        assertEquals(PassportReader.Verdict.VERIFIED, PassportReader.verifyClaim(circuits, registry, datum, Claim.ORIGIN,
                ApprovedSets.EU_COUNTRIES.root(), circuits.prove(openings.get(2), ApprovedSets.EU_COUNTRIES.root())));
        assertEquals(PassportReader.Verdict.VERIFIED, PassportReader.verifyClaim(circuits, registry, datum, Claim.INSPECTIONS,
                ApprovedSets.INSPECTORS.root(), circuits.prove(openings.get(3), ApprovedSets.INSPECTORS.root())));

        // A transfer of the passport (Revoke redeemer, no burn), signed by the auditor: refused.
        var transfer = new ScriptTx()
                .collectFrom(passport, PassportTransactions.revokeRedeemer())
                .payToAddress(mallory.baseAddress(), List.of(Amount.ada(2), new Amount(script.unit(productId), BigInteger.ONE)))
                .attachSpendingValidator(script.script())
                .withChangeAddress(auditor.baseAddress());
        Result<String> transferred;
        try {
            transferred = new QuickTxBuilder(backend).compose(transfer)
                    .withTxEvaluator(LocalJulcEvaluator.create(backend))
                    .withSigner(SignerProviders.signerFrom(auditor))
                    .withRequiredSigners(RoleKeys.pkh(auditor))
                    .feePayer(auditor.baseAddress()).collateralPayer(auditor.baseAddress())
                    .complete();
        } catch (RuntimeException e) {
            transferred = Result.error(e.getMessage());
        }
        assertScriptRejected(transferred, "a transfer of the passport");
        // A revoke by the manufacturer: refused.
        assertScriptRejected(PassportTransactions.revoke(backend, script, manufacturer, passport, productId,
                RoleKeys.pkh(manufacturer)), "a revoke without the auditor");

        // The auditor revokes.
        Result<String> revoked = PassportTransactions.revoke(backend, script, auditor, passport, productId);
        assertTrue(revoked.isSuccessful(), "revoke: " + revoked.getResponse());
        waitForTx(backend, revoked.getValue());
        assertTrue(passportAt(backend, script, productId).isEmpty(), "the passport is gone");
        assertEquals(PassportReader.Status.REVOKED, PassportReader.status(PassportReader.fetchHistory(STORE_URL, script.unit(productId))));
        System.out.println("Passport on DevKit: issued " + issued.getValue() + ", revoked " + revoked.getValue());
    }

    private static Optional<Utxo> passportAt(BackendService backend, PassportScript script, byte[] productId) throws Exception {
        String unit = script.unit(productId);
        var result = backend.getUtxoService().getUtxos(script.address(), 100, 1);
        if (!result.isSuccessful() || result.getValue() == null) return Optional.empty();
        return result.getValue().stream().filter(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().equals(unit))).findFirst();
    }

    /**
     * The transaction failed in script evaluation (local Julc evaluation, as the node would run
     * it), not for lack of funds; a refused transaction is never submitted.
     */
    private static void assertScriptRejected(Result<String> result, String what) {
        assertFalse(result.isSuccessful(), what + " must be rejected");
        String response = String.valueOf(result.getResponse());
        System.out.println("Rejected (" + what + "): " + response.substring(0, Math.min(140, response.length())));
        assertTrue(response.contains("Script evaluation failed") || response.contains("Error while evaluating script cost"),
                what + " must be rejected by a script: " + response);
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

    private static void topUp(String address, int ada) throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create(ADMIN_URL + "/local-cluster/api/addresses/topup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"address\":\"" + address + "\",\"adaAmount\":" + ada + "}"))
                .build();
        HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        Thread.sleep(3_000);
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

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }
}
