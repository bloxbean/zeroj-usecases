package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OnChainOwnershipService;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.ProofCompressor;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * Verify a generated proof.
 *
 * <ul>
 *   <li><b>off-chain</b> (default) — a pure-Java Groth16 pairing check against the bundle's
 *       verification key. Seconds, no network.</li>
 *   <li><b>on-chain</b> (<code>--onchain</code>) — lock a gate UTxO whose datum is the address's
 *       payment key hash at the bundled Plutus validator, then unlock it with the proof. Proves the
 *       chain accepts the proof. Uses a Blockfrost-compatible API; defaults to a local Yaci DevKit.</li>
 * </ul>
 */
@Command(name = "verify", mixinStandardHelpOptions = true,
        description = "Verify a proof off-chain (default) or on-chain.")
public final class VerifyCommand implements Callable<Integer> {

    private static final String DEVKIT_BF = "http://localhost:8080/api/v1/";
    private static final String DEVKIT_ADMIN = "http://localhost:10000";

    @Option(names = "--keys", defaultValue = "keys", description = "Key-bundle directory (for the VK). Default: ${DEFAULT-VALUE}.")
    Path keysDir;

    @Option(names = "--proof", defaultValue = "proofs", description = "Directory with proof.json + public-inputs.json. Default: ${DEFAULT-VALUE}.")
    Path proofDir;

    @Option(names = "--onchain", description = "Verify on-chain (default: off-chain).")
    boolean onchain;

    @Option(names = "--bf-url", defaultValue = DEVKIT_BF,
            description = "Blockfrost-compatible API URL. Default: ${DEFAULT-VALUE} (Yaci DevKit).")
    String bfUrl;

    @Option(names = "--bf-key", defaultValue = "", description = "Blockfrost project id/key (blank for Yaci DevKit).")
    String bfKey;

    @Override
    public Integer call() throws Exception {
        var bundle = new Bundle(keysDir);
        if (!bundle.exists()) {
            System.err.println("No key bundle at " + keysDir.toAbsolutePath() + " (need it for the verification key).");
            return 2;
        }
        Path proofFile = proofDir.resolve(ProofIO.PROOF_FILE);
        Path pubFile = proofDir.resolve(ProofIO.PUBLIC_FILE);
        if (!java.nio.file.Files.isRegularFile(proofFile) || !java.nio.file.Files.isRegularFile(pubFile)) {
            System.err.println("No proof in " + proofDir.toAbsolutePath() + " (run `prove` first).");
            return 2;
        }

        String proofFp = ProofIO.readFingerprint(pubFile);
        String bundleFp = bundle.metadata().getProperty("fingerprint");
        if (proofFp != null && bundleFp != null && !proofFp.equals(bundleFp)) {
            System.err.println("Proof/key mismatch: proof fingerprint " + proofFp + " vs bundle " + bundleFp + ".");
            return 2;
        }

        return onchain ? verifyOnChain(bundle, proofFile, pubFile) : verifyOffChain(proofFile, pubFile);
    }

    private int verifyOffChain(Path proofFile, Path pubFile) throws Exception {
        System.out.println("Off-chain verification (pairing check) ...");
        long t = System.nanoTime();
        var pts = ProofIO.readProof(proofFile);
        var pub = ProofIO.readPublicInputs(pubFile);
        boolean ok;
        if (VkIO.exists(keysDir)) {                      // fast path: tiny vk.json, no 23 GB load
            ok = OffchainVerifier.verify(VkIO.readVk(keysDir), pts, pub);
        } else {                                         // fallback: extract VK from the proving-key store
            var key = Groth16PkStore.load(keysDir);
            try {
                ok = OffchainVerifier.verify(key, pts, pub);
                VkIO.writeQuietly(keysDir, Bundle.vkSetup(key)); // cache for next time
            } finally {
                Bundle.closeQuietly(key);
            }
        }
        System.out.printf("  result: %s (%.2fs)%n", ok ? "VALID" : "INVALID", (System.nanoTime() - t) / 1e9);
        return ok ? 0 : 1;
    }

    private int verifyOnChain(Bundle bundle, Path proofFile, Path pubFile) throws Exception {
        byte[] pkh = ProofIO.readPkh(pubFile);
        var compressed = ProofIO.readCompressedProof(proofFile);

        System.out.println("On-chain verification via " + bfUrl);
        boolean devkit = bfUrl.contains("localhost") || bfUrl.contains("127.0.0.1");

        // A funded payer is needed to lock the gate UTxO and pay fees. On Yaci DevKit it is topped
        // up automatically; against a hosted network it must already hold funds.
        System.out.println("A funding wallet is needed to submit the gate transactions"
                + (devkit ? " (Yaci DevKit: it will be auto-funded)." : "."));
        String payerMnemonic = ProveCommand.readMnemonic();
        if (payerMnemonic == null || payerMnemonic.isBlank()) {
            System.err.println("No funding mnemonic entered.");
            return 2;
        }
        var payer = new Account(Networks.testnet(), payerMnemonic.trim());
        payerMnemonic = null;
        if (devkit) topUp(payer.baseAddress(), 10000);

        // The validator only needs the (small) verification key — prefer vk.json over a 23 GB store load.
        SnarkjsToCardano.VkCompressed vk;
        if (VkIO.exists(keysDir)) {
            vk = VkIO.readVkCompressed(keysDir);
        } else {
            var key = Groth16PkStore.load(keysDir);
            try {
                vk = ProofCompressor.compressVk(Bundle.vkSetup(key));
                VkIO.writeQuietly(keysDir, Bundle.vkSetup(key));
            } finally {
                Bundle.closeQuietly(key);
            }
        }
        var onChain = new OnChainOwnershipService(new BFBackendService(bfUrl, bfKey), payer, vk);
        System.out.println("  gate script address: " + onChain.scriptAddress());
        System.out.println("  locking gate + unlocking with proof ...");
        long t = System.nanoTime();
        String txHash = onChain.verifyOwnershipOnChain(compressed, pkh);
        System.out.printf("  VERIFIED ON-CHAIN (%.1fs): tx=%s%n", (System.nanoTime() - t) / 1e9, txHash);
        return txHash != null ? 0 : 1;
    }

    private static void topUp(String address, int ada) throws Exception {
        try {
            String body = "{\"address\":\"" + address + "\",\"adaAmount\":" + ada + "}";
            var req = HttpRequest.newBuilder(URI.create(DEVKIT_ADMIN + "/local-cluster/api/addresses/topup"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            var resp = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2)
                System.out.println("  (top-up skipped: HTTP " + resp.statusCode() + " — ensure the payer is funded)");
            else Thread.sleep(1500);
        } catch (Exception e) {
            System.out.println("  (top-up skipped: " + e.getMessage() + " — ensure the payer is funded)");
        }
    }
}
