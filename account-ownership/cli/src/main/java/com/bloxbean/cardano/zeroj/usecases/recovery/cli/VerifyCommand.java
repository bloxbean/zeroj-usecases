package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OnChainOwnershipService;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.ProofCompressor;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.math.BigInteger;
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

    enum Net { devnet, preview, preprod, mainnet }

    @Option(names = "--network", defaultValue = "devnet",
            description = "devnet (Yaci DevKit) | preview | preprod | mainnet. Sets the Blockfrost URL "
                    + "automatically unless --bf-url is given. Default: ${DEFAULT-VALUE}.")
    Net network;

    @Option(names = "--bf-url",
            description = "Override the Blockfrost-compatible API URL (default: derived from --network).")
    String bfUrl;

    @Option(names = "--bf-key",
            description = "Blockfrost project id/key (or set env BLOCKFROST_PROJECT_ID); not needed for devnet.")
    String bfKey;

    @Option(names = "--expect-address",
            description = "Verify the proof is for THIS address (bech32). Default: the address recorded in "
                    + "public-inputs.json. Pass a value you know independently for real assurance.")
    String expectAddress;

    @Option(names = "--expect-recipient",
            description = "Verify the proof is bound to THIS recipient (bech32). Default: the recipient in "
                    + "public-inputs.json.")
    String expectRecipient;

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
        final BigInteger[] pub;
        final Flows.VerifyTargets targets;
        try {
            // Recompute the public inputs from the address + recipient (default: the file's fields;
            // or --expect-* overrides). Ties the result to those values, not the stored array.
            pub = Flows.resolvePublicInputs(pubFile, expectAddress, expectRecipient);
            targets = Flows.resolveTargets(pubFile, expectAddress, expectRecipient);
        } catch (RuntimeException ex) {
            System.err.println("  " + ex.getMessage());
            return 1;
        }
        System.out.println("  checking the proof is for address " + targets.address()
                + " → recipient " + targets.recipient()
                + (targets.overridden() ? "  (your expected values)" : ""));
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
        final Flows.VerifyTargets targets;
        try {
            targets = Flows.resolveTargets(pubFile, expectAddress, expectRecipient);
        } catch (RuntimeException ex) {
            System.err.println(ex.getMessage());
            return 2;
        }
        byte[] pkh = targets.pkh();
        byte[] recipientPkh = targets.recipientPkh();
        String recipient = targets.recipient();
        var compressed = ProofIO.readCompressedProof(proofFile);

        // --network sets the endpoint automatically; --bf-url overrides. Key from --bf-key or env.
        String url = (bfUrl != null && !bfUrl.isBlank()) ? bfUrl : defaultBfUrl();
        String key = (bfKey != null && !bfKey.isBlank()) ? bfKey : System.getenv("BLOCKFROST_PROJECT_ID");
        boolean devkit = network == Net.devnet;
        if (!devkit && (key == null || key.isBlank())) {
            System.err.println("A Blockfrost project key is required for " + network
                    + " — pass --bf-key or set BLOCKFROST_PROJECT_ID.");
            return 2;
        }
        Network net = network();
        System.out.println("On-chain verification on " + network + " via " + url);

        // The ADMIN / funding account locks the gate UTxO and pays fees + collateral. It's the account
        // of the mnemonic in AOR_ADMIN_MNEMONIC, else prompted (hidden), base address
        // m/1852'/1815'/0'/0/0. This is a FUNDING wallet, NOT the wallet being proven — use a
        // low-value account. On devnet it is auto-funded; elsewhere it must already hold ADA.
        String payerMnemonic = System.getenv("AOR_ADMIN_MNEMONIC");
        if (payerMnemonic != null && !payerMnemonic.isBlank()) {
            System.out.println("Using ADMIN account from AOR_ADMIN_MNEMONIC.");
        } else {
            System.out.println("Enter the ADMIN/funding account mnemonic (locks + pays for the gate txs)"
                    + (devkit ? " — Yaci DevKit will fund it." : " — it must already hold ADA on " + network + ".")
                    + "  [or set AOR_ADMIN_MNEMONIC]");
            payerMnemonic = ProveCommand.readMnemonic();
        }
        if (payerMnemonic == null || payerMnemonic.isBlank()) {
            System.err.println("No admin/funding mnemonic (set AOR_ADMIN_MNEMONIC or enter it at the prompt).");
            return 2;
        }
        var payer = new Account(net, payerMnemonic.trim());
        payerMnemonic = null;
        System.out.println("  admin address: " + payer.baseAddress());
        if (devkit) topUp(payer.baseAddress(), 10000);

        // The validator only needs the (small) verification key — prefer vk.json over a 23 GB store load.
        SnarkjsToCardano.VkCompressed vk;
        if (VkIO.exists(keysDir)) {
            vk = VkIO.readVkCompressed(keysDir);
        } else {
            var loaded = Groth16PkStore.load(keysDir);
            try {
                vk = ProofCompressor.compressVk(Bundle.vkSetup(loaded));
                VkIO.writeQuietly(keysDir, Bundle.vkSetup(loaded));
            } finally {
                Bundle.closeQuietly(loaded);
            }
        }
        var onChain = new OnChainOwnershipService(new BFBackendService(url, key == null ? "" : key), payer, vk, net);
        System.out.println("  gate script address: " + onChain.scriptAddress());
        System.out.println("  locking gate + unlocking with proof (refund → " + recipient + ") ...");
        long t = System.nanoTime();
        String txHash = onChain.verifyOwnershipOnChain(compressed, pkh, recipientPkh, recipient,
                OnChainOwnershipService.DEMO_REFUND_LOVELACE);
        System.out.printf("  VERIFIED ON-CHAIN (%.1fs): tx=%s%n", (System.nanoTime() - t) / 1e9, txHash);
        return txHash != null ? 0 : 1;
    }

    private Network network() {
        return switch (network) {
            case devnet -> Networks.testnet();      // Yaci DevKit uses the testnet network id
            case preview -> Networks.preview();
            case preprod -> Networks.preprod();
            case mainnet -> Networks.mainnet();
        };
    }

    private String defaultBfUrl() {
        return switch (network) {
            case devnet -> DEVKIT_BF;
            case preview -> "https://cardano-preview.blockfrost.io/api/v0/";
            case preprod -> "https://cardano-preprod.blockfrost.io/api/v0/";
            case mainnet -> "https://cardano-mainnet.blockfrost.io/api/v0/";
        };
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
