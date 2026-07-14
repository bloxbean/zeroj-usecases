package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Keys;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Pipeline;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OnChainOwnershipService;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OwnershipCircuitService;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.ProofCompressor;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * High-level flows over the account-ownership service layer, expressed with plain {@link Path},
 * primitive, and {@link Consumer} signatures so any front-end (the picocli commands, the JavaFX UI)
 * can drive them without depending on the ZeroJ crypto types. The heavy lifting lives in
 * {@link OwnershipCircuitService} / {@link Groth16Pipeline}; this class wires the pieces the same
 * way {@link SetupCommand} / {@link ProveCommand} / {@link VerifyCommand} do. Everything is pure
 * Java (no blst) — safe on every platform.
 */
public final class Flows {

    private Flows() {}

    /** Result of a successful {@link #prove}: what the UI shows and where the artifacts landed. */
    public record ProveResult(String address, String pkhHex, String recipient, Path proofDir) {}

    /** Decode a recipient bech32 address to its 28-byte payment key hash (the {@code recipient} public input). */
    public static byte[] paymentKeyHashOf(String bech32) {
        if (bech32 == null || bech32.isBlank())
            throw new IllegalArgumentException("A recipient address is required.");
        var pkh = new com.bloxbean.cardano.client.address.Address(bech32.trim()).getPaymentCredentialHash();
        if (pkh.isEmpty())
            throw new IllegalArgumentException("Recipient address has no payment credential "
                    + "(use a base or enterprise address): " + bech32);
        byte[] b = pkh.get();
        if (b.length != 28)
            throw new IllegalArgumentException("Recipient payment key hash must be 28 bytes, got " + b.length);
        return b;
    }

    /**
     * What a verify is checked against: the proven address and the recipient (bech32 + their 28-byte
     * payment key hashes). Each defaults to the corresponding field in {@code public-inputs.json};
     * {@code overridden} is true when the caller supplied an expected value instead.
     */
    public record VerifyTargets(byte[] pkh, byte[] recipientPkh, String address, String recipient,
                                boolean overridden) {}

    /**
     * Resolve the address + recipient a verify should bind to. Pass a bech32 address in
     * {@code expectAddress}/{@code expectRecipient} to check the proof against <b>your</b> value
     * (the real security control); leave them blank to take the values recorded in
     * {@code public-inputs.json}.
     */
    public static VerifyTargets resolveTargets(Path pubFile, String expectAddress, String expectRecipient)
            throws IOException {
        boolean addrOverride = expectAddress != null && !expectAddress.isBlank();
        boolean recipOverride = expectRecipient != null && !expectRecipient.isBlank();
        byte[] pkh = addrOverride ? paymentKeyHashOf(expectAddress) : ProofIO.readPkh(pubFile);
        byte[] recipientPkh = recipOverride ? paymentKeyHashOf(expectRecipient) : ProofIO.readRecipientPkh(pubFile);
        String address = addrOverride ? expectAddress.trim() : ProofIO.readAddress(pubFile);
        String recipient = recipOverride ? expectRecipient.trim() : ProofIO.readRecipient(pubFile);
        if (recipientPkh == null || recipient == null)
            throw new IllegalArgumentException("public-inputs.json has no recipient — re-run "
                    + "`prove --recipient <addr>`, or pass --expect-address/--expect-recipient.");
        return new VerifyTargets(pkh, recipientPkh, address, recipient, addrOverride || recipOverride);
    }

    /**
     * The two Groth16 public-input scalars to verify against — the big-endian packing of the resolved
     * pkh and recipient (matching the circuit). In pure default mode (no overrides) the stored
     * {@code publicInputs} array must equal the recomputed pair, so a hand-edited pkh, recipient, or
     * array is caught here rather than silently trusted.
     */
    public static BigInteger[] resolvePublicInputs(Path pubFile, String expectAddress, String expectRecipient)
            throws IOException {
        VerifyTargets t = resolveTargets(pubFile, expectAddress, expectRecipient);
        BigInteger[] recomputed = { new BigInteger(1, t.pkh()), new BigInteger(1, t.recipientPkh()) };
        if (!t.overridden()) {
            BigInteger[] stored = ProofIO.readPublicInputs(pubFile);
            if (!Arrays.equals(stored, recomputed))
                throw new IllegalStateException("public-inputs.json is inconsistent: its publicInputs "
                        + "do not match the pkh/recipient (edited file?). Re-run `prove`, or pass "
                        + "--expect-address/--expect-recipient to verify against known values.");
        }
        return recomputed;
    }

    /** The proven address recorded in a proof folder (for prefill/display), or {@code null}. */
    public static String proofAddress(Path proofDir) throws IOException {
        return ProofIO.readAddress(proofDir.resolve(ProofIO.PUBLIC_FILE));
    }

    /** The recipient recorded in a proof folder (for prefill/display), or {@code null}. */
    public static String proofRecipient(Path proofDir) throws IOException {
        return ProofIO.readRecipient(proofDir.resolve(ProofIO.PUBLIC_FILE));
    }

    /** True if {@code bundleDir} holds a usable key bundle. */
    public static boolean hasKeys(Path bundleDir) {
        return new Bundle(bundleDir).exists();
    }

    /** The circuit fingerprint pinned in a bundle, or {@code null} if there is no bundle. */
    public static String keyFingerprint(Path bundleDir) {
        var bundle = new Bundle(bundleDir);
        return bundle.exists() ? bundle.metadata().getProperty("fingerprint") : null;
    }

    /** True if {@code proofDir} holds a proof + its public inputs. */
    public static boolean hasProof(Path proofDir) {
        return Files.isRegularFile(proofDir.resolve(ProofIO.PROOF_FILE))
                && Files.isRegularFile(proofDir.resolve(ProofIO.PUBLIC_FILE));
    }

    /**
     * Extract a downloaded key-bundle ZIP into {@code bundleDir} (the archive holds the bundle
     * files — {@code points*.bin}, {@code aux.bin}, {@code manifest.properties},
     * {@code bundle.properties}, {@code vk.json}, {@code r1cs.bin} — at its root), then confirm the
     * result is a well-formed bundle. Guards against zip-slip.
     *
     * @return the extracted bundle's circuit fingerprint
     * @throws IOException on a malformed archive, an unsafe entry, or a non-bundle result
     */
    public static String extractBundle(Path archive, Path bundleDir, Consumer<String> stage) throws IOException {
        Files.createDirectories(bundleDir);
        Path root = bundleDir.toAbsolutePath().normalize();
        stage.accept("Extracting bundle…");
        try (var zf = new java.util.zip.ZipFile(archive.toFile())) {
            byte[] buf = new byte[1 << 20];
            var entries = zf.entries();
            while (entries.hasMoreElements()) {
                var e = entries.nextElement();
                Path out = root.resolve(e.getName()).normalize();
                if (!out.startsWith(root)) throw new IOException("Unsafe archive entry (zip-slip): " + e.getName());
                if (e.isDirectory()) { Files.createDirectories(out); continue; }
                if (out.getParent() != null) Files.createDirectories(out.getParent());
                stage.accept("Extracting " + root.relativize(out) + "…");
                try (var in = zf.getInputStream(e); var os = Files.newOutputStream(out)) {
                    int n;
                    while ((n = in.read(buf)) != -1) os.write(buf, 0, n);
                }
            }
        }
        if (!hasKeys(bundleDir))
            throw new IOException("The downloaded archive is not a valid key bundle "
                    + "(missing manifest.properties / bundle.properties).");
        return keyFingerprint(bundleDir);
    }

    /**
     * Generate a <b>local, single-party</b> (dev/testing) key bundle at {@code bundleDir} — the
     * same output as {@code setup --i-understand-insecure} (~8 GB heap, ~5–6 min).
     *
     * @param stage receives short stage messages (compile → setup → finalize); pass {@code s -> {}} to ignore
     */
    public static void generateLocalKeys(Path bundleDir, Consumer<String> stage) throws IOException {
        Files.createDirectories(bundleDir);
        var svc = new OwnershipCircuitService();

        stage.accept("Compiling circuit (BLS12-381)…");
        svc.compile();
        int nc = svc.numConstraints(), nw = svc.numWires(), np = svc.numPublicInputs();

        stage.accept(String.format("%,d constraints — running single-party trusted setup (~5–6 min)…", nc));
        var setup = svc.localSetupToStore(bundleDir, /*sparse*/ true);

        stage.accept("Writing verification key + bundle metadata…");
        VkIO.write(bundleDir, setup);
        new Bundle(bundleDir).finalizeAndReport("local", nc, nw, np);
    }

    /**
     * Prove ownership of {@code m/1852'/1815'/0'/role/index} for the given mnemonic against the key
     * bundle in {@code bundleDir}, writing {@code proof.json} + {@code public-inputs.json} to
     * {@code outDir} and running an off-chain self-check. Pure Java, ~1–1.5 min.
     *
     * <p>The {@code mnemonic} char array is <b>zeroed</b> before this method returns.</p>
     *
     * @throws IllegalStateException on a bad bundle, a circuit/key mismatch, or a failed self-check
     */
    public static ProveResult prove(Path bundleDir, char[] mnemonic, int account, int role, int index,
                                    String recipientAddress, boolean mainnet, Path outDir,
                                    Consumer<String> stage) throws Exception {
        if (account < 0 || role < 0 || index < 0)
            throw new IllegalArgumentException("account, role and index must be non-negative soft indices (< 2^31).");
        byte[] recipientPkh = paymentKeyHashOf(recipientAddress);   // decode the bech32 → 28-byte payment credential
        var bundle = new Bundle(bundleDir);
        if (!bundle.exists()) throw new IllegalStateException("No key bundle at " + bundleDir + " — run setup or download first.");

        String bundleFp = bundle.metadata().getProperty("fingerprint");
        Path cacheFile = bundleDir.resolve(Groth16Pipeline.R1CS_CACHE);

        var svc = new OwnershipCircuitService();
        var ccBox = new Groth16Pipeline.Compiled[1];
        Supplier<Groth16Pipeline.Compiled> compile = () -> {
            if (ccBox[0] == null) {
                stage.accept("Compiling circuit (BLS12-381)…");
                var cs = svc.compile();
                ccBox[0] = new Groth16Pipeline.Compiled(cs.flat(), cs.numConstraints(), cs.numWires(), cs.numPublicInputs());
            }
            return ccBox[0];
        };
        var dims = Groth16Pipeline.parseFingerprint(bundleFp);
        int numPublic = dims != null ? dims.numPublic() : compile.get().numPublic();
        int bindingRows = bundle.isSnarkjsKey() ? numPublic + 1 : 0;

        WalletDerivation.Wallet wallet;
        try {
            stage.accept("Deriving wallet key…");
            wallet = new WalletDerivation().derive(new String(mnemonic).trim(), account, role, index,
                    mainnet ? Networks.mainnet() : Networks.testnet());
        } finally {
            Arrays.fill(mnemonic, '\0'); // drop the secret material we control
        }

        stage.accept("Loading proving key (memory-mapped)…");
        var loaded = Groth16PkStore.load(bundleDir);
        try {
            var progress = new Groth16Pipeline.Progress() {
                @Override public void constraintsMapped(int rows, double s) { stage.accept("Constraints ready…"); }
                @Override public void proveStarted() { stage.accept("Generating proof (multi-core)…"); }
            };
            Groth16ProofBLS381 proof = Groth16Pipeline.prove(Groth16Keys.of(loaded), cacheFile, bundleFp,
                    compile,
                    () -> {
                        stage.accept("Computing witness…");
                        return svc.witnessFlat(wallet.rootKL(), wallet.rootKR(), wallet.rootChainCode(),
                                wallet.account(), wallet.role(), wallet.index(), wallet.pkh(), recipientPkh);
                    },
                    bindingRows, ProverBackend.PURE_JAVA, progress);

            String fp = bundleFp != null ? bundleFp : ccBox[0].fingerprint();
            Files.createDirectories(outDir);
            ProofIO.writeProof(outDir, proof);
            ProofIO.writePublicInputs(outDir, wallet.pkh(), wallet.address(), recipientPkh, recipientAddress.trim(), fp);

            stage.accept("Self-check (off-chain pairing)…");
            var pts = ProofIO.readProof(outDir.resolve(ProofIO.PROOF_FILE));
            var pub = ProofIO.readPublicInputs(outDir.resolve(ProofIO.PUBLIC_FILE));
            if (!OffchainVerifier.verify(loaded, pts, pub))
                throw new IllegalStateException("Self-check failed — the generated proof did not verify.");

            return new ProveResult(wallet.address(), WalletDerivation.hex(wallet.pkh()), recipientAddress.trim(), outDir);
        } finally {
            Bundle.closeQuietly(loaded);
        }
    }

    /**
     * Off-chain verification of the proof in {@code proofDir} against the key bundle in
     * {@code bundleDir} — the pure-Java pairing check, sub-second. Uses {@code vk.json} when present
     * (no proving-key load), else falls back to the store.
     *
     * @throws IllegalStateException if the proof was made for a different circuit than the bundle
     */
    public static boolean verifyOffChain(Path bundleDir, Path proofDir) throws Exception {
        return verifyOffChain(bundleDir, proofDir, null, null);
    }

    /**
     * Off-chain pairing check. The public inputs are <b>recomputed</b> from the proven address and
     * recipient (see {@link #resolvePublicInputs}) rather than trusted from the file's array, so the
     * result is tied to those values — pass {@code expectAddress}/{@code expectRecipient} (bech32) to
     * verify against values you know independently.
     */
    public static boolean verifyOffChain(Path bundleDir, Path proofDir,
                                         String expectAddress, String expectRecipient) throws Exception {
        Path pubFile = proofDir.resolve(ProofIO.PUBLIC_FILE);
        String proofFp = ProofIO.readFingerprint(pubFile);
        String bundleFp = keyFingerprint(bundleDir);
        if (proofFp != null && bundleFp != null && !proofFp.equals(bundleFp))
            throw new IllegalStateException("Proof/key mismatch: proof is " + proofFp + " but the bundle is " + bundleFp + ".");

        var pts = ProofIO.readProof(proofDir.resolve(ProofIO.PROOF_FILE));
        var pub = resolvePublicInputs(pubFile, expectAddress, expectRecipient);
        if (VkIO.exists(bundleDir)) return OffchainVerifier.verify(VkIO.readVk(bundleDir), pts, pub);

        var key = Groth16PkStore.load(bundleDir);
        try { return OffchainVerifier.verify(key, pts, pub); }
        finally { Bundle.closeQuietly(key); }
    }

    /** Result of an on-chain verification. */
    public record OnChainResult(String txHash, String adminAddress, String scriptAddress) {}

    private static final String DEVKIT_ADMIN = "http://localhost:10000";

    /**
     * Verify a proof <b>on-chain</b>: an admin/funding account locks a gate UTxO (datum = the pkh
     * public inputs) at the validator, then unlocks it with the Groth16 proof — the ledger runs the
     * verifier. Returns the unlock transaction hash.
     *
     * @param adminMnemonic funding wallet that locks the gate and pays fees + collateral — <b>not</b>
     *                      the wallet being proven; use a low-value account. Zeroed before return.
     *                      On {@code devnet} it is auto-funded by Yaci DevKit.
     * @param network       {@code devnet | preview | preprod | mainnet}
     * @param blockfrostKey Blockfrost project id — required for preview/preprod/mainnet; ignored on devnet
     * @param bfUrl         optional endpoint override (blank = the network default; e.g. a DevKit at
     *                      {@code http://host.docker.internal:8080/api/v1/})
     * @throws IllegalArgumentException on an unknown network or a missing Blockfrost key
     */
    public static OnChainResult verifyOnChain(Path bundleDir, Path proofDir, char[] adminMnemonic,
            String network, String blockfrostKey, String bfUrl, Consumer<String> stage) throws Exception {
        return verifyOnChain(bundleDir, proofDir, adminMnemonic, network, blockfrostKey, bfUrl, null, null, stage);
    }

    /**
     * {@link #verifyOnChain} binding the datum pkh + payout recipient to the caller's expected values
     * ({@code expectAddress}/{@code expectRecipient}, bech32) instead of the proof file's fields.
     */
    public static OnChainResult verifyOnChain(Path bundleDir, Path proofDir, char[] adminMnemonic,
            String network, String blockfrostKey, String bfUrl,
            String expectAddress, String expectRecipient, Consumer<String> stage) throws Exception {
        String net = network == null ? "devnet" : network.trim().toLowerCase();
        boolean devnet = net.equals("devnet");
        Network cnet = switch (net) {
            case "devnet" -> Networks.testnet();   // Yaci DevKit uses the testnet network id
            case "preview" -> Networks.preview();
            case "preprod" -> Networks.preprod();
            case "mainnet" -> Networks.mainnet();
            default -> throw new IllegalArgumentException("Unknown network: " + network);
        };
        String url = (bfUrl != null && !bfUrl.isBlank()) ? bfUrl.trim() : switch (net) {
            case "devnet" -> "http://localhost:8080/api/v1/";
            case "preview" -> "https://cardano-preview.blockfrost.io/api/v0/";
            case "preprod" -> "https://cardano-preprod.blockfrost.io/api/v0/";
            default -> "https://cardano-mainnet.blockfrost.io/api/v0/";
        };
        String key = blockfrostKey == null ? "" : blockfrostKey.trim();
        if (!devnet && key.isEmpty())
            throw new IllegalArgumentException("A Blockfrost project key is required for " + net + ".");

        Path pubFile = proofDir.resolve(ProofIO.PUBLIC_FILE);
        VerifyTargets t = resolveTargets(pubFile, expectAddress, expectRecipient);
        byte[] pkh = t.pkh();
        byte[] recipientPkh = t.recipientPkh();
        String recipient = t.recipient();
        var compressed = ProofIO.readCompressedProof(proofDir.resolve(ProofIO.PROOF_FILE));

        Account payer;
        try {
            payer = new Account(cnet, new String(adminMnemonic).trim());
        } finally {
            Arrays.fill(adminMnemonic, '\0');
        }
        stage.accept("Admin account: " + payer.baseAddress());
        if (devnet) { stage.accept("Funding admin on Yaci DevKit…"); topUpDevKit(payer.baseAddress(), 10000); }

        SnarkjsToCardano.VkCompressed vk;
        if (VkIO.exists(bundleDir)) {
            vk = VkIO.readVkCompressed(bundleDir);
        } else {
            var loaded = Groth16PkStore.load(bundleDir);
            try { vk = ProofCompressor.compressVk(Bundle.vkSetup(loaded)); }
            finally { Bundle.closeQuietly(loaded); }
        }

        var onChain = new OnChainOwnershipService(new BFBackendService(url, key), payer, vk, cnet);
        stage.accept("Locking gate + unlocking with proof (refund → " + recipient + ") at "
                + onChain.scriptAddress() + " …");
        String txHash = onChain.verifyOwnershipOnChain(compressed, pkh, recipientPkh, recipient,
                OnChainOwnershipService.DEMO_REFUND_LOVELACE);
        return new OnChainResult(txHash, payer.baseAddress(), onChain.scriptAddress());
    }

    /** Best-effort Yaci DevKit faucet top-up; if it fails the admin must already hold ADA. */
    private static void topUpDevKit(String address, int ada) {
        try {
            String body = "{\"address\":\"" + address + "\",\"adaAmount\":" + ada + "}";
            var req = HttpRequest.newBuilder(URI.create(DEVKIT_ADMIN + "/local-cluster/api/addresses/topup"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            var resp = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 == 2) Thread.sleep(1500);
        } catch (Exception ignore) {
            // best-effort — the admin must already be funded if this fails
        }
    }
}
