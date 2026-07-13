package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Keys;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Pipeline;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OwnershipCircuitService;

import java.io.IOException;
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
    public record ProveResult(String address, String pkhHex, Path proofDir) {}

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
                                    boolean mainnet, Path outDir, Consumer<String> stage) throws Exception {
        if (account != 0) throw new IllegalArgumentException("Only account 0 is supported (circuit v2 fixes the account at 0').");
        if (role < 0 || index < 0) throw new IllegalArgumentException("role and index must be non-negative soft indices (< 2^31).");
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
                                wallet.role(), wallet.index(), wallet.pkh());
                    },
                    bindingRows, ProverBackend.PURE_JAVA, progress);

            String fp = bundleFp != null ? bundleFp : ccBox[0].fingerprint();
            Files.createDirectories(outDir);
            ProofIO.writeProof(outDir, proof);
            ProofIO.writePublicInputs(outDir, wallet.pkh(), wallet.address(), fp);

            stage.accept("Self-check (off-chain pairing)…");
            var pts = ProofIO.readProof(outDir.resolve(ProofIO.PROOF_FILE));
            var pub = ProofIO.readPublicInputs(outDir.resolve(ProofIO.PUBLIC_FILE));
            if (!OffchainVerifier.verify(loaded, pts, pub))
                throw new IllegalStateException("Self-check failed — the generated proof did not verify.");

            return new ProveResult(wallet.address(), WalletDerivation.hex(wallet.pkh()), outDir);
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
        Path pubFile = proofDir.resolve(ProofIO.PUBLIC_FILE);
        String proofFp = ProofIO.readFingerprint(pubFile);
        String bundleFp = keyFingerprint(bundleDir);
        if (proofFp != null && bundleFp != null && !proofFp.equals(bundleFp))
            throw new IllegalStateException("Proof/key mismatch: proof is " + proofFp + " but the bundle is " + bundleFp + ".");

        var pts = ProofIO.readProof(proofDir.resolve(ProofIO.PROOF_FILE));
        var pub = ProofIO.readPublicInputs(pubFile);
        if (VkIO.exists(bundleDir)) return OffchainVerifier.verify(VkIO.readVk(bundleDir), pts, pub);

        var key = Groth16PkStore.load(bundleDir);
        try { return OffchainVerifier.verify(key, pts, pub); }
        finally { Bundle.closeQuietly(key); }
    }
}
