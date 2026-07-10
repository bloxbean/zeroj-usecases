package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.api.R1CSFlatIO;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend;
import com.bloxbean.cardano.zeroj.cryptoblst.BlstProverBackend;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OwnershipCircuitService;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * Generate an ownership proof from the wallet mnemonic. This is where a normal user starts: given a
 * downloaded key bundle, it takes ~2-3 min end-to-end with ≥10 GB of heap (the proving key is
 * mmap-loaded instantly, the constraints come from the r1cs.bin cache, and the multi-core prove is
 * ~2 min on either backend — ADR-0033/0034).
 *
 * <p>The mnemonic is read via a hidden interactive prompt — never a command-line argument, an
 * environment variable, or a file. The root key derived from it stays in memory and is never
 * written or transmitted; only the proof and its public inputs are saved.</p>
 */
@Command(name = "prove", mixinStandardHelpOptions = true,
        description = "Generate an ownership proof from your mnemonic.")
public final class ProveCommand implements Callable<Integer> {

    // ADR-0034 measured heap floors for the 19M-constraint prove (2026-07-10, packed CSR
    // constraints + flat witness/hCoeffs + r1cs.bin cache): a first run must compile — 8 GB
    // passes, 6 GB OOMs in the compile; with a matching r1cs.bin the compile is skipped and
    // 7 GB passes (6 GB OOMs building the witness graph). HARD_MIN: below this the run cannot
    // complete; RECOMMENDED: comfortable headroom.
    private static final int HARD_MIN_HEAP_GB = 4; // TEMP probe
    private static final int HARD_MIN_CACHED_HEAP_GB = 4; // TEMP probe
    private static final int RECOMMENDED_HEAP_GB = 10;

    enum Backend { blst, java }

    @Option(names = "--keys", defaultValue = "keys", description = "Key-bundle directory. Default: ${DEFAULT-VALUE}.")
    Path keysDir;

    @Option(names = "--backend", defaultValue = "java",
            description = "Prover backend. java (default): pure-Java multi-core — same speed as "
                    + "blst at this circuit size since ADR-0033/0034, no native lib, and safe on "
                    + "small-memory machines. blst: native MSM — may be faster on some hardware, "
                    + "but its native buffers need ~10 GB beyond the heap (OOM risk under ~24 GB "
                    + "total memory — ADR-0034 M5).")
    Backend backend;

    @Option(names = "--out", defaultValue = "proofs", description = "Output directory for the proof. Default: ${DEFAULT-VALUE}.")
    Path outDir;

    @Option(names = "--account", defaultValue = "0", description = "CIP-1852 account index (m/1852'/1815'/N'). Default: ${DEFAULT-VALUE}.")
    int account;

    @Option(names = "--index", defaultValue = "0", description = "Address index (.../0/N). Default: ${DEFAULT-VALUE}.")
    int index;

    @Option(names = "--mainnet", description = "Show the mainnet address for the target (default: testnet).")
    boolean mainnet;

    @Option(names = "--no-self-verify", negatable = true,
            description = "Skip the off-chain pairing self-check after proving.")
    boolean selfVerify = true;

    @Option(names = "--no-cache",
            description = "Recompile the circuit instead of using/creating the r1cs.bin constraint "
                    + "cache in the keys directory (ADR-0034 M4).")
    boolean noCache;

    @Override
    public Integer call() throws Exception {
        var bundle = new Bundle(keysDir);
        if (!bundle.exists()) {
            System.err.println("No key bundle at " + keysDir.toAbsolutePath()
                    + "\nRun `setup` (coordinator) or download a published bundle into this directory.");
            return 2;
        }

        // ADR-0034 M4: the packed constraints are a pure function of the circuit, so a
        // fingerprint-matched r1cs.bin beside the key bundle skips the whole R1CS compile
        // (the circuit graph is still built later for witness calculation). A stale, foreign,
        // or tampered cache is ignored/harmless: the fingerprint gates staleness, and a proof
        // from wrong constraints cannot pass the pairing self-check against this bundle's VK.
        // Only the header is probed here — the full ~1 GB load happens after the witness is
        // packed, so the constraints never coexist with the witness-generation peak.
        String bundleFp = bundle.metadata().getProperty("fingerprint");
        Path cacheFile = keysDir.resolve("r1cs.bin");
        boolean cacheDeferred = !noCache && bundleFp != null && R1CSFlatIO.hasMatching(cacheFile, bundleFp);

        // ADR-0033: fail fast on an obviously-too-small heap, BEFORE the multi-GB circuit compile
        // and the mnemonic prompt. Sizes below the hard floor cannot complete regardless of
        // backend; with a matching constraint cache the compile is skipped and the floor is
        // 1 GB lower. round to nearest GB: -Xmx8g reports maxMemory() slightly under 8 GB.
        int hardMin = cacheDeferred ? HARD_MIN_CACHED_HEAP_GB : HARD_MIN_HEAP_GB;
        long maxHeapGb = (Runtime.getRuntime().maxMemory() + (1L << 29)) / (1L << 30);
        if (maxHeapGb < hardMin) {
            System.err.printf("Not enough heap: -Xmx is ~%d GB but proving this circuit needs at "
                    + "least ~%d GB (recommended %d GB). Re-run with a larger -Xmx (the fat-jar/native "
                    + "launchers auto-size to ~80%% of RAM), on a machine with enough RAM.%n",
                    maxHeapGb, hardMin, RECOMMENDED_HEAP_GB);
            return 2;
        }
        if (maxHeapGb < RECOMMENDED_HEAP_GB) {
            System.err.printf("Warning: -Xmx is ~%d GB; proving may be tight (recommended ~%d GB). "
                    + "Continuing.%n", maxHeapGb, RECOMMENDED_HEAP_GB);
        }

        var svc = new OwnershipCircuitService();
        long t0 = System.nanoTime();
        R1CSFlat flat = null;
        String fp;
        int numPublic;
        if (cacheDeferred) {
            fp = bundleFp;
            numPublic = Integer.parseInt(fp.substring(fp.lastIndexOf('p') + 1));
            System.out.printf("Constraint cache matches (%s) — compile skipped%n", cacheFile.getFileName());
        } else {
            System.out.println("Compiling circuit (BLS12-381) ...");
            svc.compile();
            int nc = svc.numConstraints(), nw = svc.numWires();
            numPublic = svc.numPublicInputs();
            fp = Bundle.fingerprint(nc, nw, numPublic);
            System.out.printf("  %,d constraints | %.1fs%n", nc, secs(t0));

            if (bundleFp != null && !bundleFp.equals(fp)) {
                System.err.println("Circuit/key mismatch: bundle fingerprint " + bundleFp
                        + " but this build's circuit is " + fp + ". The bundle was made for a different circuit.");
                return 2;
            }
            flat = svc.compile().flat();
            if (!noCache) {
                try {
                    long tc = System.nanoTime();
                    R1CSFlatIO.write(flat, fp, cacheFile);
                    System.out.printf("  constraints cached → %s (%.1fs; later proves skip the compile)%n",
                            cacheFile, secs(tc));
                } catch (Exception e) {
                    System.err.println("  (could not write r1cs cache: " + e.getMessage() + " — continuing)");
                }
            }
        }
        int bindingRows = bundle.isSnarkjsKey() ? numPublic + 1 : 0;

        String mnemonic = readMnemonic();
        if (mnemonic == null || mnemonic.isBlank()) {
            System.err.println("No mnemonic entered.");
            return 2;
        }
        var wallet = new WalletDerivation().derive(mnemonic.trim(), account, index,
                mainnet ? Networks.mainnet() : Networks.testnet());
        mnemonic = null; // drop the reference; nothing secret is persisted

        System.out.println("Proving ownership of:");
        System.out.println("  address : " + wallet.address());
        System.out.println("  pkh     : " + WalletDerivation.hex(wallet.pkh()));
        System.out.printf ("  path    : m/1852'/1815'/%d'/0/%d%n", account, index);

        System.out.println("Loading proving key (mmap) ...");
        long tl = System.nanoTime();
        java.lang.foreign.Arena csArena = null; // mmap arena for the deferred constraint cache
        var loaded = Groth16PkStore.load(keysDir);
        try {
            System.out.printf("  key loaded: %.1fs%n", secs(tl));

            System.out.println("Computing witness ...");
            long tw = System.nanoTime();
            // born-flat witness (ADR-0034 M7): evaluated into 4 MB chunks, consolidated after
            // the graph is released
            var witness = svc.witnessFlat(wallet.rootKL(), wallet.rootKR(), wallet.rootChainCode(), wallet.pkh());
            System.out.printf("  witness: %.1fs%n", secs(tw));

            if (cacheDeferred) {
                // deferred cache load (ADR-0034 M4) — the graph is gone, witness is packed.
                // M6a: the CSR arrays are mmap'd (segment-backed), not heap-loaded — like the key.
                long tc = System.nanoTime();
                csArena = java.lang.foreign.Arena.ofShared();
                flat = R1CSFlatIO.readMapped(cacheFile, fp, csArena);
                if (flat == null) { // vanished/corrupted since the header probe — recompile
                    System.err.println("  (r1cs cache unreadable — recompiling)");
                    flat = svc.compile().flat();
                }
                System.out.printf("  %,d constraints mapped: %.1fs%n", flat.rows(), secs(tc));
            }

            ProverBackend prover = selectBackend();
            System.out.println("Generating proof (" + backendLabel + ", multi-core) ...");
            long tp = System.nanoTime();
            Groth16ProofBLS381 proof = svc.prove(loaded, witness, flat, bindingRows, prover);
            flat = null;
            System.out.printf("  proof generated: %.1fs%n", secs(tp));
            if (!(proof.a().isOnCurve() && proof.b().isOnCurve() && proof.c().isOnCurve())) {
                System.err.println("Internal error: generated proof is not on-curve.");
                return 1;
            }

            Files.createDirectories(outDir);
            ProofIO.writeProof(outDir, proof);
            ProofIO.writePublicInputs(outDir, wallet.pkh(), wallet.address(), account, index, fp);

            if (selfVerify) {
                System.out.print("Self-check (off-chain pairing) ... ");
                System.out.flush();
                var pts = ProofIO.readProof(outDir.resolve(ProofIO.PROOF_FILE));
                var pub = ProofIO.readPublicInputs(outDir.resolve(ProofIO.PUBLIC_FILE));
                boolean ok = OffchainVerifier.verify(loaded, pts, pub);
                System.out.println(ok ? "PASS" : "FAIL");
                if (!ok) { System.err.println("Self-check failed — proof did not verify."); return 1; }
            }
        } finally {
            Bundle.closeQuietly(loaded);   // shared mmap Arena close is unsupported in a native image
            if (csArena != null) {
                try { csArena.close(); } catch (Throwable ignore) { /* native-image: unmapped at exit */ }
            }
        }

        System.out.printf("%nProof written to %s (%s, %s)%n", outDir.toAbsolutePath(),
                ProofIO.PROOF_FILE, ProofIO.PUBLIC_FILE);
        System.out.printf("Total: %.1f min%n", secs(t0) / 60);
        System.out.println("Next: `verify` (off-chain) or `verify --onchain` (against a node).");
        return 0;
    }

    private String backendLabel = "blst";

    /**
     * Pure Java is the default (ADR-0034 M5): same speed as blst at this circuit size, no native
     * lib, native-image-clean, and no hidden native memory — blst's concurrent MSM arenas need
     * ~10 GB beyond the heap at 19M constraints (a hard-capped 16 GB cgroup OOM-kills blst but
     * completes pure Java in ~2.6 min). {@code --backend blst} opts in explicitly; it may be
     * faster on some hardware.
     */
    private ProverBackend selectBackend() {
        if (backend != Backend.blst) { backendLabel = "java"; return ProverBackend.PURE_JAVA; }

        long totalGb = totalMemoryGb();
        if (totalGb > 0 && totalGb < 24) {
            System.err.printf("Warning: --backend blst on a ~%d GB machine — blst's native MSM "
                    + "buffers need ~10 GB beyond the heap at this circuit size and may be "
                    + "OOM-killed. --backend java is equally fast here. Continuing.%n", totalGb);
        }
        // blst reaches libblst via FFM downcalls, which aren't registered in this native image.
        if (System.getProperty("org.graalvm.nativeimage.imagecode") != null) {
            System.err.println("Note: blst is unavailable in the native binary — using the pure-Java "
                    + "backend (same speed).");
            backendLabel = "java";
            return ProverBackend.PURE_JAVA;
        }
        try {
            ProverBackend b = BlstProverBackend.create();
            backendLabel = "blst";
            return b;
        } catch (Throwable t) {
            System.err.println("blst native backend unavailable (" + t.getMessage()
                    + ") — falling back to the pure-Java backend (same speed).");
            backendLabel = "java";
            return ProverBackend.PURE_JAVA;
        }
    }

    /** Total physical (or cgroup-capped) memory in GB; -1 if undeterminable. Container-aware. */
    private static long totalMemoryGb() {
        try {
            var os = (com.sun.management.OperatingSystemMXBean)
                    java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            return (os.getTotalMemorySize() + (1L << 29)) >> 30;
        } catch (Throwable t) {
            return -1;
        }
    }

    /** Hidden interactive prompt; falls back to stdin only when there is no terminal (e.g. testing). */
    static String readMnemonic() throws java.io.IOException {
        var console = System.console();
        if (console != null) {
            char[] c = console.readPassword("Enter your wallet mnemonic (input hidden): ");
            return c == null ? null : new String(c);
        }
        System.err.println("WARNING: no interactive terminal — reading the mnemonic from stdin (NOT hidden). "
                + "Prefer running in a real terminal.");
        var br = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        return br.readLine();
    }

    private static double secs(long startNanos) { return (System.nanoTime() - startNanos) / 1e9; }
}
