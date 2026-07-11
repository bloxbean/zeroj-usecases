package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Keys;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Pipeline;
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
    private static final int HARD_MIN_HEAP_GB = 8;
    private static final int HARD_MIN_CACHED_HEAP_GB = 7;
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

    @Option(names = "--account", defaultValue = "0",
            description = "CIP-1852 account index (m/1852'/1815'/N'). Circuit v2 fixes the account "
                    + "at 0' — only 0 is accepted. Default: ${DEFAULT-VALUE}.")
    int account;

    @Option(names = "--role", defaultValue = "0",
            description = "CIP-1852 role/chain (.../N/…): 0 = external payment address, "
                    + "1 = internal/change. Default: ${DEFAULT-VALUE}.")
    int role;

    @Option(names = "--index", defaultValue = "0", description = "Address index (.../role/N). Default: ${DEFAULT-VALUE}.")
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
        // The circuit derives at account 0' (hardened; role/index are witness inputs since v2).
        if (account != 0) {
            System.err.println("--account " + account + " is not supported: circuit v2 fixes the "
                    + "account at 0' (role and index are free). Re-run with --account 0.");
            return 2;
        }
        if (role < 0 || index < 0) {
            System.err.println("--role and --index must be non-negative soft indices (< 2^31).");
            return 2;
        }
        var bundle = new Bundle(keysDir);
        if (!bundle.exists()) {
            System.err.println("No key bundle at " + keysDir.toAbsolutePath()
                    + "\nRun `setup` (coordinator) or download a published bundle into this directory.");
            return 2;
        }

        // ADR-0034 M4: a fingerprint-matched r1cs.bin beside the key bundle skips the whole R1CS
        // compile; the mmap'd load is deferred until after the witness (Groth16Pipeline owns that
        // ordering now). A stale, foreign, or tampered cache is ignored/harmless: the fingerprint
        // gates staleness, and a proof from wrong constraints cannot pass the pairing self-check.
        String bundleFp = bundle.metadata().getProperty("fingerprint");
        Path cacheFile = noCache ? null : keysDir.resolve(Groth16Pipeline.R1CS_CACHE);
        boolean cacheDeferred = Groth16Pipeline.cacheMatches(cacheFile, bundleFp);

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

        // Memoized compile — Groth16Pipeline invokes it only when the cache can't be used.
        var ccBox = new Groth16Pipeline.Compiled[1];
        java.util.function.Supplier<Groth16Pipeline.Compiled> compile = () -> {
            if (ccBox[0] == null) {
                System.out.println("Compiling circuit (BLS12-381) ...");
                long tc = System.nanoTime();
                var cs = svc.compile();
                ccBox[0] = new Groth16Pipeline.Compiled(cs.flat(),
                        cs.numConstraints(), cs.numWires(), cs.numPublicInputs());
                System.out.printf("  %,d constraints | %.1fs%n", cs.numConstraints(), secs(tc));
            }
            return ccBox[0];
        };
        if (cacheDeferred)
            System.out.printf("Constraint cache matches (%s) — compile skipped%n", cacheFile.getFileName());

        // numPublic (for the snarkjs binding rows) comes from the bundle fingerprint — every
        // bundle carries one; a fingerprint-less bundle falls back to an eager compile.
        var dims = Groth16Pipeline.parseFingerprint(bundleFp);
        int numPublic = dims != null ? dims.numPublic() : compile.get().numPublic();
        int bindingRows = bundle.isSnarkjsKey() ? numPublic + 1 : 0;

        String mnemonic = readMnemonic();
        if (mnemonic == null || mnemonic.isBlank()) {
            System.err.println("No mnemonic entered.");
            return 2;
        }
        var wallet = new WalletDerivation().derive(mnemonic.trim(), account, role, index,
                mainnet ? Networks.mainnet() : Networks.testnet());
        mnemonic = null; // drop the reference; nothing secret is persisted

        System.out.println("Proving ownership of:");
        System.out.println("  address : " + wallet.address());
        System.out.println("  pkh     : " + WalletDerivation.hex(wallet.pkh()));
        System.out.printf ("  path    : m/1852'/1815'/%d'/%d/%d (path stays private — only the pkh is a public input)%n",
                account, role, index);

        System.out.println("Loading proving key (mmap) ...");
        long tl = System.nanoTime();
        var loaded = Groth16PkStore.load(keysDir);
        try {
            System.out.printf("  key loaded: %.1fs%n", secs(tl));
            ProverBackend prover = selectBackend();

            // Narrates the pipeline stages in this CLI's format; tp anchors the prove timer at
            // the same boundary as before (start of computeH — witness and mapped load excluded).
            var progress = new Groth16Pipeline.Progress() {
                long tp;
                @Override public void constraintCacheWritten(Path f, double s) {
                    System.out.printf("  constraints cached → %s (%.1fs; later proves skip the compile)%n", f, s);
                }
                @Override public void constraintCacheWriteFailed(Exception e) {
                    System.err.println("  (could not write r1cs cache: " + e.getMessage() + " — continuing)");
                }
                @Override public void constraintsMapped(int rows, double s) {
                    System.out.printf("  %,d constraints mapped: %.1fs%n", rows, s);
                }
                @Override public void constraintCacheUnreadable() {
                    System.err.println("  (r1cs cache unreadable — recompiling)");
                }
                @Override public void proveStarted() {
                    System.out.println("Generating proof (" + backendLabel + ", multi-core) ...");
                    tp = System.nanoTime();
                }
            };

            Groth16ProofBLS381 proof;
            try {
                proof = Groth16Pipeline.prove(Groth16Keys.of(loaded), cacheFile, bundleFp,
                        compile,
                        () -> {
                            System.out.println("Computing witness ...");
                            long tw = System.nanoTime();
                            var w = svc.witnessFlat(wallet.rootKL(), wallet.rootKR(),
                                    wallet.rootChainCode(), wallet.role(), wallet.index(), wallet.pkh());
                            System.out.printf("  witness: %.1fs%n", secs(tw));
                            return w;
                        },
                        bindingRows, prover, progress);
            } catch (IllegalStateException e) {
                System.err.println(e.getMessage()); // circuit/key fingerprint mismatch
                return 2;
            }
            String fp = bundleFp != null ? bundleFp : ccBox[0].fingerprint();
            System.out.printf("  proof generated: %.1fs%n", secs(progress.tp));
            if (!(proof.a().isOnCurve() && proof.b().isOnCurve() && proof.c().isOnCurve())) {
                System.err.println("Internal error: generated proof is not on-curve.");
                return 1;
            }

            Files.createDirectories(outDir);
            ProofIO.writeProof(outDir, proof);
            ProofIO.writePublicInputs(outDir, wallet.pkh(), wallet.address(), fp);

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
