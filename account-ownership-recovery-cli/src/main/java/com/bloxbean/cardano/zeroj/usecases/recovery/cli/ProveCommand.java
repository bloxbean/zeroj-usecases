package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.client.common.model.Networks;
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
 * downloaded key bundle, it takes ~2.5 min end-to-end with ≥24 GB of heap (the proving key is
 * mmap-loaded instantly; the proof itself is ~2 min on the blst multi-core backend — ADR-0033).
 *
 * <p>The mnemonic is read via a hidden interactive prompt — never a command-line argument, an
 * environment variable, or a file. The root key derived from it stays in memory and is never
 * written or transmitted; only the proof and its public inputs are saved.</p>
 */
@Command(name = "prove", mixinStandardHelpOptions = true,
        description = "Generate an ownership proof from your mnemonic.")
public final class ProveCommand implements Callable<Integer> {

    // ADR-0033 measured heap floors for the 19M-constraint prove: 20 GB passes (2026-07-09,
    // blst, ~2.6 min), 16 GB OOMs in the R1CS frontend compile before the prove is reached.
    // HARD_MIN: below this the run cannot complete; RECOMMENDED: no-GC-tax headroom (~2.2 min).
    private static final int HARD_MIN_HEAP_GB = 20;
    private static final int RECOMMENDED_HEAP_GB = 24;

    enum Backend { blst, java }

    @Option(names = "--keys", defaultValue = "keys", description = "Key-bundle directory. Default: ${DEFAULT-VALUE}.")
    Path keysDir;

    @Option(names = "--backend", defaultValue = "blst",
            description = "Prover backend: blst (native) or java (pure-Java multi-core, no native "
                    + "lib). Both ~2-3 min since ADR-0033. Default: ${DEFAULT-VALUE}.")
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

    @Override
    public Integer call() throws Exception {
        var bundle = new Bundle(keysDir);
        if (!bundle.exists()) {
            System.err.println("No key bundle at " + keysDir.toAbsolutePath()
                    + "\nRun `setup` (coordinator) or download a published bundle into this directory.");
            return 2;
        }

        // ADR-0033: fail fast on an obviously-too-small heap, BEFORE the multi-GB circuit compile
        // and the mnemonic prompt. Sizes below the hard floor cannot complete regardless of
        // backend — 16 GB dies in the R1CS compile itself, so this check must come first.
        // round to nearest GB: -Xmx20g reports maxMemory() slightly under 20 GB
        long maxHeapGb = (Runtime.getRuntime().maxMemory() + (1L << 29)) / (1L << 30);
        if (maxHeapGb < HARD_MIN_HEAP_GB) {
            System.err.printf("Not enough heap: -Xmx is ~%d GB but proving this circuit needs at "
                    + "least ~%d GB (recommended %d GB). Re-run with a larger -Xmx (the fat-jar/native "
                    + "launchers auto-size to ~80%% of RAM), on a machine with enough RAM.%n",
                    maxHeapGb, HARD_MIN_HEAP_GB, RECOMMENDED_HEAP_GB);
            return 2;
        }
        if (maxHeapGb < RECOMMENDED_HEAP_GB) {
            System.err.printf("Warning: -Xmx is ~%d GB; proving may be tight (recommended ~%d GB). "
                    + "Continuing.%n", maxHeapGb, RECOMMENDED_HEAP_GB);
        }

        var svc = new OwnershipCircuitService();
        System.out.println("Compiling circuit (BLS12-381) ...");
        long t0 = System.nanoTime();
        svc.compile();
        int nc = svc.numConstraints(), nw = svc.numWires(), np = svc.numPublicInputs();
        String fp = Bundle.fingerprint(nc, nw, np);
        System.out.printf("  %,d constraints | %.1fs%n", nc, secs(t0));

        String bundleFp = bundle.metadata().getProperty("fingerprint");
        if (bundleFp != null && !bundleFp.equals(fp)) {
            System.err.println("Circuit/key mismatch: bundle fingerprint " + bundleFp
                    + " but this build's circuit is " + fp + ". The bundle was made for a different circuit.");
            return 2;
        }

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
        var loaded = Groth16PkStore.load(keysDir);
        try {
            System.out.printf("  key loaded: %.1fs%n", secs(tl));

            System.out.println("Computing witness ...");
            long tw = System.nanoTime();
            BigInteger[] witness = svc.witness(wallet.rootKL(), wallet.rootKR(), wallet.rootChainCode(), wallet.pkh());
            System.out.printf("  witness: %.1fs%n", secs(tw));

            ProverBackend prover = selectBackend();
            System.out.println("Generating proof (" + backendLabel + ", multi-core) ...");
            long tp = System.nanoTime();
            Groth16ProofBLS381 proof = svc.prove(loaded, witness, prover, bundle.isSnarkjsKey());
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
        }

        System.out.printf("%nProof written to %s (%s, %s)%n", outDir.toAbsolutePath(),
                ProofIO.PROOF_FILE, ProofIO.PUBLIC_FILE);
        System.out.printf("Total: %.1f min%n", secs(t0) / 60);
        System.out.println("Next: `verify` (off-chain) or `verify --onchain` (against a node).");
        return 0;
    }

    private String backendLabel = "blst";

    /** blst by default; pure-Java fallback if the native lib can't load or we're in a GraalVM image. */
    private ProverBackend selectBackend() {
        if (backend == Backend.java) { backendLabel = "java"; return ProverBackend.PURE_JAVA; }
        // blst reaches libblst via FFM downcalls, which aren't registered in this native image.
        // Route to the pure-Java backend so proving works — since ADR-0033 (mmap'd key, no
        // marshalling) it proves in the same ~2-3 min as blst at this scale.
        if (System.getProperty("org.graalvm.nativeimage.imagecode") != null) {
            System.err.println("Note: blst is unavailable in the native binary — using the pure-Java "
                    + "backend (comparable speed).");
            backendLabel = "java";
            return ProverBackend.PURE_JAVA;
        }
        try {
            ProverBackend b = BlstProverBackend.create();
            backendLabel = "blst";
            return b;
        } catch (Throwable t) {
            System.err.println("blst native backend unavailable (" + t.getMessage()
                    + ") — falling back to the pure-Java backend (comparable speed). "
                    + "Use --backend java to silence this.");
            backendLabel = "java";
            return ProverBackend.PURE_JAVA;
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
