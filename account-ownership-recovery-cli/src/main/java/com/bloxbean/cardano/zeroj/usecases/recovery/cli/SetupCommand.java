package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyPkStoreImporter;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OwnershipCircuitService;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * One-time trusted setup: compile the circuit, run the trusted setup, and export the proving-key
 * bundle (proving key + verification key + metadata + integrity manifest) into a keys directory.
 * Normally run once by a coordinator; the bundle is then published for users to prove against.
 */
@Command(name = "setup", mixinStandardHelpOptions = true,
        description = "One-time: produce the proving/verification key bundle (coordinator).")
public final class SetupCommand implements Callable<Integer> {

    enum TauMode { local, ptau, filecoin }

    @Option(names = "--tau", defaultValue = "local",
            description = "Setup mode: local (single-party, dev/testing), ptau (real phase-2 from a "
                    + "prepared .ptau, needs snarkjs), filecoin (auto-download the attested phase-1). "
                    + "Default: ${DEFAULT-VALUE}.")
    TauMode tau;

    @Option(names = "--ptau", description = "Prepared .ptau file (2^25+) for --tau ptau.")
    Path ptau;

    @Option(names = "--zkey", description = "Import an already-finalized .zkey (a real ceremony's output) instead of running snarkjs setup.")
    Path zkey;

    @Option(names = "--contributions", defaultValue = "1",
            description = "Coordinator contributions before the finalization beacon (--tau ptau). Default: ${DEFAULT-VALUE}.")
    int contributions;

    @Option(names = "--work-dir", description = "Scratch dir for r1cs/zkey/ptau (default: <keys>/../aor-ceremony-work).")
    Path workDir;

    @Option(names = "--timeout-hours", defaultValue = "48",
            description = "Per-step snarkjs timeout in hours. Default: ${DEFAULT-VALUE}.")
    int timeoutHours;

    @Option(names = "--filecoin-url", description = "Phase-1 source URL for --tau filecoin (resumable download).")
    String filecoinUrl;

    @Option(names = "--phase1-file", description = "Local phase-1 file for --tau filecoin (skips download).")
    Path phase1File;

    @Option(names = "--i-understand-filecoin-cost",
            description = "Acknowledge the large download + multi-hour prepare of --tau filecoin.")
    boolean ackFilecoin;

    @Option(names = "--truncate-to", defaultValue = "-1",
            description = "Best-effort truncate the phase-1 to 2^N before prepare (--tau filecoin).")
    int truncateTo;

    @Option(names = "--keys", defaultValue = "keys",
            description = "Output key-bundle directory. Default: ${DEFAULT-VALUE}.")
    Path keysDir;

    @Option(names = "--i-understand-insecure",
            description = "Acknowledge that --tau local produces a DEV-ONLY key (this machine could "
                    + "forge proofs). Required for --tau local.")
    boolean ackInsecure;

    @Option(names = "--force", description = "Overwrite an existing key bundle in the keys directory.")
    boolean force;

    @Override
    public Integer call() throws Exception {
        var bundle = new Bundle(keysDir);
        if (bundle.exists() && !force) {
            System.err.println("A key bundle already exists at " + keysDir.toAbsolutePath()
                    + ". Use --force to overwrite.");
            return 2;
        }
        Files.createDirectories(keysDir);

        var svc = new OwnershipCircuitService();
        System.out.println("Compiling circuit (BLS12-381) ...");
        long t0 = System.nanoTime();
        svc.compile();
        int nc = svc.numConstraints(), nw = svc.numWires(), np = svc.numPublicInputs();
        System.out.printf("  %,d constraints | %,d wires | %d public | %.1fs%n",
                nc, nw, np, secs(t0));

        switch (tau) {
            case local -> {
                if (!ackInsecure) {
                    System.err.println("""
                            --tau local runs a SINGLE-PARTY trusted setup: this machine learns the setup
                            randomness and could forge proofs. Fine for testing; for anything trusted use
                            --tau ptau / --tau filecoin (a multi-party ceremony). Re-run with
                            --i-understand-insecure to proceed.""");
                    return 2;
                }
                System.out.println("Running single-party trusted setup (dev/testing) — this takes a while ...");
                long t1 = System.nanoTime();
                var setup = svc.localSetup();
                System.out.printf("  setup complete: %.1f min%n", secs(t1) / 60);
                System.out.println("Saving proving-key store + verification key ...");
                Groth16PkStore.save(setup, keysDir);
                VkIO.write(keysDir, setup);
            }
            case ptau -> {
                int rc = ptauSetup(svc, resolveWorkDir(), ptau);
                if (rc != 0) return rc;
            }
            case filecoin -> {
                Path prepared = new FilecoinSetup(resolveWorkDir(), timeoutHours * 3600L)
                        .source(filecoinUrl, phase1File)
                        .ackCost(ackFilecoin)
                        .truncateTo(truncateTo)
                        .downloadAndPrepare(force);
                if (prepared == null) return 2;
                int rc = ptauSetup(svc, resolveWorkDir(), prepared);
                if (rc != 0) return rc;
            }
        }

        System.out.println("Writing bundle metadata + integrity manifest ...");
        bundle.writeMetadata(tau.name(), nc, nw, np, zerojVersion(), java.time.Instant.now().toString());
        bundle.writeIntegrityManifest();

        long bytes = dirSize(keysDir);
        System.out.printf("%nKey bundle ready at %s (%.1f GB)%n", keysDir.toAbsolutePath(), bytes / 1e9);
        System.out.println("  fingerprint: " + Bundle.fingerprint(nc, nw, np));
        System.out.println("Next: `prove` to generate a proof, or publish this directory for users.");
        return 0;
    }

    /**
     * Real phase-2 setup from a prepared {@code .ptau}: export R1CS → snarkjs {@code groth16 setup}
     * (+ coordinator contributions + beacon) or import a supplied finalized {@code .zkey} → import
     * into the proving-key store → export {@code vk.json}.
     */
    private int ptauSetup(OwnershipCircuitService svc, Path work, Path ptauFile) throws Exception {
        if (ptauFile == null && zkey == null) {
            System.err.println("--tau ptau needs either --ptau <prepared.ptau> or --zkey <finalized.zkey>.");
            return 2;
        }
        var snark = new SnarkjsSetup(work, timeoutHours * 3600L);
        if (zkey == null && !snark.available()) {
            System.err.println("snarkjs not found. Install it (npm i -g snarkjs) or pass --zkey <finalized.zkey>.");
            return 2;
        }
        System.out.println("Phase-2 setup via snarkjs (work dir: " + work + ") ...");
        Path r1cs = snark.exportR1cs(svc.constraints(), svc.numWires(), svc.numPublicInputs(), force);

        Path finalZkey;
        if (zkey != null) {
            System.out.println("Using supplied finalized zkey: " + zkey);
            if (ptauFile != null && snark.available()) snark.verify(r1cs, ptauFile, zkey);
            finalZkey = zkey;
        } else {
            finalZkey = snark.runCeremony(r1cs, ptauFile, contributions, force);
        }

        var imported = snark.importToStore(finalZkey, keysDir);
        System.out.printf("  imported: %,d wires | %d public | domain %d%n",
                imported.numWires(), imported.numPublic(), imported.domainSize());
        System.out.println("Exporting verification key (vk.json) ...");
        try (var loaded = Groth16PkStore.load(keysDir)) {
            VkIO.write(keysDir, Bundle.vkSetup(loaded));
        }
        return 0;
    }

    private Path resolveWorkDir() throws java.io.IOException {
        Path w = workDir != null ? workDir
                : keysDir.toAbsolutePath().getParent().resolve("aor-ceremony-work");
        Files.createDirectories(w);
        return w;
    }

    private static double secs(long startNanos) { return (System.nanoTime() - startNanos) / 1e9; }

    static String zerojVersion() {
        String v = Groth16PkStore.class.getPackage().getImplementationVersion();
        return v != null ? v : "unknown";
    }

    private static long dirSize(Path dir) throws java.io.IOException {
        try (var s = Files.walk(dir)) {
            return s.filter(Files::isRegularFile).mapToLong(p -> {
                try { return Files.size(p); } catch (java.io.IOException e) { return 0; }
            }).sum();
        }
    }
}
