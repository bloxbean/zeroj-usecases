package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OwnershipCircuitService;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * Produce a <b>local, single-party</b> key bundle for development/testing (runs entirely offline —
 * no snarkjs, no ceremony). This machine generates the setup randomness and could forge proofs, so
 * the bundle is dev-only. For a trustworthy bundle, run a phase-2 ceremony externally (see
 * {@code export-r1cs}) and bring the result in with {@code import}.
 *
 * <p>The output {@code .bin} bundle can be kept and reused: run this once, then anyone can
 * {@code prove}/{@code verify} against it for a quick demo (~5 min) without repeating setup.</p>
 */
@Command(name = "setup", mixinStandardHelpOptions = true,
        description = "Generate a LOCAL (single-party, dev-only) key bundle for testing.")
public final class SetupCommand implements Callable<Integer> {

    @Option(names = "--keys", defaultValue = "keys",
            description = "Output key-bundle directory. Default: ${DEFAULT-VALUE}.")
    Path keysDir;

    @Option(names = "--i-understand-insecure",
            description = "Acknowledge that this produces a DEV-ONLY key (this machine could forge proofs).")
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
        if (!ackInsecure) {
            System.err.println("""
                    `setup` runs a SINGLE-PARTY trusted setup: this machine learns the setup randomness
                    and could forge proofs — fine for testing, never for production. For a trustworthy
                    bundle, run a ceremony externally (see `export-r1cs`) and `import` the result.
                    Re-run with --i-understand-insecure to proceed.""");
            return 2;
        }
        Files.createDirectories(keysDir);

        var svc = new OwnershipCircuitService();
        System.out.println("Compiling circuit (BLS12-381) ...");
        svc.compile();
        int nc = svc.numConstraints(), nw = svc.numWires(), np = svc.numPublicInputs();
        System.out.printf("  %,d constraints | %,d wires | %d public%n", nc, nw, np);

        System.out.println("Running single-party trusted setup (dev/testing) — this takes a while ...");
        long t = System.nanoTime();
        // ADR-0035: streamed setup — every point is written straight into the mmap'd key files,
        // so no proving-key array is ever heap-resident.
        var setup = svc.localSetupToStore(keysDir);
        System.out.printf("  setup complete (streamed to store): %.1f min%n", (System.nanoTime() - t) / 6e10);
        VkIO.write(keysDir, setup);

        bundle.finalizeAndReport("local", nc, nw, np);
        return 0;
    }
}
