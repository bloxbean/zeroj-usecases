package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.crypto.groth16.R1csExporter;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OwnershipCircuitService;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * Export the circuit to an iden3 {@code .r1cs} file — the input to an <b>external</b> snarkjs phase-2
 * ceremony. Run this, do the ceremony outside this tool, then bring the finalized key back with
 * {@code import}. The CLI itself never touches snarkjs or the powers-of-tau.
 */
@Command(name = "export-r1cs", mixinStandardHelpOptions = true,
        description = "Export the circuit r1cs for an external snarkjs phase-2 ceremony.")
public final class ExportR1csCommand implements Callable<Integer> {

    @Option(names = "--out", defaultValue = "circuit.r1cs",
            description = "Output .r1cs file. Default: ${DEFAULT-VALUE}.")
    Path out;

    @Override
    public Integer call() throws Exception {
        var svc = new OwnershipCircuitService();
        System.out.println("Compiling circuit (BLS12-381) ...");
        svc.compile();
        int nc = svc.numConstraints(), nw = svc.numWires(), np = svc.numPublicInputs();
        System.out.printf("  %,d constraints | %,d wires | %d public%n", nc, nw, np);

        R1csExporter.export(svc.constraints(), nw, np, out);
        System.out.println("Wrote " + out.toAbsolutePath() + " (" + Files.size(out) + " bytes)");

        String f = out.getFileName().toString();
        System.out.println("""

                Next — run the phase-2 ceremony EXTERNALLY with a prepared BLS12-381 ptau (power >= 25):
                  snarkjs groth16 setup %s <pot25_final.ptau> circuit_0000.zkey
                  snarkjs zkey contribute circuit_0000.zkey circuit_0001.zkey --name="c1" -v   (one per contributor)
                  snarkjs zkey beacon     circuit_0001.zkey circuit_final.zkey <beaconHashHex> 10
                  snarkjs zkey verify     %s <pot25_final.ptau> circuit_final.zkey
                Then bring the finalized key back in:
                  account-ownership-recovery-cli import --zkey circuit_final.zkey
                """.formatted(f, f));
        return 0;
    }
}
