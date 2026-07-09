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
 * Import a finalized snarkjs {@code .zkey} — the output of an external phase-2 ceremony — into a key
 * bundle usable by {@code prove}/{@code verify}. Pure Java: <b>no snarkjs required</b>. Produces the
 * same bundle shape as {@code setup} (proving-key store + {@code vk.json} + metadata + integrity),
 * so downstream commands don't care whether the keys came from a local setup or a ceremony.
 */
@Command(name = "import", mixinStandardHelpOptions = true,
        description = "Import a finalized snarkjs .zkey (ceremony output) into a key bundle.")
public final class ImportCommand implements Callable<Integer> {

    @Option(names = "--zkey", required = true, description = "Finalized ceremony .zkey to import.")
    Path zkey;

    @Option(names = "--keys", defaultValue = "keys",
            description = "Output key-bundle directory. Default: ${DEFAULT-VALUE}.")
    Path keysDir;

    @Option(names = "--force", description = "Overwrite an existing key bundle in the keys directory.")
    boolean force;

    @Override
    public Integer call() throws Exception {
        if (!Files.isRegularFile(zkey)) {
            System.err.println("zkey not found: " + zkey);
            return 2;
        }
        var bundle = new Bundle(keysDir);
        if (bundle.exists() && !force) {
            System.err.println("A key bundle already exists at " + keysDir.toAbsolutePath()
                    + ". Use --force to overwrite.");
            return 2;
        }
        Files.createDirectories(keysDir);

        var svc = new OwnershipCircuitService();
        System.out.println("Compiling circuit (BLS12-381) ...");
        svc.compile();
        int nc = svc.numConstraints(), nw = svc.numWires(), np = svc.numPublicInputs();

        System.out.println("Importing zkey -> proving-key store ...");
        var imported = ZkeyPkStoreImporter.importToPkStore(zkey, keysDir);
        System.out.printf("  imported: %,d wires | %d public | domain %d%n",
                imported.numWires(), imported.numPublic(), imported.domainSize());
        if (imported.numWires() != nw || imported.numPublic() != np) {
            System.err.println("This zkey is for a different circuit (got " + imported.numWires() + " wires / "
                    + imported.numPublic() + " public; this circuit is " + nw + " / " + np + ").");
            return 2;
        }

        System.out.println("Exporting verification key (vk.json) ...");
        var loaded = Groth16PkStore.load(keysDir);
        try {
            VkIO.write(keysDir, Bundle.vkSetup(loaded));
        } finally {
            Bundle.closeQuietly(loaded);
        }

        bundle.finalizeAndReport("ceremony", nc, nw, np);
        return 0;
    }
}
