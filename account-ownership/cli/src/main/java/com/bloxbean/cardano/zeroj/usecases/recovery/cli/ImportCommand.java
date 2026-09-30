package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import org.zeroj.crypto.groth16.Groth16PkStore;
import org.zeroj.crypto.groth16.ZkeyPkStoreImporter;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.OwnershipCircuitService;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

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

    @Option(names = "--sha256",
            description = "Expected SHA-256 of the --zkey file, taken from the ceremony's published and "
                    + "independently verified manifest. The import stops if the file does not match.")
    String sha256;

    @Option(names = "--allow-unpinned",
            description = "Import without checking --zkey against a published hash. For local rehearsals only: "
                    + "it cannot tell a genuine ceremony key from a swapped one.")
    boolean allowUnpinned;

    @Override
    public Integer call() throws Exception {
        // Everything that can be checked cheaply is checked before the (slow) circuit compile.
        if ((sha256 == null) == !allowUnpinned) {
            System.err.println("Choose exactly one of --sha256 <hex> (the ceremony's published .zkey hash) "
                    + "or --allow-unpinned (local rehearsals only).");
            return 2;
        }
        if (sha256 != null && !sha256.matches("[0-9a-fA-F]{64}")) {
            System.err.println("--sha256 must be a SHA-256 hash: 64 hexadecimal characters.");
            return 2;
        }
        if (!Files.isRegularFile(zkey)) {
            System.err.println("zkey not found: " + zkey);
            return 2;
        }
        var bundle = new Bundle(keysDir);
        boolean replaceExisting = bundle.exists();
        if (replaceExisting && !force) {
            System.err.println("A key bundle already exists at " + keysDir.toAbsolutePath()
                    + ". Use --force to overwrite.");
            return 2;
        }
        if (!replaceExisting && Files.exists(keysDir) && !isEmptyDirectory(keysDir)) {
            System.err.println(keysDir.toAbsolutePath() + " exists and is not a key bundle. "
                    + "Choose a new or empty --keys directory.");
            return 2;
        }

        var svc = new OwnershipCircuitService();
        System.out.println("Compiling circuit (BLS12-381) ...");
        svc.compile();
        int nc = svc.numConstraints(), nw = svc.numWires(), np = svc.numPublicInputs();

        // The importer stages atomically into a directory that must not exist yet. A forced re-import
        // goes to a fresh sibling first, so a rejected .zkey (wrong hash, wrong circuit) leaves the
        // existing bundle untouched; it is replaced only once the new store is imported and checked.
        if (!replaceExisting) Files.deleteIfExists(keysDir); // an empty directory, or none
        Path target = replaceExisting
                ? keysDir.resolveSibling(keysDir.getFileName() + ".import-" + System.nanoTime())
                : keysDir;

        System.out.println("Importing zkey -> proving-key store ...");
        var imported = sha256 != null
                ? ZkeyPkStoreImporter.importToPkStore(zkey, target, sha256)
                : ZkeyPkStoreImporter.importUnpinnedToPkStore(zkey, target);
        System.out.printf("  imported: %,d wires | %d public | domain %d%n",
                imported.numWires(), imported.numPublic(), imported.domainSize());
        if (imported.numWires() != nw || imported.numPublic() != np) {
            System.err.println("This zkey is for a different circuit (got " + imported.numWires() + " wires / "
                    + imported.numPublic() + " public; this circuit is " + nw + " / " + np + ").");
            deleteRecursively(target);
            return 2;
        }
        if (replaceExisting) {
            deleteRecursively(keysDir);
            Files.move(target, keysDir);
        }

        System.out.println("Exporting verification key (vk.json) ...");
        var loaded = Groth16PkStore.load(keysDir, imported.manifestSha256());
        try {
            VkIO.write(keysDir, Bundle.vkSetup(loaded));
        } finally {
            Bundle.closeQuietly(loaded);
        }

        bundle.finalizeAndReport("ceremony", nc, nw, np);
        System.out.println("  zkey SHA-256:     " + imported.sourceSha256()
                + (sha256 != null ? "  (matches --sha256)" : "  (NOT pinned: local rehearsal import)"));
        System.out.println("  store manifest:   " + imported.manifestSha256()
                + "  (record this to check the store later)");
        return 0;
    }

    private static boolean isEmptyDirectory(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) return false;
        try (Stream<Path> entries = Files.list(dir)) {
            return entries.findAny().isEmpty();
        }
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) return;
        try (Stream<Path> paths = Files.walk(dir)) {
            for (Path p : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(p);
        }
    }
}
