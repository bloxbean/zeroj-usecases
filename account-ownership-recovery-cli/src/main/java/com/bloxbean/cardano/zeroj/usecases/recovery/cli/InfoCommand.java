package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

/**
 * Inspect a key bundle: setup mode, circuit fingerprint, size, and (optionally) integrity.
 */
@Command(name = "info", mixinStandardHelpOptions = true, description = "Inspect a key bundle.")
public final class InfoCommand implements Callable<Integer> {

    @Option(names = "--keys", defaultValue = "keys", description = "Key-bundle directory. Default: ${DEFAULT-VALUE}.")
    Path keysDir;

    @Option(names = "--verify-integrity",
            description = "Recompute and check SHA256SUMS (reads the whole ~23 GB bundle; slow).")
    boolean verifyIntegrity;

    @Override
    public Integer call() throws Exception {
        var bundle = new Bundle(keysDir);
        System.out.println("Key bundle: " + keysDir.toAbsolutePath());
        if (!bundle.exists()) {
            System.out.println("  status: NOT PRESENT (run `setup`, or download a published bundle here)");
            return 1;
        }
        var m = bundle.metadata();
        System.out.println("  setup mode  : " + m.getProperty("setupMode")
                + ("local".equals(m.getProperty("setupMode")) ? "  (DEV-ONLY — single-party)" : ""));
        System.out.println("  constraints : " + m.getProperty("numConstraints"));
        System.out.println("  fingerprint : " + m.getProperty("fingerprint"));
        System.out.println("  zeroj       : " + m.getProperty("zerojVersion"));
        System.out.println("  created     : " + m.getProperty("createdAt"));
        System.out.printf("  size        : %.1f GB%n", dirSize(keysDir) / 1e9);
        System.out.println("  vk.json     : " + (VkIO.exists(keysDir) ? "present (fast verify)" : "absent (built on first verify)"));

        if (verifyIntegrity) {
            System.out.print("  integrity   : verifying (hashing the whole bundle) ... ");
            System.out.flush();
            var problems = bundle.verifyIntegrity();
            if (problems.isEmpty()) System.out.println("OK");
            else { System.out.println("FAILED"); problems.forEach(p -> System.out.println("    - " + p)); return 1; }
        } else {
            System.out.println("  integrity   : (run with --verify-integrity to check SHA256SUMS)");
        }
        return 0;
    }

    private static long dirSize(Path dir) throws java.io.IOException {
        try (var s = Files.walk(dir)) {
            return s.filter(Files::isRegularFile).mapToLong(p -> {
                try { return Files.size(p); } catch (java.io.IOException e) { return 0; }
            }).sum();
        }
    }
}
