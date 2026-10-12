package com.bloxbean.cardano.zeroj.usecases.reserves.config;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.regex.Pattern;

/**
 * The deployed {@code ReserveAttestation} parameters, kept next to the custodian key in the demo
 * data directory (ADR-0009 D11). Both are removed together by {@code ./demo.sh proof-of-reserves
 * --clean-cache}, which amounts to a fresh deployment.
 */
public record DeploymentState(String custodianPkh, long genesisMs, long periodMs, String policyId) {

    public static final String FILE = "reserves-deployment.properties";

    private static final Pattern HEX28 = Pattern.compile("[0-9a-f]{56}");

    public DeploymentState {
        if (custodianPkh == null || !HEX28.matcher(custodianPkh).matches()) {
            throw new IllegalArgumentException("custodianPkh must be 28 bytes of lowercase hex");
        }
        if (policyId == null || !HEX28.matcher(policyId).matches()) {
            throw new IllegalArgumentException("policyId must be 28 bytes of lowercase hex");
        }
        if (genesisMs < 0 || periodMs <= 0) {
            throw new IllegalArgumentException("genesisMs must be >= 0 and periodMs > 0");
        }
    }

    public static Path path(Path dataDir) {
        return dataDir.resolve(FILE);
    }

    public static boolean exists(Path dataDir) {
        return Files.exists(path(dataDir));
    }

    /** Reads the state, failing on anything unreadable or malformed. */
    public static DeploymentState read(Path dataDir) {
        Path file = path(dataDir);
        try {
            var props = new Properties();
            props.load(new StringReader(Files.readString(file, StandardCharsets.UTF_8)));
            return new DeploymentState(
                    props.getProperty("custodianPkh"),
                    Long.parseLong(props.getProperty("genesisMs", "")),
                    Long.parseLong(props.getProperty("periodMs", "")),
                    props.getProperty("policyId"));
        } catch (IOException | RuntimeException e) {
            throw new IllegalStateException("Reserves deployment state " + file + " is unreadable or corrupt ("
                    + e.getMessage() + "). Reset with ./demo.sh proof-of-reserves --clean-cache.", e);
        }
    }

    public void write(Path dataDir) throws IOException {
        var props = new Properties();
        props.setProperty("custodianPkh", custodianPkh);
        props.setProperty("genesisMs", Long.toString(genesisMs));
        props.setProperty("periodMs", Long.toString(periodMs));
        props.setProperty("policyId", policyId);
        var out = new StringWriter();
        props.store(out, "ReserveAttestation deployment (ADR-0009 D4/D11)");
        DemoFiles.writeAtomically(path(dataDir), out.toString().getBytes(StandardCharsets.UTF_8));
    }
}
