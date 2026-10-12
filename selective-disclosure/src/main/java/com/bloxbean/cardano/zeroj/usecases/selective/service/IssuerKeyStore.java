package com.bloxbean.cardano.zeroj.usecases.selective.service;

import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Properties;

/**
 * The issuer's EdDSA-Jubjub signing key, generated with {@link SecureRandom} on first start and
 * persisted in the demo data directory (ADR-0009 D11). It replaces the seed that earlier versions
 * published in the source, which let anyone sign credentials the deployed validator accepts.
 *
 * <p>Two files live side by side in the data directory:
 * <ul>
 *   <li>{@value #KEY_FILE} — the secret scalar, owner-only;</li>
 *   <li>{@value #DEPLOYMENT_FILE} — the deployment state: the issuer public key the validator is
 *       parameterised with.</li>
 * </ul>
 * Both are written atomically and durably (temp file in the same directory, fsync, rename, then
 * fsync of the directory).
 *
 * <p><b>Lifecycle.</b> With neither file, a fresh key is generated and both are written. With both,
 * the key is loaded and must match the recorded public key. With only the key (a crash between the
 * two writes), the key is loaded and the deployment state is written. If the deployment state exists
 * but the key is missing, unreadable or doesn't match, {@link #loadOrCreate} fails closed: it never
 * silently creates a new key. Resetting means removing both files together
 * ({@code ./demo.sh <demo> --clean-cache}).
 */
public final class IssuerKeyStore {

    public static final String KEY_FILE = "issuer-eddsa-jubjub.key";
    public static final String DEPLOYMENT_FILE = "issuer-deployment.properties";

    private static final String KEY_FORMAT = "zeroj-usecases.issuer-key.eddsa-jubjub.v1";
    private static final String DEPLOYMENT_FORMAT = "zeroj-usecases.issuer-deployment.v1";

    private IssuerKeyStore() {}

    /**
     * Load the issuer key from {@code dataDir}, or create it on a fresh install.
     *
     * @param demo the demo's name, for the reset hint in errors
     * @throws IllegalStateException if the key can't be used and the demo must stop (fail closed)
     */
    public static EdDSAJubjub.Keypair loadOrCreate(Path dataDir, String demo, SecureRandom random) {
        Path keyFile = dataDir.resolve(KEY_FILE);
        Path deploymentFile = dataDir.resolve(DEPLOYMENT_FILE);
        try {
            Files.createDirectories(dataDir);
            boolean deployed = Files.exists(deploymentFile);
            if (!Files.exists(keyFile)) {
                if (deployed) {
                    throw failClosed(demo, dataDir, "the deployment state " + deploymentFile
                            + " exists but the issuer key " + keyFile + " is missing");
                }
                EdDSAJubjub.Keypair created = EdDSAJubjub.generateKeypair(random);
                writeAtomically(keyFile, "format=" + KEY_FORMAT + "\nsk=" + hex64(created.sk()) + "\n");
                writeDeployment(deploymentFile, created.pk());
                return created;
            }
            EdDSAJubjub.Keypair loaded = readKey(keyFile, demo, dataDir);
            if (deployed) {
                JubjubPoint recorded = readDeployment(deploymentFile, demo, dataDir);
                if (!recorded.affineU().equals(loaded.pk().affineU())
                        || !recorded.affineV().equals(loaded.pk().affineV())) {
                    throw failClosed(demo, dataDir, "the issuer key " + keyFile
                            + " does not match the public key the validator was deployed with ("
                            + deploymentFile + ")");
                }
            } else {
                writeDeployment(deploymentFile, loaded.pk());
            }
            return loaded;
        } catch (IOException e) {
            throw failClosed(demo, dataDir, "the issuer key or deployment state can't be read or written: "
                    + e.getMessage());
        }
    }

    private static EdDSAJubjub.Keypair readKey(Path keyFile, String demo, Path dataDir) throws IOException {
        Properties p = load(keyFile);
        String sk = p.getProperty("sk");
        if (!KEY_FORMAT.equals(p.getProperty("format")) || sk == null || !sk.matches("[0-9a-f]{64}")) {
            throw failClosed(demo, dataDir, "the issuer key " + keyFile + " is corrupted");
        }
        try {
            return EdDSAJubjub.keypairFromSecret(new BigInteger(sk, 16));
        } catch (IllegalArgumentException e) {
            throw failClosed(demo, dataDir, "the issuer key " + keyFile + " is not a valid EdDSA-Jubjub secret");
        }
    }

    private static JubjubPoint readDeployment(Path file, String demo, Path dataDir) throws IOException {
        Properties p = load(file);
        String u = p.getProperty("issuerPkU");
        String v = p.getProperty("issuerPkV");
        if (!DEPLOYMENT_FORMAT.equals(p.getProperty("format"))
                || u == null || !u.matches("[0-9a-f]{64}") || v == null || !v.matches("[0-9a-f]{64}")) {
            throw failClosed(demo, dataDir, "the deployment state " + file + " is corrupted");
        }
        try {
            return JubjubPoint.fromAffine(new BigInteger(u, 16), new BigInteger(v, 16));
        } catch (IllegalArgumentException e) {
            throw failClosed(demo, dataDir, "the deployment state " + file + " holds an invalid public key");
        }
    }

    private static void writeDeployment(Path file, JubjubPoint pk) throws IOException {
        writeAtomically(file, "format=" + DEPLOYMENT_FORMAT
                + "\nissuerPkU=" + hex64(pk.affineU()) + "\nissuerPkV=" + hex64(pk.affineV()) + "\n");
    }

    private static Properties load(Path file) throws IOException {
        String text = Files.readString(file, StandardCharsets.UTF_8);
        Properties p = new Properties();
        try (Reader reader = new StringReader(text)) {
            p.load(reader);
        }
        return p;
    }

    /**
     * Write {@code content} to a new owner-only temp file in the target's directory, fsync it, rename
     * it over the target, then fsync the directory so the rename survives a crash. (Directories
     * can't be opened for fsync on Windows; there the rename is atomic but not forced.)
     */
    static void writeAtomically(Path target, String content) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        boolean posix = dir.getFileSystem().supportedFileAttributeViews().contains("posix");
        Path tmp = posix
                ? Files.createTempFile(dir, "." + target.getFileName(), ".tmp",
                        PosixFilePermissions.asFileAttribute(
                                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)))
                : Files.createTempFile(dir, "." + target.getFileName(), ".tmp");
        try {
            if (!posix) {
                var f = tmp.toFile();
                f.setReadable(false, false);
                f.setWritable(false, false);
                f.setReadable(true, true);
                f.setWritable(true, true);
            }
            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                channel.write(ByteBuffer.wrap(content.getBytes(StandardCharsets.UTF_8)));
                channel.force(true);
            }
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp);
        }
        if (posix) {
            // Make the rename itself durable: fsync the directory that holds the new entry.
            try (FileChannel directory = FileChannel.open(dir, StandardOpenOption.READ)) {
                directory.force(true);
            }
        }
    }

    private static String hex64(BigInteger value) {
        String hex = value.toString(16);
        return "0".repeat(64 - hex.length()) + hex;
    }

    private static IllegalStateException failClosed(String demo, Path dataDir, String reason) {
        return new IllegalStateException("Refusing to start: " + reason + ". The demo never replaces an "
                + "issuer key silently. To start a fresh deployment, with a new issuer key and new script "
                + "hashes, run ./demo.sh " + demo + " --clean-cache (or delete " + dataDir.toAbsolutePath()
                + "), which removes the key and the deployment state together.");
    }
}
