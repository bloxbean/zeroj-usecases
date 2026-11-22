package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.crypto.bip39.MnemonicCode;
import com.bloxbean.cardano.client.util.HexUtil;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;

/**
 * The DPP manufacturer's and auditor's wallet keys (ADR-0009 D11). Each is a random 24-word
 * wallet (256 bits of {@code SecureRandom} entropy) generated on first start, never derived from
 * anything published; its key hash is a {@code DppPassport} parameter.
 *
 * <p><b>Lifecycle.</b>
 * <ul>
 *   <li>Storage: {@code manufacturer.mnemonic} and {@code auditor.mnemonic} in the demo data
 *       directory, written atomically (a temporary file, then a rename) with owner-only
 *       permissions, next to the deployment state {@code dpp-deployment.properties}, which records
 *       both key hashes and, once deployed, the passport policy id.</li>
 *   <li>Restart: both keys are loaded and checked against the deployment state.</li>
 *   <li>Reset: only by removing the data directory ({@code ./demo.sh dpp --clean-cache}), which
 *       removes the keys and the deployment state together.</li>
 *   <li>Fail closed: if the deployment state exists and a key is missing, unreadable or does not
 *       match the recorded key hash, loading throws. A key is never silently replaced.</li>
 * </ul>
 */
public final class RoleKeys {

    public static final String STATE_FILE = "dpp-deployment.properties";
    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");
    private static final SecureRandom RANDOM = new SecureRandom();

    public enum Role {
        MANUFACTURER("manufacturer"), AUDITOR("auditor");

        private final String name;

        Role(String name) { this.name = name; }

        public String fileName() { return name + ".mnemonic"; }

        String stateKey() { return name + "Pkh"; }
    }

    private final Path dir;
    private final Account manufacturer;
    private final Account auditor;

    private RoleKeys(Path dir, Account manufacturer, Account auditor) {
        this.dir = dir;
        this.manufacturer = manufacturer;
        this.auditor = auditor;
    }

    /**
     * Loads both keys, or generates them on a fresh data directory (no deployment state). Throws
     * {@link IllegalStateException} if deployment state exists and either key is missing,
     * unreadable or mismatched.
     */
    public static RoleKeys loadOrCreate(Path dataDir, Network network) {
        try {
            Files.createDirectories(dataDir);
            Path state = dataDir.resolve(STATE_FILE);
            if (Files.exists(state)) {
                Properties props = readState(state);
                Account m = loadMatching(dataDir, Role.MANUFACTURER, props, network);
                Account a = loadMatching(dataDir, Role.AUDITOR, props, network);
                return new RoleKeys(dataDir, m, a);
            }
            // A fresh data directory: nothing is deployed under any key yet.
            Account m = loadOrGenerate(dataDir, Role.MANUFACTURER, network);
            Account a = loadOrGenerate(dataDir, Role.AUDITOR, network);
            if (Arrays.equals(pkh(m), pkh(a))) throw new IllegalStateException("manufacturer and auditor keys coincide");
            Properties props = new Properties();
            props.setProperty(Role.MANUFACTURER.stateKey(), HexUtil.encodeHexString(pkh(m)));
            props.setProperty(Role.AUDITOR.stateKey(), HexUtil.encodeHexString(pkh(a)));
            writeState(state, props);
            return new RoleKeys(dataDir, m, a);
        } catch (IOException e) {
            throw new IllegalStateException("cannot read or write the DPP keys in " + dataDir + ": " + e.getMessage(), e);
        }
    }

    public Account manufacturer() { return manufacturer; }

    public Account auditor() { return auditor; }

    public static byte[] pkh(Account account) {
        return account.hdKeyPair().getPublicKey().getKeyHash();
    }

    /**
     * Records the deployed passport policy on first deployment, and on every later start checks
     * that the policy is unchanged (a regenerated circuit key or other parameters would otherwise
     * silently start a second deployment beside the passports already minted).
     */
    public void bindPolicy(String policyId) {
        try {
            Path state = dir.resolve(STATE_FILE);
            Properties props = readState(state);
            String recorded = props.getProperty("policyId");
            if (recorded == null) {
                props.setProperty("policyId", policyId);
                writeState(state, props);
            } else if (!recorded.equals(policyId)) {
                throw new IllegalStateException("the passport policy changed from " + recorded + " to " + policyId
                        + " (were the circuit keys regenerated?). Reset the demo with --clean-cache.");
            }
        } catch (IOException e) {
            throw new IllegalStateException("cannot update " + STATE_FILE + ": " + e.getMessage(), e);
        }
    }

    // ------------------------------------------------------------------ files

    private static Account loadMatching(Path dir, Role role, Properties state, Network network) throws IOException {
        Path file = dir.resolve(role.fileName());
        if (!Files.isRegularFile(file)) {
            throw new IllegalStateException("deployment state exists but the " + role.name + " key " + file
                    + " is missing; refusing to create a new key. Reset the demo with --clean-cache.");
        }
        Account account;
        try {
            account = parse(Files.readString(file, StandardCharsets.UTF_8), network);
        } catch (RuntimeException e) {
            throw new IllegalStateException("the " + role.name + " key " + file + " is unreadable: " + e.getMessage(), e);
        }
        String expected = state.getProperty(role.stateKey());
        if (expected == null || !expected.equalsIgnoreCase(HexUtil.encodeHexString(pkh(account)))) {
            throw new IllegalStateException("the " + role.name + " key " + file
                    + " does not match the deployed key hash " + expected);
        }
        return account;
    }

    private static Account loadOrGenerate(Path dir, Role role, Network network) throws IOException {
        Path file = dir.resolve(role.fileName());
        if (Files.exists(file)) {
            try {
                return parse(Files.readString(file, StandardCharsets.UTF_8), network);
            } catch (RuntimeException e) {
                throw new IllegalStateException("the " + role.name + " key " + file + " is unreadable: " + e.getMessage(), e);
            }
        }
        byte[] entropy = new byte[32];
        RANDOM.nextBytes(entropy);
        String mnemonic;
        try {
            mnemonic = String.join(" ", MnemonicCode.INSTANCE.toMnemonic(entropy));
        } catch (Exception e) {
            throw new IllegalStateException("mnemonic generation failed", e);
        } finally {
            Arrays.fill(entropy, (byte) 0);
        }
        writeAtomically(file, mnemonic + "\n");
        return parse(mnemonic, network);
    }

    private static Account parse(String text, Network network) {
        String mnemonic = text.trim();
        if (mnemonic.split("\\s+").length != 24) throw new IllegalArgumentException("expected a 24-word mnemonic");
        return Account.createFromMnemonic(network, mnemonic);
    }

    private static Properties readState(Path state) throws IOException {
        Properties props = new Properties();
        try (Reader r = new StringReader(Files.readString(state, StandardCharsets.UTF_8))) {
            props.load(r);
        }
        return props;
    }

    private static void writeState(Path state, Properties props) throws IOException {
        StringWriter w = new StringWriter();
        props.store(w, "DPP deployment state (ADR-0009 D11): reset only together with the keys");
        writeAtomically(state, w.toString());
    }

    /** Writes {@code content} to a temporary owner-only file beside {@code target}, syncs it, renames it, and syncs the directory. */
    static void writeAtomically(Path target, String content) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
        Path tmp = posix
                ? Files.createTempFile(dir, "." + target.getFileName(), ".tmp", PosixFilePermissions.asFileAttribute(OWNER_ONLY))
                : Files.createTempFile(dir, "." + target.getFileName(), ".tmp");
        try {
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ch.write(StandardCharsets.UTF_8.encode(content));
                ch.force(true);
            }
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            if (posix) Files.setPosixFilePermissions(target, OWNER_ONLY);
            // Make the rename itself durable.
            try (FileChannel d = FileChannel.open(dir, StandardOpenOption.READ)) {
                d.force(true);
            } catch (IOException e) {
                if (posix) throw e;   // directories cannot be opened on some non-POSIX file systems
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
