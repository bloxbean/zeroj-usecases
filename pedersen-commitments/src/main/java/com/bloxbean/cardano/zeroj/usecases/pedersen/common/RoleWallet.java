package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.bip39.MnemonicCode;
import com.bloxbean.cardano.client.crypto.bip39.MnemonicException;
import com.bloxbean.cardano.client.util.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * The wallet of a demo role whose signature makes a statement the role's own, such as the
 * solvency exchange's attestation: a random key, persisted in the demo data directory with the
 * ADR-0009 D11 lifecycle. Its payment key hash is the role's validator parameter.
 *
 * <p>Two files in the data directory, each written atomically (a temporary file in the same
 * directory, then a rename) and readable by its owner only:
 * <ul>
 *   <li>{@code <role>.wallet.key}: a BIP-39 mnemonic over 32 bytes of {@link SecureRandom}
 *       entropy (24 words, checksum verified on load);</li>
 *   <li>{@code <role>.deployment}: the deployment state, the payment key hash the role's scripts
 *       are parameterised with.</li>
 * </ul>
 *
 * <p>Lifecycle:
 * <ul>
 *   <li><b>First start</b> (neither file): a new key, then the deployment state.</li>
 *   <li><b>Restart</b>: the key is loaded, and its key hash must equal the deployed one. A key
 *       without deployment state (a first start stopped between the two writes) is loaded and
 *       the state written.</li>
 *   <li><b>Fail closed</b>: deployment state with a missing, unreadable or invalid key file, or a
 *       key whose hash differs from the deployed one, stops the demo. A new key is never created
 *       silently.</li>
 *   <li><b>Reset</b>: {@code ./demo.sh pedersen-commitments --clean-cache} removes the data
 *       directory, so the key and the deployment state go together.</li>
 * </ul>
 */
public final class RoleWallet {

    private static final Logger log = LoggerFactory.getLogger(RoleWallet.class);
    static final String KEY_HEADER = "zeroj.pedersen.role-wallet-key.v1";
    static final String DEPLOYMENT_HEADER = "zeroj.pedersen.role-deployment.v1";

    /** The role's wallet, and whether this start created it. */
    public record Loaded(Account account, boolean created) {
        public byte[] keyHash() {
            return RoleWallet.keyHash(account);
        }
    }

    private RoleWallet() {}

    public static Path keyFile(Path dataDir, String role) {
        return dataDir.resolve(checkedRole(role) + ".wallet.key");
    }

    public static Path deploymentFile(Path dataDir, String role) {
        return dataDir.resolve(checkedRole(role) + ".deployment");
    }

    /**
     * Loads the role's wallet from {@code dataDir}, or creates it on first start.
     *
     * @throws IllegalStateException if the key or the deployment state cannot be used (fail closed)
     */
    public static Loaded loadOrCreate(Path dataDir, String role, SecureRandom random) {
        Path keyFile = keyFile(dataDir, role);
        Path deploymentFile = deploymentFile(dataDir, role);
        boolean hasKey = Files.exists(keyFile);
        boolean hasDeployment = Files.exists(deploymentFile);

        if (!hasKey && hasDeployment) {
            throw failClosed(role, "its deployment state " + deploymentFile + " exists, but the key file "
                    + keyFile + " is missing");
        }
        if (!hasKey) {
            byte[] entropy = new byte[32];
            random.nextBytes(entropy);
            String mnemonic;
            try {
                mnemonic = String.join(" ", MnemonicCode.INSTANCE.toMnemonic(entropy));
            } catch (MnemonicException.MnemonicLengthException e) {
                throw new IllegalStateException(e);
            } finally {
                Arrays.fill(entropy, (byte) 0);
            }
            Account account = Account.createFromMnemonic(Networks.testnet(), mnemonic);
            writeAtomically(keyFile, KEY_HEADER + "\n" + mnemonic + "\n");
            writeDeployment(deploymentFile, role, account);
            log.info("Created a random wallet for {} ({}), key in {}", role, account.baseAddress(), keyFile);
            return new Loaded(account, true);
        }

        Account account = readKey(keyFile, role);
        if (!hasDeployment) {
            writeDeployment(deploymentFile, role, account);
        } else {
            byte[] deployed = readDeployment(deploymentFile, role);
            if (!Arrays.equals(deployed, keyHash(account))) {
                throw failClosed(role, "the key in " + keyFile + " has key hash " + HexUtil.encodeHexString(keyHash(account))
                        + ", but the deployment state names " + HexUtil.encodeHexString(deployed));
            }
        }
        log.info("Loaded the wallet for {} ({}) from {}", role, account.baseAddress(), keyFile);
        return new Loaded(account, false);
    }

    public static byte[] keyHash(Account account) {
        return account.hdKeyPair().getPublicKey().getKeyHash();
    }

    // ------------------------------------------------------------------

    private static Account readKey(Path keyFile, String role) {
        List<String> lines;
        try {
            lines = Files.readAllLines(keyFile, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            throw failClosed(role, "its key file " + keyFile + " cannot be read (" + e.getMessage() + ")");
        }
        if (lines.size() != 2 || !lines.getFirst().equals(KEY_HEADER)) {
            throw failClosed(role, "its key file " + keyFile + " is malformed");
        }
        List<String> words = List.of(lines.get(1).split(" ", -1));
        try {
            if (words.size() != 24) throw new MnemonicException.MnemonicLengthException("expected 24 words");
            MnemonicCode.INSTANCE.check(words);
        } catch (MnemonicException e) {
            throw failClosed(role, "its key file " + keyFile + " holds no valid key (" + e.getClass().getSimpleName() + ")");
        }
        return Account.createFromMnemonic(Networks.testnet(), lines.get(1));
    }

    private static byte[] readDeployment(Path file, String role) {
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            throw failClosed(role, "its deployment state " + file + " cannot be read (" + e.getMessage() + ")");
        }
        if (lines.size() != 3 || !lines.get(0).equals(DEPLOYMENT_HEADER) || !lines.get(1).equals("role=" + role)
                || !lines.get(2).matches("paymentKeyHash=[0-9a-f]{56}")) {
            throw failClosed(role, "its deployment state " + file + " is malformed");
        }
        return HexUtil.decodeHexString(lines.get(2).substring("paymentKeyHash=".length()));
    }

    private static void writeDeployment(Path file, String role, Account account) {
        writeAtomically(file, DEPLOYMENT_HEADER + "\nrole=" + role + "\npaymentKeyHash="
                + HexUtil.encodeHexString(keyHash(account)) + "\n");
    }

    /**
     * Makes the rename durable: on POSIX file systems the directory entry is flushed too. (Windows
     * cannot open a directory as a channel; there the rename's own durability applies.)
     */
    private static void syncDirectory(Path dir) throws IOException {
        if (!dir.getFileSystem().supportedFileAttributeViews().contains("posix")) return;
        try (FileChannel channel = FileChannel.open(dir, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private static void writeAtomically(Path file, String text) {
        try {
            Path dir = file.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            Path tmp;
            try {
                tmp = Files.createTempFile(dir, "." + file.getFileName(), ".tmp",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            } catch (UnsupportedOperationException e) {
                // Not a POSIX file system (Windows): the file inherits the directory's access control.
                log.warn("Cannot set owner-only permissions in {}; protect the directory yourself", dir);
                tmp = Files.createTempFile(dir, "." + file.getFileName(), ".tmp");
            }
            try {
                try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.WRITE,
                        StandardOpenOption.TRUNCATE_EXISTING)) {
                    channel.write(ByteBuffer.wrap(text.getBytes(StandardCharsets.UTF_8)));
                    channel.force(true);
                }
                try {
                    Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    throw new IOException("the file system cannot rename atomically", e);
                }
                syncDirectory(dir);
            } finally {
                Files.deleteIfExists(tmp);
            }
        } catch (IOException e) {
            throw new IllegalStateException("could not write " + file + ": " + e.getMessage(), e);
        }
    }

    private static String checkedRole(String role) {
        if (!role.matches("[a-z0-9-]+")) throw new IllegalArgumentException("role names are lower-case words and dashes");
        return role;
    }

    private static IllegalStateException failClosed(String role, String problem) {
        return new IllegalStateException("The " + role + " wallet cannot be loaded: " + problem + ". The demo"
                + " does not replace a deployed key silently: restore the files, or reset the key together with"
                + " the deployment state with ./demo.sh pedersen-commitments --clean-cache (or delete the data directory).");
    }
}
