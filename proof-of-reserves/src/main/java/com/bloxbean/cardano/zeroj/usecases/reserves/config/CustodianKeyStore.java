package com.bloxbean.cardano.zeroj.usecases.reserves.config;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.crypto.bip39.MnemonicCode;
import com.bloxbean.cardano.client.crypto.bip39.MnemonicException;
import com.bloxbean.cardano.client.util.HexUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * The custodian's wallet key (ADR-0009 D11): random on first start, persisted owner-only and
 * atomically in the demo data directory, and never silently replaced.
 *
 * <ul>
 *   <li><b>First start</b> (no key, no deployment state): 32 bytes from {@link SecureRandom} become a
 *       24-word mnemonic, written to {@value #FILE}.</li>
 *   <li><b>Restart:</b> the key is loaded.</li>
 *   <li><b>Fail closed:</b> if deployment state exists but the key is missing, unreadable, corrupt,
 *       or its key hash differs from the deployed {@code custodianPkh}, startup stops with an
 *       error. A corrupt key file is refused even without deployment state.</li>
 *   <li><b>Reset:</b> {@code ./demo.sh proof-of-reserves --clean-cache} removes the data directory,
 *       so the key and the deployment state go together.</li>
 * </ul>
 */
public final class CustodianKeyStore {

    public static final String FILE = "custodian-wallet.key";
    static final String HEADER = "zeroj.reserves.custodian.v1";

    private CustodianKeyStore() {}

    public static Path path(Path dataDir) {
        return dataDir.resolve(FILE);
    }

    /** Loads the custodian key, or creates it on a fresh data directory. */
    public static Account loadOrCreate(Path dataDir, Network network, SecureRandom rng) {
        Path file = path(dataDir);
        boolean deployed = DeploymentState.exists(dataDir);
        Account account;
        if (Files.exists(file)) {
            account = read(file, network);
        } else if (deployed) {
            throw new IllegalStateException("Reserves deployment state exists in " + dataDir
                    + " but the custodian key " + file + " is missing. Refusing to create a new key for an"
                    + " existing deployment; reset with ./demo.sh proof-of-reserves --clean-cache.");
        } else {
            account = create(file, network, rng);
        }
        if (deployed) {
            DeploymentState state = DeploymentState.read(dataDir);
            String pkh = keyHash(account);
            if (!state.custodianPkh().equals(pkh)) {
                throw new IllegalStateException("The custodian key in " + file + " (key hash " + pkh
                        + ") does not match the deployed custodianPkh " + state.custodianPkh()
                        + ". Reset with ./demo.sh proof-of-reserves --clean-cache.");
            }
        }
        return account;
    }

    /** The payment key hash, hex: the validator's {@code custodianPkh} parameter. */
    public static String keyHash(Account account) {
        return HexUtil.encodeHexString(account.hdKeyPair().getPublicKey().getKeyHash());
    }

    private static Account create(Path file, Network network, SecureRandom rng) {
        byte[] entropy = new byte[32];
        rng.nextBytes(entropy);
        try {
            String mnemonic = String.join(" ", MnemonicCode.INSTANCE.toMnemonic(entropy));
            DemoFiles.writeAtomically(file, (HEADER + "\n" + mnemonic + "\n").getBytes(StandardCharsets.UTF_8));
            return Account.createFromMnemonic(network, mnemonic);
        } catch (Exception e) {
            throw new IllegalStateException("Could not create the custodian key " + file + ": " + e.getMessage(), e);
        } finally {
            Arrays.fill(entropy, (byte) 0);
        }
    }

    private static Account read(Path file, Network network) {
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            if (lines.size() != 2 || !HEADER.equals(lines.get(0))) {
                throw new IllegalArgumentException("unexpected format");
            }
            List<String> words = Arrays.asList(lines.get(1).trim().split(" "));
            if (words.size() != 24) throw new IllegalArgumentException("expected 24 words");
            MnemonicCode.INSTANCE.check(words); // word list and checksum
            return Account.createFromMnemonic(network, String.join(" ", words));
        } catch (IOException | RuntimeException | MnemonicException e) {
            throw new IllegalStateException("The custodian key " + file + " is unreadable or corrupt ("
                    + e.getMessage() + "). Refusing to replace it; reset with"
                    + " ./demo.sh proof-of-reserves --clean-cache.", e);
        }
    }
}
