package com.bloxbean.cardano.zeroj.usecases.nft.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.cip.cip30.CIP30DataSigner;
import com.bloxbean.cardano.client.cip.cip30.DataSignError;
import com.bloxbean.cardano.client.cip.cip30.DataSignature;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.address.Address;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Properties;
import java.util.Set;

/**
 * The NFT holder custody wallet (ADR-0009 D11). It holds the demo NFTs and signs their CIP-8
 * snapshot registrations (D2), so its key must not be derivable from published data.
 *
 * <p>Key lifecycle:
 * <ul>
 *   <li><b>Storage.</b> A random 24-word mnemonic (CCL {@code Account}, whose entropy comes from
 *       {@code SecureRandom}), written atomically (temp file and rename, owner-only permissions) to
 *       {@value #KEY_FILE} in the demo data directory, next to the deployment state
 *       {@value #STATE_FILE} that records the wallet's address.</li>
 *   <li><b>Restart.</b> Both files are loaded and must agree.</li>
 *   <li><b>Reset.</b> {@code ./demo.sh nft --clean-cache} removes the data volume, so the key and
 *       the deployment state go together.</li>
 *   <li><b>Fail closed.</b> If the deployment state exists but the key is missing, unreadable, or
 *       does not match the recorded address, startup stops. A key is generated only when neither
 *       file exists.</li>
 * </ul>
 *
 * <p>The list operator (fees, collateral, the list's root and inserts) stays on the DevKit
 * mnemonic in {@code application.yml}: a deliberately public devnet role.
 */
@Service
public class CustodyWallet {

    private static final Logger log = LoggerFactory.getLogger(CustodyWallet.class);

    static final String KEY_FILE = "nft-custody-wallet.key";
    static final String STATE_FILE = "nft-ownership-deployment.properties";
    private static final String ADDRESS = "custodyAddress";

    private final Account account;

    public CustodyWallet(@Value("${demo.data-dir:./data}") String dataDir) {
        this(Path.of(dataDir), Networks.testnet());
    }

    CustodyWallet(Path dataDir, Network network) {
        this.account = loadOrCreate(dataDir, network);
        log.info("NFT custody wallet: {}", account.baseAddress());
    }

    /** The custody wallet's base address, which holds the demo NFTs. */
    public String address() {
        return account.baseAddress();
    }

    /** The custody wallet's payment key hash (28 bytes). */
    public byte[] paymentKeyHash() {
        return new Address(account.baseAddress()).getPaymentCredentialHash().orElseThrow();
    }

    /**
     * Signs a registration of {@code leaf} for {@code token} in event {@code contextId}, as a CIP-8
     * {@code COSE_Sign1} over {@link NftScheme#registrationPayload} with the wallet's address in
     * the protected header (CIP-30 {@code signData}).
     */
    public DataSignature signRegistration(BigInteger contextId, BigInteger token, BigInteger leaf) {
        try {
            return CIP30DataSigner.INSTANCE.signData(new Address(account.baseAddress()).getBytes(),
                    NftScheme.registrationPayload(contextId, token, leaf), account);
        } catch (DataSignError e) {
            throw new IllegalStateException("custody wallet could not sign the registration", e);
        }
    }

    /**
     * Loads the custody key from {@code dataDir}, or creates it when neither the key nor the
     * deployment state exists. Fails closed otherwise.
     */
    static Account loadOrCreate(Path dataDir, Network network) {
        Path keyFile = dataDir.resolve(KEY_FILE);
        Path stateFile = dataDir.resolve(STATE_FILE);
        boolean hasKey = Files.exists(keyFile);
        boolean hasState = Files.exists(stateFile);
        try {
            if (!hasKey) {
                if (hasState) {
                    throw new IllegalStateException("NFT deployment state " + stateFile + " exists but the custody key "
                            + keyFile + " is missing; refusing to create a new key. Restore the key, or reset the demo"
                            + " with ./demo.sh nft --clean-cache (or delete " + dataDir + ").");
                }
                Files.createDirectories(dataDir);
                Account fresh = new Account(network);
                writeAtomically(keyFile, fresh.mnemonic().getBytes(StandardCharsets.UTF_8));
                writeState(stateFile, fresh.baseAddress());
                log.info("Created a random NFT custody key in {}", keyFile);
                return fresh;
            }

            Account loaded;
            try {
                String mnemonic = Files.readString(keyFile, StandardCharsets.UTF_8).trim();
                loaded = new Account(network, mnemonic);
                loaded.baseAddress();
            } catch (IOException | RuntimeException e) {
                throw new IllegalStateException("NFT custody key " + keyFile + " is unreadable or corrupt; refusing"
                        + " to replace it. Restore it, or reset with ./demo.sh nft --clean-cache.", e);
            }
            if (hasState) {
                String recorded = readState(stateFile);
                if (!loaded.baseAddress().equals(recorded)) {
                    throw new IllegalStateException("NFT custody key " + keyFile + " does not match the deployed"
                            + " custody address " + recorded + "; refusing to start.");
                }
            } else {
                writeState(stateFile, loaded.baseAddress());
            }
            return loaded;
        } catch (IOException e) {
            throw new IllegalStateException("cannot store the NFT custody key in " + dataDir, e);
        }
    }

    private static String readState(Path stateFile) throws IOException {
        Properties p = new Properties();
        try (InputStream in = Files.newInputStream(stateFile)) {
            p.load(in);
        }
        String address = p.getProperty(ADDRESS);
        if (address == null || address.isBlank()) {
            throw new IllegalStateException("NFT deployment state " + stateFile + " has no " + ADDRESS);
        }
        return address;
    }

    private static void writeState(Path stateFile, String address) throws IOException {
        Properties p = new Properties();
        p.setProperty(ADDRESS, address);
        var bytes = new ByteArrayOutputStream();
        try (OutputStream out = bytes) {
            p.store(out, "nft-ownership deployment state (ADR-0009 D11); reset together with " + KEY_FILE);
        }
        writeAtomically(stateFile, bytes.toByteArray());
    }

    /**
     * Writes {@code content} to a temp file (owner-only where POSIX), syncs it, renames it into
     * place atomically, and syncs the directory.
     */
    static void writeAtomically(Path target, byte[] content) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        boolean posix = dir.getFileSystem().supportedFileAttributeViews().contains("posix");
        Path tmp;
        if (posix) {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(ownerOnly);
            tmp = Files.createTempFile(dir, target.getFileName().toString(), ".tmp", attr);
        } else {
            tmp = Files.createTempFile(dir, target.getFileName().toString(), ".tmp");
        }
        try {
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(content);
                while (buffer.hasRemaining()) {
                    ch.write(buffer);
                }
                ch.force(true);
            }
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
            if (posix) {
                // Make the rename itself durable.
                try (FileChannel dirChannel = FileChannel.open(dir, StandardOpenOption.READ)) {
                    dirChannel.force(true);
                }
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
