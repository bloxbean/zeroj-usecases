package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;

/**
 * The airdrop's two private signing roles (ADR-0009 D11):
 * <ul>
 *   <li>the <b>issuer</b>'s EdDSA-Jubjub key, which signs personhood credentials; its public key
 *       is a {@code FaucetMintingPolicy} parameter;</li>
 *   <li>the <b>faucet admin</b> wallet, which holds the faucet's ADA, so its signature is what
 *       releases a payout.</li>
 * </ul>
 *
 * <p>Both are random on first start ({@link SecureRandom}) and persisted atomically, owner-only,
 * in the demo data directory next to the deployment state. A restart loads them. If any
 * deployment state exists but a key file is missing, unreadable or inconsistent, startup fails:
 * a key is never silently replaced. The only reset is removing the keys and the state together
 * ({@code ./demo.sh airdrop --clean-cache}).
 */
@Component
public class AirdropKeys {

    private static final Logger log = LoggerFactory.getLogger(AirdropKeys.class);

    private final EdDSAJubjub.Keypair issuer;
    private final Account admin;

    public AirdropKeys(AirdropDataDir data) {
        boolean state = data.hasState();
        this.issuer = loadOrCreateIssuer(data.issuerKey(), state, new SecureRandom());
        this.admin = loadOrCreateAdmin(data.adminKey(), state);
    }

    EdDSAJubjub.Keypair issuer() {
        return issuer;
    }

    public Account admin() {
        return admin;
    }

    /** The admin wallet's 28-byte payment key hash. */
    public byte[] adminKeyHash() {
        return admin.hdKeyPair().getPublicKey().getKeyHash();
    }

    private static EdDSAJubjub.Keypair loadOrCreateIssuer(Path file, boolean state, SecureRandom random) {
        JsonNode node = DemoFiles.read(file);
        if (node == null) {
            requireNoState(state, file);
            var keypair = EdDSAJubjub.generateKeypair(random);
            var out = DemoFiles.object();
            out.put("sk", keypair.sk().toString(16));
            out.put("pkU", keypair.pk().affineU().toString(16));
            out.put("pkV", keypair.pk().affineV().toString(16));
            DemoFiles.writeAtomic(file, out);
            log.info("Generated a new random issuer key → {}", file);
            return keypair;
        }
        try {
            var keypair = EdDSAJubjub.keypairFromSecret(new BigInteger(DemoFiles.text(node, "sk", file), 16));
            boolean matches = keypair.pk().affineU().equals(new BigInteger(DemoFiles.text(node, "pkU", file), 16))
                    && keypair.pk().affineV().equals(new BigInteger(DemoFiles.text(node, "pkV", file), 16));
            if (!matches) {
                throw new IllegalStateException(file + " is corrupt: its public key does not match its secret");
            }
            log.info("Loaded the issuer key from {}", file);
            return keypair;
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(file + " is corrupt", e);
        }
    }

    private static Account loadOrCreateAdmin(Path file, boolean state) {
        JsonNode node = DemoFiles.read(file);
        if (node == null) {
            requireNoState(state, file);
            // CCL generates the mnemonic's entropy with SecureRandom.
            var account = new Account(Networks.testnet());
            var out = DemoFiles.object();
            out.put("mnemonic", account.mnemonic());
            out.put("paymentKeyHash", HexUtil.encodeHexString(account.hdKeyPair().getPublicKey().getKeyHash()));
            DemoFiles.writeAtomic(file, out);
            log.info("Generated a new random faucet admin wallet {} → {}", account.baseAddress(), file);
            return account;
        }
        try {
            var account = new Account(Networks.testnet(), DemoFiles.text(node, "mnemonic", file));
            String pkh = HexUtil.encodeHexString(account.hdKeyPair().getPublicKey().getKeyHash());
            if (!pkh.equals(DemoFiles.text(node, "paymentKeyHash", file))) {
                throw new IllegalStateException(file + " is corrupt: its key hash does not match its mnemonic");
            }
            log.info("Loaded the faucet admin wallet {} from {}", account.baseAddress(), file);
            return account;
        } catch (RuntimeException e) {
            if (e instanceof IllegalStateException) throw e;
            throw new IllegalStateException(file + " is corrupt", e);
        }
    }

    private static void requireNoState(boolean state, Path file) {
        if (state) {
            throw new IllegalStateException("Airdrop deployment state exists but " + file
                    + " is missing. Refusing to create a new key (it would not match the deployed"
                    + " parameters). Restore the key, or reset keys and state together with"
                    + " ./demo.sh airdrop --clean-cache.");
        }
    }
}
