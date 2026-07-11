package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.address.Credential;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyGenerator;
import com.bloxbean.cardano.client.crypto.bip32.HdKeyPair;

import java.util.Arrays;

/**
 * Turns a wallet mnemonic into exactly what the circuit consumes: the <b>secret</b> root extended
 * private key ({@code kL,kR,chainCode}) and the <b>public</b> payment key hash of a chosen address
 * on the CIP-1852 path {@code m/1852'/1815'/account'/role/index}.
 *
 * <p>This is the same derivation the circuit re-computes in zero knowledge — the CLI does it here
 * only to build the witness and to show the user which address the proof will be about. The seed and
 * the derived root key stay in memory for the life of the process and are never written or sent.</p>
 */
public final class WalletDerivation {

    private final HdKeyGenerator hd = new HdKeyGenerator();

    /** The secret root key and the public target address, everything {@code prove} needs. */
    public record Wallet(byte[] rootKL, byte[] rootKR, byte[] rootChainCode,
                         byte[] pkh, String address, int account, int role, int index) {}

    public Wallet derive(String mnemonic, int account, int role, int index, Network network) {
        HdKeyPair root = hd.getRootKeyPairFromMnemonic(mnemonic);
        byte[] priv = root.getPrivateKey().getKeyData();
        byte[] kL = Arrays.copyOfRange(priv, 0, 32);
        byte[] kR = Arrays.copyOfRange(priv, 32, 64);
        byte[] cc = root.getPrivateKey().getChainCode();

        // m/1852'/1815'/account'/role/index  (role 0 = external/payment, 1 = internal/change)
        HdKeyPair n1 = hd.getChildKeyPair(root, 1852L, true);
        HdKeyPair n2 = hd.getChildKeyPair(n1, 1815L, true);
        HdKeyPair n3 = hd.getChildKeyPair(n2, account, true);
        HdKeyPair n4 = hd.getChildKeyPair(n3, role, false);
        HdKeyPair leaf = hd.getChildKeyPair(n4, index, false);

        byte[] pkh = Blake2bUtil.blake2bHash224(leaf.getPublicKey().getKeyData());
        String address;
        try {
            address = AddressProvider.getEntAddress(Credential.fromKey(pkh), network).toBech32();
        } catch (Exception e) {
            address = "(enterprise address unavailable; pkh=" + hex(pkh) + ")";
        }
        return new Wallet(kL, kR, cc, pkh, address, account, role, index);
    }

    public Wallet derive(String mnemonic, int account, int index) {
        return derive(mnemonic, account, 0, index, Networks.testnet());
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
