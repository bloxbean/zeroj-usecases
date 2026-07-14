package com.bloxbean.cardano.zeroj.usecases.recovery.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkCip1852;

/**
 * Off-chain ownership proof (annotation DSL): proves the claimant's wallet <b>root key</b> derives,
 * via the CIP-1852 path {@code m/1852'/1815'/account'/role/index}, to the public address payment key
 * hash — i.e. they know the seed (which an attacker holding only a leaf address key does not) — and
 * <b>binds the payout to a chosen recipient</b>.
 *
 * <p><b>v4 — packed public inputs.</b> Each 28-byte hash is packed into a single BLS12-381 scalar
 * (big-endian, {@code Σ bᵢ·256^(27-i)}; 224 bits fit in the ~253-bit field), so the circuit has just
 * <b>2 public inputs</b> — {@code pkh} then {@code recipient} — instead of v3's 56 byte-per-input
 * elements. On-chain verification is O(#public inputs), so this drops the claim tx from ~13.4×10⁹ to
 * ~2.8×10⁹ CPU steps, back under the ~10×10⁹ per-tx limit (v3 byte-per-input did not fit mainnet).
 * The validator re-derives the same two scalars from the datum's {@code pkh} and the redeemer's
 * {@code recipient} bytes via {@code byteStringToInteger} (same big-endian order).</p>
 *
 * <ul>
 *   <li><b>{@code recipient} — the second public input</b> (packed 28-byte payment key hash of the
 *       payout address). The proof attests "the owner of {@code pkh} authorises a payout to
 *       {@code recipient}", so a copied proof cannot be redirected (that would change the public
 *       input and invalidate the proof; an attacker cannot re-prove without the seed). It is a
 *       <em>bound tag</em>, not derived from the seed; the on-chain validator enforces the actual
 *       payout goes to {@code recipient} for the datum's amount (see
 *       {@code docs/verification-and-validator-flow.md}). The recipient bytes are a secret witness
 *       here purely so the public scalar is constrained to their big-endian packing.</li>
 *   <li><b>{@code account} is a secret witness</b> (4 LE bytes; hardened in-circuit), joining
 *       {@code role}/{@code index}. The proof covers <em>any</em>
 *       {@code m/1852'/1815'/account'/role/index} address; the public {@code pkh} pins the exact one.
 *       The full path stays private.</li>
 * </ul>
 *
 * <p>Concise thanks to {@link ZkCip1852}; the underlying circuit is ~19M constraints. Provable
 * end-to-end in ~1 min per proof on a 16 GB machine (ADR-0033/0034/0035) and verified on-chain by
 * the account-ownership validator.</p>
 */
@ZKCircuit(name = "account-ownership-proof", version = 4)
public class OwnershipProof {

    @Prove
    void prove(ZkContext zk,
               @Secret @FixedSize(32) ZkBytes rootKL,
               @Secret @FixedSize(32) ZkBytes rootKR,
               @Secret @FixedSize(32) ZkBytes rootChainCode,
               @Secret @FixedSize(4) ZkBytes account,
               @Secret @FixedSize(4) ZkBytes role,
               @Secret @FixedSize(4) ZkBytes index,
               @Secret @FixedSize(28) ZkBytes recipientBytes,
               @Public ZkField pkh,
               @Public ZkField recipient) {
        // Derive the address pkh from the (secret) root key + full CIP-1852 path, pack it to one
        // scalar, and pin it to the public `pkh`.
        ZkBytes derived = ZkCip1852.paymentKeyHash(zk, rootKL, rootKR, rootChainCode, account, role, index);
        pack(zk, derived).assertEqual(pkh);
        // `recipient` is a bound public input: the proof commits to the packing of the payout bytes,
        // so a mempool replayer cannot redirect the funds. Not part of the derivation.
        pack(zk, recipientBytes).assertEqual(recipient);
    }

    /**
     * Big-endian byte packing: {@code b0·256^(n-1) + … + b_{n-1}} as one field element (Horner). Must
     * match the validator's {@code byteStringToInteger(bigEndian=true, …)} and the prover's
     * {@code new BigInteger(1, bytes)}. A 28-byte hash is 224 bits, well inside the scalar field.
     */
    private static ZkField pack(ZkContext zk, ZkBytes bytes) {
        ZkField acc = bytes.get(0).asField();
        for (int i = 1; i < bytes.size(); i++) {
            acc = acc.mul(zk.constant(256L)).add(bytes.get(i).asField());
        }
        return acc;
    }
}
