package com.bloxbean.cardano.zeroj.usecases.recovery.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkCip1852;

/**
 * Off-chain ownership proof (annotation DSL): proves the claimant's wallet <b>root key</b> derives,
 * via the CIP-1852 path {@code m/1852'/1815'/0'/role/index}, to the public address payment key
 * hash — i.e. they know the seed (which an attacker holding only a leaf address key does not).
 *
 * <p><b>Path parameters (v2):</b> {@code role} and {@code index} are <b>secret</b> witness inputs
 * (4 little-endian bytes each, gadget-constrained to soft indices {@code < 2^31}), so any address
 * of the account can be proven — external ({@code role=0}), change ({@code role=1}), any index.
 * They are secret rather than public because the public {@code pkh} alone binds the statement
 * ("this root derives to this credential"): a verifier gains nothing actionable from the path,
 * publishing it would leak wallet structure, and keeping the public input exactly {@code pkh}
 * (28 bytes) leaves the VK shape, proof envelope, and on-chain validator untouched. The hardened
 * {@code account} stays fixed at {@code 0'} until a use case needs it.</p>
 *
 * <p>Concise thanks to {@link ZkCip1852}; the underlying circuit is ~19M constraints with the
 * ADR-0028 optimizations (windowing + lazy reduction; ~90M naive). Provable end-to-end: ~6 min
 * one-time local setup and ~1 min per proof on a 16 GB machine (ADR-0033/0034/0035), and verified
 * on-chain by {@code OwnershipProofValidator} for ~0.95 ADA.</p>
 */
@ZKCircuit(name = "account-ownership-proof", version = 2)
public class OwnershipProof {

    @Prove
    void prove(ZkContext zk,
               @Secret @FixedSize(32) ZkBytes rootKL,
               @Secret @FixedSize(32) ZkBytes rootKR,
               @Secret @FixedSize(32) ZkBytes rootChainCode,
               @Secret @FixedSize(4) ZkBytes role,
               @Secret @FixedSize(4) ZkBytes index,
               @Public @FixedSize(28) ZkBytes pkh) {
        ZkCip1852.paymentKeyHash(zk, rootKL, rootKR, rootChainCode, 0, role, index).assertEqual(pkh);
    }
}
