package com.bloxbean.cardano.zeroj.usecases.recovery.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidon;

/**
 * On-chain recovery-gate circuit (annotation DSL): proves knowledge of the recovery secret behind
 * an address's registered commitment — {@code Poseidon(secret, addressKeyHash) == commitment}.
 * The provable, Groth16-BLS12381 statement the on-chain {@code RecoveryProofValidator} verifies.
 */
@ZKCircuit(name = "account-recovery-commitment", version = 1)
public class RecoveryCommitmentProof {

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    @Prove
    ZkBool prove(ZkContext zk,
                 @Public ZkField commitment,
                 @Public ZkField addr,
                 @Secret ZkField secret) {
        return ZkPoseidon.hash(zk, POSEIDON, secret, addr).isEqual(commitment);
    }
}
