package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;

import java.math.BigInteger;

/**
 * Off-chain Groth16 verification: the standard pairing check
 * {@code e(A,B) · e(-alpha,beta) · e(-vk_x,gamma) · e(-C,delta) == 1}, where
 * {@code vk_x = IC[0] + Σ publicInput_i · IC[i+1]}. Pure Java, no network — the verification key is
 * read from the same key bundle used to prove. Mode-agnostic: a local or ceremony (snarkjs) key
 * verifies identically.
 */
public final class OffchainVerifier {

    private OffchainVerifier() {}

    /** Verify against a parsed {@code vk.json} (fast path — no proving-key store load). */
    public static boolean verify(VkIO.Vk vk, ProofIO.ProofPoints proof, BigInteger[] publicInputs) {
        if (vk.ic().length != publicInputs.length + 1)
            throw new IllegalStateException("VK IC has " + vk.ic().length + " points but there are "
                    + publicInputs.length + " public inputs (expected " + (publicInputs.length + 1) + ")");
        G1Point vkX = vk.ic()[0];
        for (int i = 0; i < publicInputs.length; i++)
            vkX = vkX.add(vk.ic()[i + 1].scalarMul(publicInputs[i]));
        return BLS12381Pairing.pairingCheck(
                new G1Point[]{proof.a(), vk.alpha().negate(), vkX.negate(), proof.c().negate()},
                new G2Point[]{proof.b(), vk.beta(), vk.gamma(), vk.delta()});
    }

    /** Verify against a loaded proving-key store (fallback when no {@code vk.json} is present). */
    public static boolean verify(Groth16PkStore.Loaded key, ProofIO.ProofPoints proof, BigInteger[] publicInputs) {
        var pk = key.pk();
        G1Point alpha = toG1(pk.alphaG1());
        G2Point beta = toG2(pk.betaG2());
        G2Point gamma = toG2(key.gammaG2());
        G2Point delta = toG2(pk.deltaG2());
        AffineG1[] ic = key.ic();
        if (ic.length != publicInputs.length + 1)
            throw new IllegalStateException("VK IC has " + ic.length + " points but there are "
                    + publicInputs.length + " public inputs (expected " + (publicInputs.length + 1) + ")");

        G1Point vkX = toG1(ic[0]);
        for (int i = 0; i < publicInputs.length; i++)
            vkX = vkX.add(toG1(ic[i + 1]).scalarMul(publicInputs[i]));

        return BLS12381Pairing.pairingCheck(
                new G1Point[]{proof.a(), alpha.negate(), vkX.negate(), proof.c().negate()},
                new G2Point[]{proof.b(), beta, gamma, delta});
    }

    static G1Point toG1(AffineG1 p) {
        return p.isInfinity() ? G1Point.INFINITY : new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    static G2Point toG2(AffineG2 p) {
        return p.isInfinity() ? G2Point.INFINITY
                : new G2Point(Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                              Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
