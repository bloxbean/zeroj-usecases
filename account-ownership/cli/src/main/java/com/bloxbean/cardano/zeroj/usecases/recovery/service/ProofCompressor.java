package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.util.ArrayList;
import java.util.List;

/**
 * Compresses proof/VK points to the on-chain 48-byte (G1) / 96-byte (G2) form.
 *
 * <p>Uses ZeroJ's <b>pure-Java</b> {@link Bls12381Codecs} — no native library — so {@code setup}
 * and {@code prove} run on every platform, including Windows where blst isn't packaged. The output
 * is the standard IETF/zkcrypto compressed serialization; it is verified byte-for-byte against
 * blst's {@code compress()} in {@code ProofCompressorTest} so the on-chain redeemer bytes are
 * unchanged.</p>
 */
public final class ProofCompressor {

    private ProofCompressor() {}

    public static byte[] g1Compress(JacobianG1BLS381.AffineG1 point) {
        return Bls12381Codecs.g1ToCompressed(toG1(point));
    }

    public static byte[] g2Compress(JacobianG2BLS381.AffineG2 point) {
        return Bls12381Codecs.g2ToCompressed(toG2(point));
    }

    public static SnarkjsToCardano.ProofCompressed compressProof(Groth16ProofBLS381 proof) {
        return new SnarkjsToCardano.ProofCompressed(g1Compress(proof.a()), g2Compress(proof.b()), g1Compress(proof.c()));
    }

    public static SnarkjsToCardano.VkCompressed compressVk(Groth16SetupBLS381.SetupResult setup) {
        var pk = setup.provingKey();
        List<byte[]> ic = new ArrayList<>();
        for (var p : setup.ic()) ic.add(g1Compress(p));
        return new SnarkjsToCardano.VkCompressed(g1Compress(pk.alphaG1()), g2Compress(pk.betaG2()),
                g2Compress(setup.gammaG2()), g2Compress(pk.deltaG2()), ic);
    }

    private static G1Point toG1(JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        // Fp2.of(c0=real, c1=imaginary); the codec serializes c1 (imaginary) first, per IETF.
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
