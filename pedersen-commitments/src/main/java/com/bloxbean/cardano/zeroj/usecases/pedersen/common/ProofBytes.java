package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import org.zeroj.bls12381.Bls12381Codecs;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.MontFp2_381;
import org.zeroj.bls12381.field.MontFp381;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.util.Arrays;

/**
 * A Groth16 proof as the 192 bytes {@code piA (48) ‖ piB (96) ‖ piC (48)}, the compressed form
 * the on-chain verifier takes, and back. Used to store proofs in datums (the registry's
 * possession proofs) and to verify them off-chain.
 */
public final class ProofBytes {

    public static final int LENGTH = 192;

    private ProofBytes() {}

    public static byte[] encode(Groth16ProofBLS381 proof) {
        var p = ProverToCardano.compressProof(proof);
        return Fields.concat(p.piA(), p.piB(), p.piC());
    }

    /**
     * Decodes and validates (on the curve, in the subgroup, not infinity) the three points.
     *
     * @throws IllegalArgumentException for any other length or an invalid point
     */
    public static Groth16ProofBLS381 decode(byte[] bytes) {
        if (bytes == null || bytes.length != LENGTH) {
            throw new IllegalArgumentException("a compressed Groth16 proof is " + LENGTH + " bytes");
        }
        G1Point a = Bls12381Codecs.g1FromCompressed(Arrays.copyOfRange(bytes, 0, 48));
        G2Point b = Bls12381Codecs.g2FromCompressed(Arrays.copyOfRange(bytes, 48, 144));
        G1Point c = Bls12381Codecs.g1FromCompressed(Arrays.copyOfRange(bytes, 144, 192));
        if (a.isInfinity() || b.isInfinity() || c.isInfinity()) {
            throw new IllegalArgumentException("a proof point is the point at infinity");
        }
        return new Groth16ProofBLS381(g1(a), g2(b), g1(c));
    }

    private static AffineG1 g1(G1Point p) {
        return new AffineG1(MontFp381.fromBigInteger(p.x().value()), MontFp381.fromBigInteger(p.y().value()));
    }

    private static AffineG2 g2(G2Point p) {
        return new AffineG2(
                MontFp2_381.of(p.x().c0().value(), p.x().c1().value()),
                MontFp2_381.of(p.y().c0().value(), p.y().c1().value()));
    }
}
