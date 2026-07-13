package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import org.junit.jupiter.api.Test;
import supranational.blst.P1_Affine;
import supranational.blst.P2_Affine;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * The pure-Java point compression (via {@code Bls12381Codecs}) must be <b>byte-for-byte identical</b>
 * to blst's {@code compress()} — the on-chain redeemer bytes must not change when we drop the native
 * dependency (which is what makes {@code setup}/{@code prove} work on Windows). blst is available on
 * this build platform, so this test pins the equivalence; the shipped code path never calls blst.
 */
class ProofCompressorTest {

    private static final int FP = 48;
    private static final long[] SCALARS = {1L, 2L, 3L, 7L, 42L, 12345L, 987654321L};

    @Test
    void g1Compress_matchesBlst() {
        for (long k : SCALARS) {
            var p = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(k)).toAffine();
            assertArrayEquals(blstG1(p), ProofCompressor.g1Compress(p), "G1 compress mismatch at k=" + k);
        }
        var inf = JacobianG1BLS381.AffineG1.INFINITY;
        assertArrayEquals(blstG1(inf), ProofCompressor.g1Compress(inf), "G1 infinity compress mismatch");
    }

    @Test
    void g2Compress_matchesBlst() {
        for (long k : SCALARS) {
            var p = JacobianG2BLS381.GENERATOR.scalarMul(BigInteger.valueOf(k)).toAffine();
            assertArrayEquals(blstG2(p), ProofCompressor.g2Compress(p), "G2 compress mismatch at k=" + k);
        }
        var inf = JacobianG2BLS381.AffineG2.INFINITY;
        assertArrayEquals(blstG2(inf), ProofCompressor.g2Compress(inf), "G2 infinity compress mismatch");
    }

    // --- reference: exactly what the previous blst-based ProofCompressor computed ---

    private static byte[] blstG1(JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) { byte[] r = new byte[FP]; r[0] = (byte) 0xC0; return r; }
        byte[] u = new byte[FP * 2];
        writeFp(u, 0, p.xBigInt()); writeFp(u, FP, p.yBigInt());
        return new P1_Affine(u).compress();
    }

    private static byte[] blstG2(JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) { byte[] r = new byte[FP * 2]; r[0] = (byte) 0xC0; return r; }
        byte[] u = new byte[FP * 4];
        writeFp(u, 0, p.x().imBigInt()); writeFp(u, FP, p.x().reBigInt());
        writeFp(u, FP * 2, p.y().imBigInt()); writeFp(u, FP * 3, p.y().reBigInt());
        return new P2_Affine(u).compress();
    }

    private static void writeFp(byte[] buf, int off, BigInteger val) {
        byte[] b = val.toByteArray();
        int s = Math.max(0, b.length - FP), c = Math.min(b.length, FP);
        System.arraycopy(b, s, buf, off + FP - c, c);
    }
}
