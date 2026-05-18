package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import supranational.blst.P1_Affine;
import supranational.blst.P2_Affine;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

final class ProofCompressor {

    private static final int FP_SIZE = 48;

    private ProofCompressor() {}

    static byte[] g1Compress(JacobianG1BLS381.AffineG1 point) {
        if (point.isInfinity()) {
            byte[] result = new byte[FP_SIZE];
            result[0] = (byte) 0xC0;
            return result;
        }
        byte[] uncompressed = new byte[FP_SIZE * 2];
        writeFp(uncompressed, 0, point.xBigInt());
        writeFp(uncompressed, FP_SIZE, point.yBigInt());
        return new P1_Affine(uncompressed).compress();
    }

    static byte[] g2Compress(JacobianG2BLS381.AffineG2 point) {
        if (point.isInfinity()) {
            byte[] result = new byte[FP_SIZE * 2];
            result[0] = (byte) 0xC0;
            return result;
        }
        byte[] uncompressed = new byte[FP_SIZE * 4];
        writeFp(uncompressed, 0, point.x().imBigInt());
        writeFp(uncompressed, FP_SIZE, point.x().reBigInt());
        writeFp(uncompressed, FP_SIZE * 2, point.y().imBigInt());
        writeFp(uncompressed, FP_SIZE * 3, point.y().reBigInt());
        return new P2_Affine(uncompressed).compress();
    }

    static SnarkjsToCardano.ProofCompressed compressProof(Groth16ProofBLS381 proof) {
        return new SnarkjsToCardano.ProofCompressed(
                g1Compress(proof.a()),
                g2Compress(proof.b()),
                g1Compress(proof.c()));
    }

    static SnarkjsToCardano.VkCompressed compressVk(Groth16SetupBLS381.SetupResult setup) {
        var pk = setup.provingKey();
        List<byte[]> ic = new ArrayList<>();
        for (var icPoint : setup.ic()) ic.add(g1Compress(icPoint));
        return new SnarkjsToCardano.VkCompressed(
                g1Compress(pk.alphaG1()), g2Compress(pk.betaG2()),
                g2Compress(setup.gammaG2()), g2Compress(pk.deltaG2()), ic);
    }

    private static void writeFp(byte[] buf, int offset, BigInteger value) {
        byte[] bytes = value.toByteArray();
        int srcStart = Math.max(0, bytes.length - FP_SIZE);
        int count = Math.min(bytes.length, FP_SIZE);
        int destStart = offset + FP_SIZE - count;
        System.arraycopy(bytes, srcStart, buf, destStart, count);
    }
}
