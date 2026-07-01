package com.bloxbean.cardano.zeroj.usecases.plonk.reserves.service;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProvingKeyBLS381;

import java.math.BigInteger;

final class PlonkJson {
    private PlonkJson() {
    }

    static String proofJson(PlonKProofBLS381 proof) {
        return "{"
                + "\"A\":" + g1(proof.commitA()) + ","
                + "\"B\":" + g1(proof.commitB()) + ","
                + "\"C\":" + g1(proof.commitC()) + ","
                + "\"Z\":" + g1(proof.commitZ()) + ","
                + "\"T1\":" + g1(proof.commitT1()) + ","
                + "\"T2\":" + g1(proof.commitT2()) + ","
                + "\"T3\":" + g1(proof.commitT3()) + ","
                + "\"eval_a\":\"" + proof.evalA() + "\","
                + "\"eval_b\":\"" + proof.evalB() + "\","
                + "\"eval_c\":\"" + proof.evalC() + "\","
                + "\"eval_s1\":\"" + proof.evalS1() + "\","
                + "\"eval_s2\":\"" + proof.evalS2() + "\","
                + "\"eval_zw\":\"" + proof.evalZw() + "\","
                + "\"Wxi\":" + g1(proof.commitWxi()) + ","
                + "\"Wxiw\":" + g1(proof.commitWxiw()) + ","
                + "\"protocol\":\"plonk\","
                + "\"curve\":\"bls12381\""
                + "}";
    }

    static String vkJson(PlonKProvingKeyBLS381 pk) {
        return "{"
                + "\"protocol\":\"plonk\","
                + "\"curve\":\"bls12381\","
                + "\"nPublic\":" + pk.nPublic() + ","
                + "\"power\":" + Integer.numberOfTrailingZeros(pk.domainSize()) + ","
                + "\"k1\":\"" + pk.k1() + "\","
                + "\"k2\":\"" + pk.k2() + "\","
                + "\"Qm\":" + g1(pk.qmCommit()) + ","
                + "\"Ql\":" + g1(pk.qlCommit()) + ","
                + "\"Qr\":" + g1(pk.qrCommit()) + ","
                + "\"Qo\":" + g1(pk.qoCommit()) + ","
                + "\"Qc\":" + g1(pk.qcCommit()) + ","
                + "\"S1\":" + g1(pk.s1Commit()) + ","
                + "\"S2\":" + g1(pk.s2Commit()) + ","
                + "\"S3\":" + g1(pk.s3Commit()) + ","
                + "\"X_2\":" + g2(pk.x2()) + ","
                + "\"w\":\"" + pk.omega().toBigInteger() + "\""
                + "}";
    }

    static String publicJson(BigInteger[] publicInputs) {
        var json = new StringBuilder("[");
        for (int i = 0; i < publicInputs.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(publicInputs[i]).append('"');
        }
        return json.append(']').toString();
    }

    private static String g1(JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) {
            return "[\"0\",\"1\",\"0\"]";
        }
        return "[\"" + p.xBigInt() + "\",\"" + p.yBigInt() + "\",\"1\"]";
    }

    private static String g2(JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) {
            return "[[\"0\",\"0\"],[\"1\",\"0\"],[\"0\",\"0\"]]";
        }
        return "[[\"" + p.x().reBigInt() + "\",\"" + p.x().imBigInt() + "\"],"
                + "[\"" + p.y().reBigInt() + "\",\"" + p.y().imBigInt() + "\"],"
                + "[\"1\",\"0\"]]";
    }
}
