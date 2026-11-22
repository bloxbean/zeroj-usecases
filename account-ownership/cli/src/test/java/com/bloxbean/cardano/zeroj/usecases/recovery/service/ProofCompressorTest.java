package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The pure-Java point compression (via {@code Bls12381Codecs}) must be <b>byte-for-byte identical</b>
 * to the standard ZCash/IETF compressed serialization — the on-chain redeemer bytes must not change
 * now that the native dependency is gone.
 *
 * <p>The expected bytes are known answers for {@code [k]G}, computed independently with
 * <a href="https://github.com/ethereum/py_ecc">py_ecc</a> 8.0.0 ({@code G1_to_pubkey} and
 * {@code G2_to_signature} over {@code multiply(G, k)}). They replace the former comparison against
 * blst-java's {@code compress()}: ZeroJ no longer ships blst-java (ZeroJ ADR-0062 D3), and both
 * references produce the same serialization. {@code k = 1} is the published generator encoding.</p>
 */
class ProofCompressorTest {

    private static final Map<Long, String> G1_KAT = Map.of(
            1L, "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            2L, "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
            3L, "89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224",
            7L, "b928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7",
            42L, "8ce3b57b791798433fd323753489cac9bca43b98deaafaed91f4cb010730ae1e38b186ccd37a09b8aed62ce23b699c48",
            12345L, "8530c1bdc4cd6b1408be0933c4a41ac3513350eef36850b804708e1f338932ce01b655a163344a4500b281c8750c461f",
            987654321L, "8e561be3daa71004f1079f6e5de35a852cc5a167305fb1004a447642981306118df2244de29566320a8fb4b727021f89");

    private static final Map<Long, String> G2_KAT = Map.of(
            1L, "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
                    + "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            2L, "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c33577"
                    + "1638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053",
            3L, "89380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc"
                    + "122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae",
            7L, "8d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8"
                    + "049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c",
            42L, "ac7fa63dfc38bbf3712e27a180391bca4ccabf609c5967a0592eff420b6235f3f2b323051cb099acc3969aca310f7ff4"
                    + "191b2d6db43fafc2c9592f7e5f73981107975d3d92b843891e724dbc9f05b5eee5a3b2b1fc782ede8149f30830b84444",
            12345L, "849d5b3d40fe475b145eebf53d97981bde5a64dea2964807f82561e709e804fee3ecfb5356631b2dedbe82d3d1dad0bb"
                    + "037ece3ecc512226a1e56fbe0b33aab2080ab467d14aadeff5dcd8adc6613b926bc97601a4a1f1287793757b10d68a93",
            987654321L, "b29cbccb70f3799eeb03645ea19a393af6f8c79b6ce446302ff8e075570bb0e08d3d11a57a56829285abc1b9eb51ea43"
                    + "02c931fb630414ad1478e24421893a7bf7911091e0713f58f507b8277b22ed70f4b7b87b90b2ed2f676d22b46692aaf5");

    private static final String G1_INFINITY = "c0" + "00".repeat(47);
    private static final String G2_INFINITY = "c0" + "00".repeat(95);

    @Test
    void g1Compress_matchesIndependentVectors() {
        assertEquals(7, G1_KAT.size());
        G1_KAT.forEach((k, hex) -> {
            var p = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(k)).toAffine();
            assertArrayEquals(HexFormat.of().parseHex(hex), ProofCompressor.g1Compress(p), "G1 compress mismatch at k=" + k);
        });
        assertArrayEquals(HexFormat.of().parseHex(G1_INFINITY),
                ProofCompressor.g1Compress(JacobianG1BLS381.AffineG1.INFINITY), "G1 infinity compress mismatch");
    }

    @Test
    void g2Compress_matchesIndependentVectors() {
        assertEquals(7, G2_KAT.size());
        G2_KAT.forEach((k, hex) -> {
            var p = JacobianG2BLS381.GENERATOR.scalarMul(BigInteger.valueOf(k)).toAffine();
            assertArrayEquals(HexFormat.of().parseHex(hex), ProofCompressor.g2Compress(p), "G2 compress mismatch at k=" + k);
        });
        assertArrayEquals(HexFormat.of().parseHex(G2_INFINITY),
                ProofCompressor.g2Compress(JacobianG2BLS381.AffineG2.INFINITY), "G2 infinity compress mismatch");
    }
}
