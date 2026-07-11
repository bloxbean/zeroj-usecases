package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.ProofCompressor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;

/**
 * Reads/writes the CLI's proof artifacts.
 *
 * <ul>
 *   <li>{@code proof.json} — the Groth16 proof points (A in G1, B in G2, C in G1) as decimal
 *       coordinates, in the same affine form the on-chain validator and the off-chain pairing check
 *       consume.</li>
 *   <li>{@code public-inputs.json} — the statement the proof is about: the payment key hash, the
 *       address, the circuit fingerprint, and the 28 public-input scalars. The derivation path
 *       (account/role/index) is a <b>secret</b> witness since circuit v2 and is deliberately not
 *       recorded — this file travels with the proof to the verifier.</li>
 * </ul>
 */
public final class ProofIO {

    public static final String PROOF_FILE = "proof.json";
    public static final String PUBLIC_FILE = "public-inputs.json";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final JsonNodeFactory NF = JsonNodeFactory.instance;

    private ProofIO() {}

    /** The three proof points, ready for the off-chain pairing check. */
    public record ProofPoints(G1Point a, G2Point b, G1Point c) {}

    // ---- write ----

    public static void writeProof(Path dir, Groth16ProofBLS381 p) throws IOException {
        ObjectNode root = NF.objectNode();
        root.put("version", 1);
        root.put("scheme", "groth16");
        root.put("curve", "BLS12-381");
        root.set("a", g1(p.a().xBigInt(), p.a().yBigInt()));
        root.set("b", g2(p.b().x().reBigInt(), p.b().x().imBigInt(), p.b().y().reBigInt(), p.b().y().imBigInt()));
        root.set("c", g1(p.c().xBigInt(), p.c().yBigInt()));
        // blst-compressed points (G1 48B, G2 96B) for the on-chain redeemer — no reconstruction needed
        ObjectNode comp = NF.objectNode();
        comp.put("a", ProofIOHex.hex(ProofCompressor.g1Compress(p.a())));
        comp.put("b", ProofIOHex.hex(ProofCompressor.g2Compress(p.b())));
        comp.put("c", ProofIOHex.hex(ProofCompressor.g1Compress(p.c())));
        root.set("compressed", comp);
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(dir.resolve(PROOF_FILE).toFile(), root);
    }

    public static void writePublicInputs(Path dir, byte[] pkh, String address,
                                         String fingerprint) throws IOException {
        ObjectNode root = NF.objectNode();
        root.put("pkh", WalletDerivation.hex(pkh));
        root.put("address", address);
        root.put("fingerprint", fingerprint);
        ArrayNode pub = root.putArray("publicInputs");
        for (byte b : pkh) pub.add(Integer.toString(b & 0xff));
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(dir.resolve(PUBLIC_FILE).toFile(), root);
    }

    // ---- read ----

    public static ProofPoints readProof(Path file) throws IOException {
        var root = MAPPER.readTree(file.toFile());
        var a = root.get("a");
        var b = root.get("b");
        var c = root.get("c");
        G1Point pa = new G1Point(Fp.of(big(a, "x")), Fp.of(big(a, "y")));
        G1Point pc = new G1Point(Fp.of(big(c, "x")), Fp.of(big(c, "y")));
        var bx = (ArrayNode) b.get("x");
        var by = (ArrayNode) b.get("y");
        G2Point pb = new G2Point(
                Fp2.of(Fp.of(new BigInteger(bx.get(0).asText())), Fp.of(new BigInteger(bx.get(1).asText()))),
                Fp2.of(Fp.of(new BigInteger(by.get(0).asText())), Fp.of(new BigInteger(by.get(1).asText()))));
        return new ProofPoints(pa, pb, pc);
    }

    /** The 28 public-input scalars from {@code public-inputs.json}. */
    public static BigInteger[] readPublicInputs(Path file) throws IOException {
        var root = MAPPER.readTree(file.toFile());
        var arr = (ArrayNode) root.get("publicInputs");
        BigInteger[] out = new BigInteger[arr.size()];
        for (int i = 0; i < arr.size(); i++) out[i] = new BigInteger(arr.get(i).asText());
        return out;
    }

    /** The blst-compressed proof points for the on-chain redeemer. */
    public static SnarkjsToCardano.ProofCompressed readCompressedProof(Path file) throws IOException {
        var c = MAPPER.readTree(file.toFile()).get("compressed");
        if (c == null) throw new IOException("proof.json has no compressed points (re-run `prove`)");
        return new SnarkjsToCardano.ProofCompressed(
                ProofIOHex.unhex(c.get("a").asText()), ProofIOHex.unhex(c.get("b").asText()),
                ProofIOHex.unhex(c.get("c").asText()));
    }

    public static String readFingerprint(Path file) throws IOException {
        var f = MAPPER.readTree(file.toFile()).get("fingerprint");
        return f == null ? null : f.asText();
    }

    /** The payment key hash bytes from {@code public-inputs.json}. */
    public static byte[] readPkh(Path file) throws IOException {
        return ProofIOHex.unhex(MAPPER.readTree(file.toFile()).get("pkh").asText());
    }

    // ---- helpers ----

    private static ObjectNode g1(BigInteger x, BigInteger y) {
        ObjectNode n = NF.objectNode();
        n.put("x", x.toString());
        n.put("y", y.toString());
        return n;
    }

    private static ObjectNode g2(BigInteger xre, BigInteger xim, BigInteger yre, BigInteger yim) {
        ObjectNode n = NF.objectNode();
        ArrayNode x = n.putArray("x"); x.add(xre.toString()); x.add(xim.toString());
        ArrayNode y = n.putArray("y"); y.add(yre.toString()); y.add(yim.toString());
        return n;
    }

    private static BigInteger big(com.fasterxml.jackson.databind.JsonNode parent, String field) {
        return new BigInteger(parent.get(field).asText());
    }
}
