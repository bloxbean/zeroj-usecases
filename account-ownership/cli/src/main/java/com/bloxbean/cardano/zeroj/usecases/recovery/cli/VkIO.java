package com.bloxbean.cardano.zeroj.usecases.recovery.cli;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.usecases.recovery.service.ProofCompressor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The <b>verification key</b> as a small standalone file ({@code vk.json}, a few KB) so verification
 * never has to mmap the ~23 GB proving-key store. Both forms are stored: decimal affine coordinates
 * (for the off-chain pairing check) and blst-compressed points (for the on-chain redeemer/validator).
 */
public final class VkIO {

    public static final String VK_FILE = "vk.json";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final JsonNodeFactory NF = JsonNodeFactory.instance;

    private VkIO() {}

    /** Parsed VK points for the off-chain pairing check. */
    public record Vk(int nPublic, G1Point alpha, G2Point beta, G2Point gamma, G2Point delta, G1Point[] ic) {}

    public static boolean exists(Path dir) { return Files.isRegularFile(dir.resolve(VK_FILE)); }

    // ---- write ----

    public static void write(Path dir, Groth16SetupBLS381.SetupResult setup) throws IOException {
        var pk = setup.provingKey();
        AffineG1 alpha = pk.alphaG1();
        AffineG2 beta = pk.betaG2(), gamma = setup.gammaG2(), delta = pk.deltaG2();
        AffineG1[] ic = setup.ic();

        ObjectNode root = NF.objectNode();
        root.put("nPublic", ic.length - 1);
        root.set("alpha", g1(alpha));
        root.set("beta", g2(beta));
        root.set("gamma", g2(gamma));
        root.set("delta", g2(delta));
        ArrayNode icArr = root.putArray("ic");
        for (AffineG1 p : ic) icArr.add(g1(p));

        var vkc = ProofCompressor.compressVk(setup);
        ObjectNode comp = NF.objectNode();
        comp.put("alpha", ProofIOHex.hex(vkc.alpha()));
        comp.put("beta", ProofIOHex.hex(vkc.beta()));
        comp.put("gamma", ProofIOHex.hex(vkc.gamma()));
        comp.put("delta", ProofIOHex.hex(vkc.delta()));
        ArrayNode cic = comp.putArray("ic");
        for (byte[] b : vkc.ic()) cic.add(ProofIOHex.hex(b));
        root.set("compressed", comp);

        MAPPER.writerWithDefaultPrettyPrinter().writeValue(dir.resolve(VK_FILE).toFile(), root);
    }

    /** Best-effort cache write (published bundles may be read-only) — never fails the caller. */
    public static void writeQuietly(Path dir, Groth16SetupBLS381.SetupResult setup) {
        try { write(dir, setup); } catch (Exception ignored) {}
    }

    // ---- read ----

    public static Vk readVk(Path dir) throws IOException {
        var root = MAPPER.readTree(dir.resolve(VK_FILE).toFile());
        var icNode = (ArrayNode) root.get("ic");
        G1Point[] ic = new G1Point[icNode.size()];
        for (int i = 0; i < ic.length; i++) ic[i] = g1p(icNode.get(i));
        return new Vk(root.get("nPublic").asInt(), g1p(root.get("alpha")),
                g2p(root.get("beta")), g2p(root.get("gamma")), g2p(root.get("delta")), ic);
    }

    public static SnarkjsToCardano.VkCompressed readVkCompressed(Path dir) throws IOException {
        var c = MAPPER.readTree(dir.resolve(VK_FILE).toFile()).get("compressed");
        List<byte[]> ic = new ArrayList<>();
        for (var n : (ArrayNode) c.get("ic")) ic.add(ProofIOHex.unhex(n.asText()));
        return new SnarkjsToCardano.VkCompressed(ProofIOHex.unhex(c.get("alpha").asText()),
                ProofIOHex.unhex(c.get("beta").asText()), ProofIOHex.unhex(c.get("gamma").asText()),
                ProofIOHex.unhex(c.get("delta").asText()), ic);
    }

    // ---- json <-> points ----

    private static ObjectNode g1(AffineG1 p) {
        ObjectNode n = NF.objectNode();
        n.put("x", p.xBigInt().toString());
        n.put("y", p.yBigInt().toString());
        return n;
    }

    private static ObjectNode g2(AffineG2 p) {
        ObjectNode n = NF.objectNode();
        ArrayNode x = n.putArray("x"); x.add(p.x().reBigInt().toString()); x.add(p.x().imBigInt().toString());
        ArrayNode y = n.putArray("y"); y.add(p.y().reBigInt().toString()); y.add(p.y().imBigInt().toString());
        return n;
    }

    private static G1Point g1p(com.fasterxml.jackson.databind.JsonNode n) {
        return new G1Point(Fp.of(new BigInteger(n.get("x").asText())), Fp.of(new BigInteger(n.get("y").asText())));
    }

    private static G2Point g2p(com.fasterxml.jackson.databind.JsonNode n) {
        var x = (ArrayNode) n.get("x");
        var y = (ArrayNode) n.get("y");
        return new G2Point(
                Fp2.of(Fp.of(new BigInteger(x.get(0).asText())), Fp.of(new BigInteger(x.get(1).asText()))),
                Fp2.of(Fp.of(new BigInteger(y.get(0).asText())), Fp.of(new BigInteger(y.get(1).asText()))));
    }
}
