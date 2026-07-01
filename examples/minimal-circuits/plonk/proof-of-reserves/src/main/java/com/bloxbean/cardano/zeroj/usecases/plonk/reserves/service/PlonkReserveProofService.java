package com.bloxbean.cardano.zeroj.usecases.plonk.reserves.service;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.api.VerificationResult;
import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.plonk.PlonKConstraintSystem;
import com.bloxbean.cardano.zeroj.codec.CanonicalHash;
import com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKSetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PlonkSetupCache;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.MultiInputProofCompressed;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.codec.PlonKProverToCardano.VkCompressed;
import com.bloxbean.cardano.zeroj.usecases.plonk.reserves.circuit.ReserveSolvencyProofCircuit;
import com.bloxbean.cardano.zeroj.verifier.plonk.PlonkBLS12381Verifier;

import java.math.BigInteger;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

public final class PlonkReserveProofService {
    private final int accounts;
    private final CircuitBuilder circuit;
    private final PlonKConstraintSystem plonk;
    private final PlonKProvingKeyBLS381 provingKey;
    private final CircuitId circuitId;

    public PlonkReserveProofService(int accounts, int potPower) {
        long startNanos = System.nanoTime();
        this.accounts = accounts;
        long buildStartNanos = System.nanoTime();
        this.circuit = ReserveSolvencyProofCircuit.build(accounts);
        this.plonk = circuit.compilePlonK(CurveId.BLS12_381);
        System.out.println("[plonk-reserves] circuitBuildAndCompile=" + elapsedMillis(buildStartNanos) + "ms");
        System.out.println("[plonk-reserves] accounts=" + accounts
                + ", gates=" + plonk.numGates()
                + ", publicInputs=" + plonk.numPublicInputs()
                + ", potPower=" + potPower);
        this.provingKey = setup(plonk, potPower);
        this.circuitId = new CircuitId(circuit.constraintGraph().name());
        System.out.println("[plonk-reserves] setupTotal=" + elapsedMillis(startNanos) + "ms");
    }

    public int accounts() {
        return accounts;
    }

    public PlonKProvingKeyBLS381 provingKey() {
        return provingKey;
    }

    public PlonKConstraintSystem constraintSystem() {
        return plonk;
    }

    public ProofBundle prove(ReserveSolvencyProofCircuit.Inputs inputs) {
        return prove(inputs, new SecureRandom());
    }

    public ProofBundle prove(ReserveSolvencyProofCircuit.Inputs inputs, SecureRandom rng) {
        long startNanos = System.nanoTime();
        BigInteger[] witness = inputs.calculateWitness(circuit, CurveId.BLS12_381);
        long witnessMillis = elapsedMillis(startNanos);
        long wiresStartNanos = System.nanoTime();
        BigInteger[] publicInputs = publicInputs(witness);
        var wires = wires(witness);
        long wiresMillis = elapsedMillis(wiresStartNanos);
        long proveStartNanos = System.nanoTime();
        PlonKProofBLS381 proof = PlonKProverBLS381.proveCardanoMpi(
                provingKey, wires.a(), wires.b(), wires.c(), publicInputs, rng);
        long proveMillis = elapsedMillis(proveStartNanos);
        long encodeStartNanos = System.nanoTime();
        VkCompressed vk = PlonKProverToCardano.compressVk(provingKey);
        MultiInputProofCompressed cardanoProof = PlonKProverToCardano.compressMpiProof(
                proof, provingKey, publicInputs);
        String proofJson = PlonkJson.proofJson(proof);
        String vkJson = PlonkJson.vkJson(provingKey);
        ZkProofEnvelope envelope = cardanoMpiEnvelope(proofJson, vkJson, publicInputs);
        VerificationMaterial material = VerificationMaterial.of(
                vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.PLONK,
                CurveId.BLS12_381,
                circuitId);
        long encodeMillis = elapsedMillis(encodeStartNanos);
        System.out.println("[plonk-reserves] proveTiming witness=" + witnessMillis
                + "ms, wires=" + wiresMillis
                + "ms, prove=" + proveMillis
                + "ms, encode=" + encodeMillis
                + "ms, total=" + elapsedMillis(startNanos) + "ms");
        return new ProofBundle(
                proof,
                vk,
                cardanoProof,
                publicInputs,
                proofJson,
                vkJson,
                envelope,
                material);
    }

    public VerificationResult verifyOffChain(ProofBundle bundle) {
        return new PlonkBLS12381Verifier().verify(bundle.envelope(), bundle.material());
    }

    private ZkProofEnvelope cardanoMpiEnvelope(String proofJson, String vkJson, BigInteger[] publicInputs) {
        var base = SnarkjsPlonkCodec.toEnvelopeFromJson(
                proofJson,
                vkJson,
                PlonkJson.publicJson(publicInputs),
                circuitId);
        return ZkProofEnvelope.builder()
                .proofSystem(base.proofSystem())
                .curve(base.curve())
                .circuitId(base.circuitId())
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .publicInputs(base.publicInputs())
                .vkRef(new VerificationKeyRef.ByHash(CanonicalHash.sha256(vkJson.getBytes(StandardCharsets.UTF_8))))
                .proofFormat(PlonkBLS12381Verifier.CARDANO_MPI_PROOF_FORMAT)
                .build();
    }

    private static PlonKProvingKeyBLS381 setup(PlonKConstraintSystem plonk, int potPower) {
        Path cachePath = setupCachePath(plonk, potPower, "proof-of-reserves");
        if (cachePath != null && Files.isRegularFile(cachePath)) {
            long loadStartNanos = System.nanoTime();
            try {
                PlonKProvingKeyBLS381 cached = PlonkSetupCache.loadBls12381ProvingKey(cachePath);
                validateCachedProvingKey(cached, plonk);
                System.out.println("[plonk-reserves] setupCache=hit path=" + cachePath
                        + ", load=" + elapsedMillis(loadStartNanos) + "ms");
                return cached;
            } catch (IOException | IllegalArgumentException e) {
                System.out.println("[plonk-reserves] setupCache=invalid path=" + cachePath
                        + ", reason=" + e.getMessage());
            }
        }
        long srsStartNanos = System.nanoTime();
        var srs = PowersOfTauBLS381.generate(potPower);
        long srsMillis = elapsedMillis(srsStartNanos);
        long setupStartNanos = System.nanoTime();
        int numGates = plonk.numGates();
        BigInteger[][] gates = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var row = plonk.gateRows().get(i);
            gates[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }
        var provingKey = PlonKSetupBLS381.setup(numGates, plonk.numPublicInputs(), gates,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);
        System.out.println("[plonk-reserves] setupTiming srs=" + srsMillis
                + "ms, provingKey=" + elapsedMillis(setupStartNanos) + "ms");
        if (cachePath != null) {
            long saveStartNanos = System.nanoTime();
            try {
                PlonkSetupCache.saveBls12381ProvingKey(provingKey, cachePath);
                System.out.println("[plonk-reserves] setupCache=saved path=" + cachePath
                        + ", save=" + elapsedMillis(saveStartNanos) + "ms");
            } catch (IOException e) {
                System.out.println("[plonk-reserves] setupCache=saveFailed path=" + cachePath
                        + ", reason=" + e.getMessage());
            }
        }
        return provingKey;
    }

    private static Path setupCachePath(PlonKConstraintSystem plonk, int potPower, String name) {
        String cacheDir = System.getProperty("zeroj.plonk.setup.cache.dir");
        if (cacheDir == null || cacheDir.isBlank()) {
            cacheDir = System.getenv("ZEROJ_PLONK_SETUP_CACHE_DIR");
        }
        if (cacheDir == null || cacheDir.isBlank()) {
            return null;
        }
        return Path.of(cacheDir).resolve(name + "-" + setupFingerprint(plonk, potPower) + ".pk.bin");
    }

    private static String setupFingerprint(PlonKConstraintSystem plonk, int potPower) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            updateInt(digest, potPower);
            updateInt(digest, plonk.numGates());
            updateInt(digest, plonk.numPublicInputs());
            updateInt(digest, plonk.numWires());
            for (var row : plonk.gateRows()) {
                updateScalar(digest, row.qL());
                updateScalar(digest, row.qR());
                updateScalar(digest, row.qO());
                updateScalar(digest, row.qM());
                updateScalar(digest, row.qC());
            }
            updateInts(digest, plonk.sigmaA());
            updateInts(digest, plonk.sigmaB());
            updateInts(digest, plonk.sigmaC());
            byte[] hash = digest.digest();
            return HexFormat.of().formatHex(hash, 0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static void validateCachedProvingKey(PlonKProvingKeyBLS381 cached, PlonKConstraintSystem plonk) {
        if (cached.nConstraints() != plonk.numGates()) {
            throw new IllegalArgumentException("cached proving key constraint count does not match circuit");
        }
        if (cached.nPublic() != plonk.numPublicInputs()) {
            throw new IllegalArgumentException("cached proving key public input count does not match circuit");
        }
        if (cached.domainSize() < plonk.numGates()) {
            throw new IllegalArgumentException("cached proving key domain is smaller than circuit");
        }
    }

    private static void updateInts(MessageDigest digest, int[] values) {
        updateInt(digest, values.length);
        for (int value : values) {
            updateInt(digest, value);
        }
    }

    private static void updateInt(MessageDigest digest, int value) {
        digest.update((byte) (value >>> 24));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 8));
        digest.update((byte) value);
    }

    private static void updateScalar(MessageDigest digest, BigInteger value) {
        byte[] bytes = value.toByteArray();
        updateInt(digest, bytes.length);
        digest.update(bytes);
    }

    private BigInteger[] publicInputs(BigInteger[] witness) {
        BigInteger[] publicInputs = new BigInteger[plonk.numPublicInputs()];
        for (int i = 0; i < publicInputs.length; i++) {
            publicInputs[i] = witness[i + 1];
        }
        return publicInputs;
    }

    private Wires wires(BigInteger[] witness) {
        var extWitness = plonk.extendWitness(witness);
        int n = provingKey.domainSize();
        MontFr381[] wireA = new MontFr381[n];
        MontFr381[] wireB = new MontFr381[n];
        MontFr381[] wireC = new MontFr381[n];
        int numGates = plonk.numGates();
        for (int i = 0; i < n; i++) {
            if (i < numGates) {
                var row = plonk.gateRows().get(i);
                wireA[i] = MontFr381.fromBigInteger(extWitness[row.wireA()]);
                wireB[i] = MontFr381.fromBigInteger(extWitness[row.wireB()]);
                wireC[i] = MontFr381.fromBigInteger(extWitness[row.wireC()]);
            } else {
                wireA[i] = MontFr381.ZERO;
                wireB[i] = MontFr381.ZERO;
                wireC[i] = MontFr381.ZERO;
            }
        }
        return new Wires(wireA, wireB, wireC);
    }

    private record Wires(MontFr381[] a, MontFr381[] b, MontFr381[] c) {
    }

    private static long elapsedMillis(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    public record ProofBundle(
            PlonKProofBLS381 proof,
            VkCompressed vk,
            MultiInputProofCompressed cardanoProof,
            BigInteger[] publicInputs,
            String proofJson,
            String vkJson,
            ZkProofEnvelope envelope,
            VerificationMaterial material) {
        public ProofBundle {
            publicInputs = publicInputs == null ? null : Arrays.copyOf(publicInputs, publicInputs.length);
        }

        @Override
        public BigInteger[] publicInputs() {
            return publicInputs == null ? null : Arrays.copyOf(publicInputs, publicInputs.length);
        }
    }
}
