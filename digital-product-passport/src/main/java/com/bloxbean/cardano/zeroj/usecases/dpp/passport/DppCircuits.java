package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.CarbonClaimProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.InspectionClaimProof;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.InspectionClaimProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.OriginClaimProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.RecycledClaimProofCircuit;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * The four claim circuits with their (development) Groth16 keys. Every statement is
 * {@code [σ, u, v, param]}: {@code param} is the threshold for carbon and recycled content, and
 * the approved-set root for origin and inspections.
 */
public final class DppCircuits {

    private final Map<Claim, KeyedCircuit> circuits;

    private DppCircuits(Map<Claim, KeyedCircuit> circuits) {
        this.circuits = circuits;
    }

    /** Compiles and keys the four circuits, in parallel, caching keys under {@code ./data}. */
    public static DppCircuits compile() {
        return compile(KeyedCircuit.DEFAULT_CACHE_DIR);
    }

    /** Compiles and keys the four circuits, in parallel, caching keys under {@code cacheDir}. */
    public static DppCircuits compile(Path cacheDir) {
        Map<String, Supplier<CircuitBuilder>> builders = new LinkedHashMap<>();
        builders.put("dpp-carbon-claim", CarbonClaimProofCircuit::build);
        builders.put("dpp-recycled-claim", RecycledClaimProofCircuit::build);
        builders.put("dpp-origin-claim", OriginClaimProofCircuit::build);
        builders.put("dpp-inspection-claim", InspectionClaimProofCircuit::build);
        List<KeyedCircuit> keyed = KeyedCircuit.compileAll(builders, cacheDir);
        Map<Claim, KeyedCircuit> map = new EnumMap<>(Claim.class);
        map.put(Claim.CARBON, keyed.get(0));
        map.put(Claim.RECYCLED, keyed.get(1));
        map.put(Claim.ORIGIN, keyed.get(2));
        map.put(Claim.INSPECTIONS, keyed.get(3));
        return new DppCircuits(map);
    }

    public KeyedCircuit circuit(Claim claim) {
        return circuits.get(claim);
    }

    // ------------------------------------------------------------------ witnesses

    public static CarbonClaimProofCircuit.Inputs carbonInputs(ClaimOpening o, long threshold) {
        require(o, Claim.CARBON);
        JubjubPoint c = o.point();
        return CarbonClaimProofCircuit.inputs()
                .schemaDigest(Claim.CARBON.schema().digest()).u(c.affineU()).v(c.affineV())
                .threshold(threshold).carbonKg(o.values().get(0)).blinding(o.blinding());
    }

    public static RecycledClaimProofCircuit.Inputs recycledInputs(ClaimOpening o, long threshold) {
        require(o, Claim.RECYCLED);
        JubjubPoint c = o.point();
        return RecycledClaimProofCircuit.inputs()
                .schemaDigest(Claim.RECYCLED.schema().digest()).u(c.affineU()).v(c.affineV())
                .threshold(threshold).recycledPct(o.values().get(0)).blinding(o.blinding());
    }

    /**
     * The origin witness. A country outside the set has no path; the path of the last leaf (a
     * padding leaf) is used instead, so the inputs are complete but fail the circuit (the honest
     * prover simply cannot prove).
     */
    public static OriginClaimProofCircuit.Inputs originInputs(ClaimOpening o, ApprovedSet countries) {
        require(o, Claim.ORIGIN);
        JubjubPoint c = o.point();
        ApprovedSet.Path path = pathOrPadding(countries, o.values().get(0));
        return OriginClaimProofCircuit.inputs()
                .schemaDigest(Claim.ORIGIN.schema().digest()).u(c.affineU()).v(c.affineV())
                .countryRoot(countries.root()).country(o.values().get(0)).blinding(o.blinding())
                .siblings(path.siblings()).pathBits(path.pathBits());
    }

    public static InspectionClaimProofCircuit.Inputs inspectionInputs(ClaimOpening o, ApprovedSet inspectors) {
        require(o, Claim.INSPECTIONS);
        JubjubPoint c = o.point();
        List<BigInteger> ids = new ArrayList<>();
        List<BigInteger> times = new ArrayList<>();
        List<List<BigInteger>> siblings = new ArrayList<>();
        List<List<BigInteger>> bits = new ArrayList<>();
        for (int i = 0; i < InspectionClaimProof.CHECKPOINTS; i++) {
            BigInteger id = o.values().get(2 * i);
            ids.add(id);
            times.add(o.values().get(2 * i + 1));
            ApprovedSet.Path path = pathOrPadding(inspectors, id);
            siblings.add(path.siblings());
            bits.add(path.pathBits());
        }
        return InspectionClaimProofCircuit.inputs()
                .schemaDigest(Claim.INSPECTIONS.schema().digest()).u(c.affineU()).v(c.affineV())
                .inspectorRoot(inspectors.root()).inspectors(ids).times(times).blinding(o.blinding())
                .siblings(siblings).pathBits(bits);
    }

    private static ApprovedSet.Path pathOrPadding(ApprovedSet set, BigInteger value) {
        ApprovedSet.Path path = set.path(value);
        return path != null ? path : set.pathAt((1 << set.depth()) - 1);
    }

    private static void require(ClaimOpening o, Claim claim) {
        if (o.claim() != claim) throw new IllegalArgumentException("expected a " + claim + " opening, got " + o.claim());
    }

    // ------------------------------------------------------------------ proving

    /** The witness map of {@code o}'s claim against {@code param}. */
    public static Map<String, List<BigInteger>> witness(ClaimOpening o, BigInteger param) {
        return switch (o.claim()) {
            case CARBON -> carbonInputs(o, param.longValueExact()).toWitnessMap();
            case RECYCLED -> recycledInputs(o, param.longValueExact()).toWitnessMap();
            case ORIGIN -> {
                requireRoot(param, ApprovedSets.EU_COUNTRIES);
                yield originInputs(o, ApprovedSets.EU_COUNTRIES).toWitnessMap();
            }
            case INSPECTIONS -> {
                requireRoot(param, ApprovedSets.INSPECTORS);
                yield inspectionInputs(o, ApprovedSets.INSPECTORS).toWitnessMap();
            }
        };
    }

    private static void requireRoot(BigInteger root, ApprovedSet set) {
        if (!set.root().equals(root)) throw new IllegalArgumentException("unknown approved-set root");
    }

    /**
     * Proves {@code o}'s claim against {@code param} (threshold or approved-set root); throws if
     * the committed values do not satisfy it.
     */
    public Groth16ProofBLS381 prove(ClaimOpening o, BigInteger param) {
        return circuit(o.claim()).prove(witness(o, param));
    }

    /** {@code [σ, u, v, param]}. */
    public static List<BigInteger> statement(BigInteger sigma, BigInteger u, BigInteger v, BigInteger param) {
        return List.of(sigma, u, v, param);
    }

    /** Verifies a claim proof against {@code [σ, u, v, param]} with ZeroJ's pure-Java verifier. */
    public boolean verify(Claim claim, Groth16ProofBLS381 proof, BigInteger sigma, BigInteger u, BigInteger v,
                          BigInteger param) {
        return circuit(claim).verify(proof, statement(sigma, u, v, param));
    }
}
