package com.bloxbean.cardano.zeroj.usecases.dpp.circuit;

import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ApprovedSet;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ApprovedSets;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.Claim;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ClaimOpening;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.DppCircuits;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.junit.jupiter.api.function.Executable;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenVectorBases;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The four passport claim circuits (ADR-0009 D1, M6 circuit exit criteria). Every statement is
 * {@code [σ, u, v, param]}; the expected commitments and roots come from ZeroJ's host APIs
 * ({@code PedersenVectorCommitment}, {@code PoseidonHash} through {@link ApprovedSet}), not from
 * the circuits under test.
 */
class ClaimCircuitTest {

    static final long CARBON_THRESHOLD = 50;
    static final long RECYCLED_THRESHOLD = 30;
    private static final long DEU = 276;
    private static final long CHN = 156;
    private static DppCircuits circuits;

    @BeforeAll
    static void setup() {
        circuits = DppCircuits.compile();
    }

    // ------------------------------------------------------------------ honest proofs

    @Test
    @DisplayName("Each claim proves and verifies; the proof is bound to σ, u, v and the threshold or root")
    void honestClaimsProveAndBindTheirStatement() {
        var openings = List.of(
                ClaimOpening.fresh(Claim.CARBON, 7),
                ClaimOpening.fresh(Claim.RECYCLED, 45),
                ClaimOpening.fresh(Claim.ORIGIN, DEU),
                ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1_717_000_000L, 13, 1_717_086_400L, 11, 1_717_172_800L));
        for (ClaimOpening o : openings) {
            BigInteger param = param(o.claim());
            var proof = circuits.prove(o, param);
            JubjubPoint c = PedersenVectorCommitment.commit(o.claim().schema(), o.values(), o.blinding()).point().normalized();
            List<BigInteger> statement = List.of(o.claim().schema().digest(), c.affineU(), c.affineV(), param);
            assertTrue(circuits.circuit(o.claim()).verify(proof, statement), o.claim() + " verifies");
            for (int i = 0; i < statement.size(); i++) {
                List<BigInteger> changed = new ArrayList<>(statement);
                changed.set(i, changed.get(i).add(BigInteger.ONE));
                assertFalse(circuits.circuit(o.claim()).verify(proof, changed), o.claim() + ": public input " + i + " not bound");
            }
            System.out.println("[" + o.claim() + "] constraints: " + circuits.circuit(o.claim()).numConstraints());
        }
        // The generated public-input order is the ADR's: σ, u, v, param.
        var o = ClaimOpening.fresh(Claim.CARBON, 7);
        JubjubPoint c = o.point();
        assertEquals(List.of(Claim.CARBON.schema().digest(), c.affineU(), c.affineV(), BigInteger.valueOf(CARBON_THRESHOLD)),
                CarbonClaimProofCircuit.publicInputs(DppCircuits.carbonInputs(o, CARBON_THRESHOLD)));
    }

    // ------------------------------------------------------------------ thresholds

    @Test
    @DisplayName("Carbon: at the threshold proves, one over has no witness")
    void carbonThreshold() {
        CircuitBuilder circuit = circuits.circuit(Claim.CARBON).circuit();
        assertDoesNotThrow(() -> witness(circuit, DppCircuits.carbonInputs(ClaimOpening.fresh(Claim.CARBON, CARBON_THRESHOLD),
                CARBON_THRESHOLD).toWitnessMap()));
        assertViolation(() -> witness(circuit, DppCircuits.carbonInputs(
                ClaimOpening.fresh(Claim.CARBON, CARBON_THRESHOLD + 1), CARBON_THRESHOLD).toWitnessMap()));
        assertViolation(() -> witness(circuit, DppCircuits.carbonInputs(
                ClaimOpening.fresh(Claim.CARBON, 65), CARBON_THRESHOLD).toWitnessMap()));
    }

    @Test
    @DisplayName("Recycled content: at the threshold proves, one under has no witness")
    void recycledThreshold() {
        CircuitBuilder circuit = circuits.circuit(Claim.RECYCLED).circuit();
        assertDoesNotThrow(() -> witness(circuit, DppCircuits.recycledInputs(
                ClaimOpening.fresh(Claim.RECYCLED, RECYCLED_THRESHOLD), RECYCLED_THRESHOLD).toWitnessMap()));
        assertViolation(() -> witness(circuit, DppCircuits.recycledInputs(
                ClaimOpening.fresh(Claim.RECYCLED, RECYCLED_THRESHOLD - 1), RECYCLED_THRESHOLD).toWitnessMap()));
    }

    // ------------------------------------------------------------------ opening and schema

    @Test
    @DisplayName("A wrong blinding, or another value under the same blinding, does not open the commitment")
    void wrongOpening() {
        CircuitBuilder circuit = circuits.circuit(Claim.CARBON).circuit();
        var o = ClaimOpening.fresh(Claim.CARBON, 7);
        assertViolation(() -> witness(circuit,
                DppCircuits.carbonInputs(o, CARBON_THRESHOLD).blinding(o.blinding().add(BigInteger.ONE)).toWitnessMap()));
        assertViolation(() -> witness(circuit,
                DppCircuits.carbonInputs(o, CARBON_THRESHOLD).carbonKg(6).toWitnessMap()));
        // The inspection vector: one changed time under the committed (u, v).
        var insp = ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1000, 12, 2000, 13, 3000);
        assertViolation(() -> witness(circuits.circuit(Claim.INSPECTIONS).circuit(),
                DppCircuits.inspectionInputs(insp, ApprovedSets.INSPECTORS).times(1, 2500).toWitnessMap()));
    }

    @Test
    @DisplayName("An aliased opening (m + l with the same blinding, the same point) is refused by the range constraint")
    void aliasedOpening() {
        var o = ClaimOpening.fresh(Claim.CARBON, 7);
        BigInteger aliased = BigInteger.valueOf(7).add(JubjubCurve.SUBGROUP_ORDER);
        // Host side: (7 + l)·G0 + r·H is the committed point, since G0 has order l.
        JubjubPoint alias = PedersenVectorBases.valueBase(0).scalarMul(aliased)
                .add(PedersenVectorBases.blindingBase().scalarMul(o.blinding())).normalized();
        assertEquals(o.point().affineU(), alias.affineU());
        assertEquals(o.point().affineV(), alias.affineV());
        // In-circuit, carbon_kg is 16 bits, so the alias has no witness (even against a threshold it would meet mod l).
        Map<String, List<BigInteger>> inputs = new HashMap<>(DppCircuits.carbonInputs(o, 65_535).toWitnessMap());
        inputs.put(CarbonClaimProofCircuit.CARBON_KG, List.of(aliased));
        assertViolation(() -> witness(circuits.circuit(Claim.CARBON).circuit(), inputs));
        // Likewise for the country and an inspection time.
        var origin = ClaimOpening.fresh(Claim.ORIGIN, 276);
        Map<String, List<BigInteger>> originInputs = new HashMap<>(DppCircuits.originInputs(origin, ApprovedSets.EU_COUNTRIES).toWitnessMap());
        originInputs.put("country", List.of(BigInteger.valueOf(276).add(JubjubCurve.SUBGROUP_ORDER)));
        assertViolation(() -> witness(circuits.circuit(Claim.ORIGIN).circuit(), originInputs));
        var insp = ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1000, 12, 2000, 13, 3000);
        assertViolation(() -> witness(circuits.circuit(Claim.INSPECTIONS).circuit(), DppCircuits.inspectionInputs(insp, ApprovedSets.INSPECTORS)
                .times(2, BigInteger.valueOf(3000).add(JubjubCurve.SUBGROUP_ORDER)).toWitnessMap()));
    }

    @Test
    @DisplayName("Another schema's digest is refused by every circuit")
    void wrongSchemaDigest() {
        var carbon = ClaimOpening.fresh(Claim.CARBON, 7);
        assertViolation(() -> witness(circuits.circuit(Claim.CARBON).circuit(),
                DppCircuits.carbonInputs(carbon, CARBON_THRESHOLD).schemaDigest(Claim.RECYCLED.schema().digest()).toWitnessMap()));
        var recycled = ClaimOpening.fresh(Claim.RECYCLED, 45);
        assertViolation(() -> witness(circuits.circuit(Claim.RECYCLED).circuit(),
                DppCircuits.recycledInputs(recycled, RECYCLED_THRESHOLD).schemaDigest(Claim.CARBON.schema().digest()).toWitnessMap()));
        var origin = ClaimOpening.fresh(Claim.ORIGIN, DEU);
        assertViolation(() -> witness(circuits.circuit(Claim.ORIGIN).circuit(),
                DppCircuits.originInputs(origin, ApprovedSets.EU_COUNTRIES).schemaDigest(Claim.CARBON.schema().digest()).toWitnessMap()));
        var insp = ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1000, 12, 2000, 13, 3000);
        assertViolation(() -> witness(circuits.circuit(Claim.INSPECTIONS).circuit(),
                DppCircuits.inspectionInputs(insp, ApprovedSets.INSPECTORS).schemaDigest(Claim.ORIGIN.schema().digest()).toWitnessMap()));
    }

    // ------------------------------------------------------------------ origin

    @Test
    @DisplayName("Origin: a listed country proves; an unlisted one and 0 against the sentinel-padded tree do not")
    void origin() {
        CircuitBuilder circuit = circuits.circuit(Claim.ORIGIN).circuit();
        ApprovedSet eu = ApprovedSets.EU_COUNTRIES;
        assertEquals(BigInteger.ONE.shiftLeft(16), eu.sentinel());
        assertDoesNotThrow(() -> witness(circuit, DppCircuits.originInputs(ClaimOpening.fresh(Claim.ORIGIN, DEU), eu).toWitnessMap()));
        // Unlisted: CHN with every listed country's path, and with the padding path.
        var chn = ClaimOpening.fresh(Claim.ORIGIN, CHN);
        for (int leaf = 0; leaf < (1 << eu.depth()); leaf++) {
            var path = eu.pathAt(leaf);
            assertViolation(() -> witness(circuit, DppCircuits.originInputs(chn, eu)
                    .siblings(path.siblings()).pathBits(path.pathBits()).toWitnessMap()), "CHN at leaf " + leaf);
        }
        // 0 is not a member: with the sentinel no leaf holds 0.
        var zero = ClaimOpening.fresh(Claim.ORIGIN, 0);
        for (int leaf = 0; leaf < (1 << eu.depth()); leaf++) {
            var path = eu.pathAt(leaf);
            assertViolation(() -> witness(circuit, DppCircuits.originInputs(zero, eu)
                    .siblings(path.siblings()).pathBits(path.pathBits()).toWitnessMap()), "0 at leaf " + leaf);
        }
    }

    @Test
    @DisplayName("Why the sentinel: a zero-padded tree would admit the value 0")
    void zeroPaddingWouldAdmitZero() {
        // The old trees padded with 0. A 0 in the first padding slot (leaf 27) is that tree's
        // path for 0, rebuilt here only to show the flaw the sentinel closes.
        List<BigInteger> withZero = new ArrayList<>(ApprovedSets.EU_COUNTRIES.members());
        withZero.add(BigInteger.ZERO);
        ApprovedSet zeroPadded = new ApprovedSet(withZero, OriginClaimProof.DEPTH, 16);
        var zero = ClaimOpening.fresh(Claim.ORIGIN, 0);
        assertDoesNotThrow(() -> witness(circuits.circuit(Claim.ORIGIN).circuit(),
                DppCircuits.originInputs(zero, zeroPadded).toWitnessMap()));
    }

    // ------------------------------------------------------------------ inspections

    @Test
    @DisplayName("Inspections: approved inspectors (repeats allowed) in strictly increasing time prove")
    void inspectionsHonest() {
        CircuitBuilder circuit = circuits.circuit(Claim.INSPECTIONS).circuit();
        assertDoesNotThrow(() -> witness(circuit, DppCircuits.inspectionInputs(
                ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1000, 11, 1001, 15, 4_000_000_000L), ApprovedSets.INSPECTORS).toWitnessMap()));
    }

    @Test
    @DisplayName("Inspections: an unlisted inspector, the padding value, equal or decreasing times have no witness")
    void inspectionsRefused() {
        CircuitBuilder circuit = circuits.circuit(Claim.INSPECTIONS).circuit();
        ApprovedSet set = ApprovedSets.INSPECTORS;
        assertEquals(BigInteger.valueOf(256), set.sentinel());
        var unlisted = ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1000, 99, 2000, 13, 3000);
        for (int leaf = 0; leaf < (1 << set.depth()); leaf++) {
            var path = set.pathAt(leaf);
            var inputs = DppCircuits.inspectionInputs(unlisted, set);
            for (int col = 0; col < set.depth(); col++) {
                inputs.siblings(1, col, path.siblings().get(col)).pathBits(1, col, path.pathBits().get(col));
            }
            assertViolation(() -> witness(circuit, inputs.toWitnessMap()), "inspector 99 at leaf " + leaf);
        }
        // 0 is not an inspector: with the sentinel no leaf holds 0, at any checkpoint's path.
        var zero = ClaimOpening.fresh(Claim.INSPECTIONS, 0, 1000, 12, 2000, 13, 3000);
        for (int leaf = 0; leaf < (1 << set.depth()); leaf++) {
            var path = set.pathAt(leaf);
            var inputs = DppCircuits.inspectionInputs(zero, set);
            for (int col = 0; col < set.depth(); col++) {
                inputs.siblings(0, col, path.siblings().get(col)).pathBits(0, col, path.pathBits().get(col));
            }
            assertViolation(() -> witness(circuit, inputs.toWitnessMap()), "inspector 0 at leaf " + leaf);
        }
        var equal = ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1000, 12, 2000, 13, 2000);
        assertViolation(() -> witness(circuit, DppCircuits.inspectionInputs(equal, set).toWitnessMap()));
        var decreasing = ClaimOpening.fresh(Claim.INSPECTIONS, 11, 2000, 12, 1000, 13, 3000);
        assertViolation(() -> witness(circuit, DppCircuits.inspectionInputs(decreasing, set).toWitnessMap()));
        var wrapped = ClaimOpening.fresh(Claim.INSPECTIONS, 11, 4_000_000_000L, 12, 1000, 13, 3000);
        assertViolation(() -> witness(circuit, DppCircuits.inspectionInputs(wrapped, set).toWitnessMap()));
    }

    // ------------------------------------------------------------------ helpers

    static BigInteger param(Claim claim) {
        return switch (claim) {
            case CARBON -> BigInteger.valueOf(CARBON_THRESHOLD);
            case RECYCLED -> BigInteger.valueOf(RECYCLED_THRESHOLD);
            case ORIGIN -> ApprovedSets.EU_COUNTRIES.root();
            case INSPECTIONS -> ApprovedSets.INSPECTORS.root();
        };
    }

    /** The relation does not hold: the witness calculator reports a violated constraint, not a host-side error. */
    private static void assertViolation(Executable witness) {
        assertViolation(witness, "");
    }

    private static void assertViolation(Executable witness, String what) {
        ArithmeticException e = assertThrows(ArithmeticException.class, witness, what);
        assertTrue(e.getMessage().startsWith("Constraint violation"), what + ": " + e.getMessage());
    }

    private static BigInteger[] witness(CircuitBuilder circuit, Map<String, List<BigInteger>> inputs) {
        return circuit.calculateWitness(inputs, CurveId.BLS12_381);
    }
}
