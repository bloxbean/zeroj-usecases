package com.bloxbean.cardano.zeroj.usecases.selective.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalPoseidon;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * Predicate circuit #1: <b>Adult Resident</b>.
 *
 * <p>Proves: <i>"I hold an issuer-signed credential whose
 * {@code (currentYear - dobYear) ≥ 21} AND whose {@code country} is in the
 * approved EU set"</i>, without revealing dobYear, country, role, salary,
 * name.
 *
 * <h2>Public inputs</h2>
 * {@code pkU, pkV, currentYear, countryRoot, eligible}.
 *
 * <h2>Secret inputs</h2>
 * Full credential (dobYear, country, roleId, salaryBracket, nameHash) +
 * issuer signature + EdDSA reduction witnesses + country Merkle proof.
 *
 * @param countryTreeDepth depth of the approved-country Merkle tree
 */
public class AdultResidentCircuit implements CircuitSpec {

    public static final int MIN_AGE = 21;

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;

    private final int countryTreeDepth;

    public AdultResidentCircuit(int countryTreeDepth) {
        this.countryTreeDepth = countryTreeDepth;
    }

    @Override
    public void define(SignalBuilder c) {
        // Public
        Signal pkU = c.publicInput("pkU");
        Signal pkV = c.publicInput("pkV");
        Signal currentYear = c.publicInput("currentYear");
        Signal countryRoot = c.publicInput("countryRoot");
        Signal eligible = c.publicOutput("eligible");

        // Secret credential fields
        Signal dobYear = c.privateInput("dobYear");
        Signal country = c.privateInput("country");
        Signal roleId = c.privateInput("roleId");
        Signal salaryBracket = c.privateInput("salaryBracket");
        Signal nameHash = c.privateInput("nameHash");

        // Secret signature + reduction witnesses
        Signal sigRU = c.privateInput("sigRU");
        Signal sigRV = c.privateInput("sigRV");
        Signal sigS = c.privateInput("sigS");
        Signal kModL = c.privateInput("kModL");
        Signal kQuotient = c.privateInput("kQuotient");

        // Country Merkle proof
        Signal[] siblings = new Signal[countryTreeDepth];
        Signal[] pathBits = new Signal[countryTreeDepth];
        for (int i = 0; i < countryTreeDepth; i++) {
            siblings[i] = c.privateInput("sibling_" + i);
            pathBits[i] = c.privateInput("pathBit_" + i);
        }

        // 1. Recompute claimsMsg = Poseidon(dobYear, country, roleId, salaryBracket, nameHash).
        //    Must match exactly how the off-circuit signer composed the message.
        Signal claimsMsg = c.wrap(PoseidonN.hash(c.api(), POSEIDON,
                dobYear.variable(), country.variable(), roleId.variable(),
                salaryBracket.variable(), nameHash.variable()));

        // 2. EdDSA-Jubjub verify against issuer pk.
        InCircuitJubjub.Point pkPoint = new InCircuitJubjub.Point(
                pkU.variable(), pkV.variable(), c.api().constant(1),
                c.api().mul(pkU.variable(), pkV.variable()));
        InCircuitJubjub.Point sigRPoint = new InCircuitJubjub.Point(
                sigRU.variable(), sigRV.variable(), c.api().constant(1),
                c.api().mul(sigRU.variable(), sigRV.variable()));
        InCircuitEdDSAJubjub.verify(c.api(), pkPoint, claimsMsg.variable(),
                sigRPoint, sigS.variable(), kModL.variable(), kQuotient.variable());

        // 3. Predicate: currentYear - dobYear >= MIN_AGE
        //    Equivalently: dobYear <= currentYear - MIN_AGE.
        //    Use 16-bit unsigned comparison (years easily fit).
        Signal maxDobYear = c.wrap(c.api().sub(currentYear.variable(), c.api().constant(MIN_AGE)));
        Signal ageOk = SignalComparators.lessOrEqual(c, dobYear, maxDobYear, 16);

        // 4. Predicate: country ∈ approved countries Merkle tree (root = countryRoot).
        SignalMerkle.verifyProof(c, country, countryRoot,
                siblings, pathBits, (sb, a, b) -> SignalPoseidon.hash(sb, POSEIDON, a, b));

        // 5. Eligibility = ageOk (Merkle membership is a hard assertion above).
        c.assertEqual(eligible, ageOk);
    }

    public static CircuitBuilder build(int countryTreeDepth) {
        var b = CircuitBuilder.create("adult-resident")
                .publicVar("pkU").publicVar("pkV")
                .publicVar("currentYear")
                .publicVar("countryRoot")
                .publicVar("eligible")
                .secretVar("dobYear").secretVar("country").secretVar("roleId")
                .secretVar("salaryBracket").secretVar("nameHash")
                .secretVar("sigRU").secretVar("sigRV").secretVar("sigS")
                .secretVar("kModL").secretVar("kQuotient");
        for (int i = 0; i < countryTreeDepth; i++) {
            b = b.secretVar("sibling_" + i).secretVar("pathBit_" + i);
        }
        return b.defineSignals(new AdultResidentCircuit(countryTreeDepth));
    }
}
