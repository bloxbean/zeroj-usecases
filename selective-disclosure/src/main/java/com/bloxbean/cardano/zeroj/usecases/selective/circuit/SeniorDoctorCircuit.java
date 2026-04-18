package com.bloxbean.cardano.zeroj.usecases.selective.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalComparators;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitEdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * Predicate circuit #2: <b>Senior Doctor</b>.
 *
 * <p>Proves: <i>"I hold an issuer-signed credential whose
 * {@code roleId == DOCTOR} AND whose {@code (currentYear - dobYear) ≥ 30}"</i>,
 * without revealing dobYear, country, salaryBracket, or name.
 *
 * <h2>Public inputs</h2>
 * {@code pkU, pkV, currentYear, eligible}.
 *
 * <h2>Demonstrates</h2>
 * The same credential signed by the issuer satisfies multiple distinct
 * predicates. {@link AdultResidentCircuit} and this circuit share the
 * issuer signature; only the predicate differs. A single Bob (born 1990,
 * doctor in Germany, salary bracket 4) can prove both:
 * <ul>
 *   <li>"adult resident" (for Library DApp)</li>
 *   <li>"senior doctor"  (for Healthcare Portal DApp)</li>
 * </ul>
 * — two different proofs against two different Plutus validators, one
 * underlying credential. That's W3C VC selective disclosure.
 */
public class SeniorDoctorCircuit implements CircuitSpec {

    public static final int MIN_AGE = 30;

    private static final PoseidonParams POSEIDON = PoseidonParamsBLS12_381T3.INSTANCE;
    private static final long DOCTOR_ROLE_ID = 1001L;

    @Override
    public void define(SignalBuilder c) {
        Signal pkU = c.publicInput("pkU");
        Signal pkV = c.publicInput("pkV");
        Signal currentYear = c.publicInput("currentYear");
        Signal eligible = c.publicOutput("eligible");

        Signal dobYear = c.privateInput("dobYear");
        Signal country = c.privateInput("country");
        Signal roleId = c.privateInput("roleId");
        Signal salaryBracket = c.privateInput("salaryBracket");
        Signal nameHash = c.privateInput("nameHash");

        Signal sigRU = c.privateInput("sigRU");
        Signal sigRV = c.privateInput("sigRV");
        Signal sigS = c.privateInput("sigS");
        Signal kModL = c.privateInput("kModL");
        Signal kQuotient = c.privateInput("kQuotient");

        Signal claimsMsg = c.wrap(PoseidonN.hash(c.api(), POSEIDON,
                dobYear.variable(), country.variable(), roleId.variable(),
                salaryBracket.variable(), nameHash.variable()));

        InCircuitJubjub.Point pkPoint = new InCircuitJubjub.Point(
                pkU.variable(), pkV.variable(), c.api().constant(1),
                c.api().mul(pkU.variable(), pkV.variable()));
        InCircuitJubjub.Point sigRPoint = new InCircuitJubjub.Point(
                sigRU.variable(), sigRV.variable(), c.api().constant(1),
                c.api().mul(sigRU.variable(), sigRV.variable()));
        InCircuitEdDSAJubjub.verify(c.api(), pkPoint, claimsMsg.variable(),
                sigRPoint, sigS.variable(), kModL.variable(), kQuotient.variable());

        // Predicate part 1: roleId == DOCTOR.
        c.assertEqual(roleId, c.constant(DOCTOR_ROLE_ID));

        // Predicate part 2: dobYear ≤ currentYear - 30 (i.e. age ≥ 30).
        Signal maxDobYear = c.wrap(c.api().sub(currentYear.variable(), c.api().constant(MIN_AGE)));
        Signal ageOk = SignalComparators.lessOrEqual(c, dobYear, maxDobYear, 16);

        c.assertEqual(eligible, ageOk);
    }

    public static CircuitBuilder build() {
        return CircuitBuilder.create("senior-doctor")
                .publicVar("pkU").publicVar("pkV")
                .publicVar("currentYear")
                .publicVar("eligible")
                .secretVar("dobYear").secretVar("country").secretVar("roleId")
                .secretVar("salaryBracket").secretVar("nameHash")
                .secretVar("sigRU").secretVar("sigRV").secretVar("sigS")
                .secretVar("kModL").secretVar("kQuotient")
                .defineSignals(new SeniorDoctorCircuit());
    }
}
