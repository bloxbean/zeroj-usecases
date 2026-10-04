package com.bloxbean.cardano.zeroj.usecases.voting.circuit;

import org.zeroj.circuit.BitDecomposition;
import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.InCircuitJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.zk.ZkJubjubPoint;

/**
 * In-circuit relations for the private ballot (ADR-0005): exponential ElGamal over the Jubjub
 * prime-order subgroup, and discrete-log equality for trustee key and decryption-share proofs.
 *
 * <p>Built from ZeroJ's Jubjub gadgets. The two scalar multiplications of one relation always
 * consume <b>one</b> bit decomposition of the scalar, so both use the same scalar. Every point a
 * verifier supplies is bound with the curve equation ({@link ZkJubjubPoint#witnessAffine});
 * subgroup membership of those points is established outside the circuit, as ADR-0005 states for
 * each one.
 */
public final class JubjubElGamalGadget {

    private JubjubElGamalGadget() {}

    /**
     * Asserts {@code A = [k]·G} and {@code B = [v]·G + [k]·PK}, with {@code (A, B)} given by their
     * public affine coordinates.
     *
     * @param vote       the message bit {@code v}; boolean by construction of {@link ZkBool}
     * @param randomness the encryption scalar {@code k}; must be declared 252 bits wide
     * @param keyU       election key {@code PK}, affine u (verifier-supplied public input)
     * @param keyV       election key {@code PK}, affine v
     */
    public static void assertEncrypts(ZkContext zk, ZkBool vote, ZkUInt randomness,
                                      ZkField keyU, ZkField keyV,
                                      ZkField handleU, ZkField handleV,
                                      ZkField ballotU, ZkField ballotV) {
        CircuitAPI api = zk.builder().api();
        BitDecomposition k = hidingScalar(api, randomness);

        // PK is a script parameter, never prover-chosen. Bind it to the curve here; its subgroup
        // membership is discharged at key setup. An identity key would make B = [v]·G public, so
        // refuse it in the circuit too, not only at setup.
        ZkJubjubPoint key = ZkJubjubPoint.witnessAffine(zk, keyU, keyV);
        key.assertNotIdentity(zk);

        InCircuitJubjub.Point handle = InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, k);
        InCircuitJubjub.Point mask = InCircuitJubjub.scalarMulVariableBase(api, point(key), k);
        InCircuitJubjub.Point message = InCircuitJubjub.select(api, vote.signal().variable(),
                InCircuitJubjub.constant(api, JubjubPoint.SUBGROUP_GENERATOR),
                InCircuitJubjub.identity(api));
        InCircuitJubjub.Point ballot = InCircuitJubjub.add(api, message, mask);

        assertAffineEquals(api, handle, handleU, handleV);
        assertAffineEquals(api, ballot, ballotU, ballotV);
    }

    /**
     * Asserts {@code P = [x]·G} and {@code D = [x]·X}: the prover knows one {@code x} that is the
     * discrete log of {@code P} to base {@code G} and of {@code D} to base {@code X}.
     *
     * <p>With {@code X = G} and {@code D = P} this is a proof of knowledge of a trustee's secret
     * key share (proof of possession). With {@code X = ΣA} it proves a decryption share.
     */
    public static void assertDiscreteLogEquality(ZkContext zk, ZkUInt secret,
                                                 ZkField baseU, ZkField baseV,
                                                 ZkField publicKeyU, ZkField publicKeyV,
                                                 ZkField shareU, ZkField shareV) {
        CircuitAPI api = zk.builder().api();
        BitDecomposition x = hidingScalar(api, secret);
        ZkJubjubPoint base = ZkJubjubPoint.witnessAffine(zk, baseU, baseV);

        InCircuitJubjub.Point publicKey = InCircuitJubjub.scalarMulFixedBase(api, JubjubPoint.SUBGROUP_GENERATOR, x);
        InCircuitJubjub.Point share = InCircuitJubjub.scalarMulVariableBase(api, point(base), x);

        assertAffineEquals(api, publicKey, publicKeyU, publicKeyV);
        assertAffineEquals(api, share, shareU, shareV);
    }

    /**
     * The scalar's single decomposition, after the ADR-0051 D2 guard rails: a full 252-bit width,
     * a secret (not public, not constant) wire, and no narrower range anywhere in the circuit. A
     * narrow encryption scalar would let anyone recover the vote by enumeration.
     */
    private static BitDecomposition hidingScalar(CircuitAPI api, ZkUInt scalar) {
        if (scalar.bits() != JubjubCurve.SCALAR_BITS) {
            throw new IllegalArgumentException("scalar must be declared " + JubjubCurve.SCALAR_BITS
                    + " bits wide; got " + scalar.bits());
        }
        Variable wire = scalar.signal().variable();
        api.requireNotPublicOrConstant(wire);
        api.requireHidingRange(wire, JubjubCurve.SCALAR_BITS);
        return scalar.decomposition();
    }

    /** {@code P = (u, v)}: {@code Z ≠ 0}, {@code U = u·Z}, {@code V = v·Z}. */
    private static void assertAffineEquals(CircuitAPI api, InCircuitJubjub.Point p, ZkField u, ZkField v) {
        api.assertNotEqual(p.z(), api.constant(0));
        api.assertEqual(api.mul(u.signal().variable(), p.z()), p.u());
        api.assertEqual(api.mul(v.signal().variable(), p.z()), p.v());
    }

    private static InCircuitJubjub.Point point(ZkJubjubPoint p) {
        return new InCircuitJubjub.Point(p.u().signal().variable(), p.v().signal().variable(),
                p.z().signal().variable(), p.t().signal().variable());
    }
}
