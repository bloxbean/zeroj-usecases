package com.bloxbean.cardano.zeroj.usecases.selective.circuit;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;

/**
 * Multi-field W3C VC schema used by both predicate circuits in this demo.
 *
 * <h2>Fields (all BLS12-381 scalar field elements)</h2>
 * <ol>
 *   <li>{@code dobYear} — year of birth, e.g. 1990. 16-bit unsigned.</li>
 *   <li>{@code country} — ISO 3166 numeric, e.g. 276 (DEU). 16-bit unsigned.</li>
 *   <li>{@code roleId} — opaque role identifier (see {@link Roles}).</li>
 *   <li>{@code salaryBracket} — 0–9 (10 brackets). 4-bit unsigned.</li>
 *   <li>{@code nameHash} — Poseidon hash of the holder's name; opaque.</li>
 * </ol>
 *
 * <h2>Issuer signature</h2>
 * The issuer signs {@code claimsMsg = Poseidon(...all fields...)} with
 * EdDSA-Jubjub. The same signature satisfies any predicate circuit because
 * each predicate independently re-derives {@code claimsMsg} from the
 * provided field witnesses, then verifies the issuer's signature on it.
 *
 * <h2>Predicate composition</h2>
 * Each predicate circuit takes the same set of field witnesses, computes
 * the same {@code claimsMsg}, verifies the issuer signature, and then
 * asserts a different predicate. The W3C VC privacy benefit: holder
 * reveals only the predicate result, never the underlying field values.
 */
public final class CredentialSchema {

    private CredentialSchema() {}

    /**
     * Computes the message that the issuer signs:
     * {@code Poseidon-fold(dobYear, country, roleId, salaryBracket, nameHash)}.
     *
     * <p>Folding via {@link PoseidonHash#hashN} matches how the in-circuit
     * gadget computes the same value (see {@code PoseidonN.hash}).
     */
    public static BigInteger claimsMessage(BigInteger dobYear, BigInteger country,
                                          BigInteger roleId, BigInteger salaryBracket,
                                          BigInteger nameHash) {
        return PoseidonHash.hashN(PoseidonParamsBLS12_381T3.INSTANCE,
                dobYear, country, roleId, salaryBracket, nameHash);
    }

    /** Standard role identifiers used by the demo. */
    public static final class Roles {
        public static final BigInteger DOCTOR = BigInteger.valueOf(1001);
        public static final BigInteger NURSE = BigInteger.valueOf(1002);
        public static final BigInteger ENGINEER = BigInteger.valueOf(2001);
        public static final BigInteger TEACHER = BigInteger.valueOf(3001);
        public static final BigInteger LAWYER = BigInteger.valueOf(4001);
        public static final BigInteger STUDENT = BigInteger.valueOf(9001);
        private Roles() {}
    }

    /**
     * Reduces a UTF-8 name to a field-element name-hash via Poseidon. Demo-
     * grade — production should use a more careful hash-to-field with domain
     * separation.
     */
    public static BigInteger nameHash(String name) {
        BigInteger raw = new BigInteger(1, name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        BigInteger reduced = raw.mod(com.bloxbean.cardano.zeroj.circuit.FieldConfig.BLS12_381.prime());
        return PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, reduced, BigInteger.ZERO);
    }
}
