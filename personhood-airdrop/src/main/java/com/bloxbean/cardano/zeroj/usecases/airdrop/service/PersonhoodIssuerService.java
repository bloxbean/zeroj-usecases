package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Personhood credential issuer (think BrightID / Worldcoin / similar).
 *
 * <p>Each "personhood credential" binds a randomly-allocated unique opaque
 * identifier ({@code personhoodId}) to the issuer's signature. The
 * personhoodId is per-real-human (the issuer enforces uniqueness off-chain
 * via biometric / proof-of-personhood mechanism — out of scope for this
 * demo). Holders never reveal the personhoodId on-chain; the airdrop
 * circuit's nullifier is the only public derivative.
 */
@Service
public class PersonhoodIssuerService {

    private static final Logger log = LoggerFactory.getLogger(PersonhoodIssuerService.class);

    /** Demo issuer secret key seed. Production: load from KMS / HSM. */
    private static final BigInteger ISSUER_SECRET_SEED = new BigInteger(
            "deadbeefcafef00d0123456789abcdefdeadbeefcafef00d0123456789abcdef", 16);

    private EdDSAJubjub.Keypair issuerKeypair;
    private final Map<String, PersonhoodCredential> credentials = Collections.synchronizedMap(new LinkedHashMap<>());

    @PostConstruct
    public void setup() {
        BigInteger sk = ISSUER_SECRET_SEED.mod(JubjubCurve.SUBGROUP_ORDER);
        if (sk.signum() == 0) sk = BigInteger.ONE;
        issuerKeypair = EdDSAJubjub.keypairFromSecret(sk);
        log.info("Personhood issuer keypair generated.");
        log.info("  pk.u = 0x{}", issuerKeypair.pk().affineU().toString(16));
        log.info("  pk.v = 0x{}", issuerKeypair.pk().affineV().toString(16));

        seedTestUsers();
    }

    private void seedTestUsers() {
        // Each gets a unique random-looking personhoodId.
        long base = 0x100;
        for (String name : List.of("Alice", "Bob", "Charlie", "Diana", "Eve")) {
            BigInteger pid = BigInteger.valueOf(base++).shiftLeft(160)
                    .or(BigInteger.valueOf(name.hashCode() & 0xffffffffL));
            issueCredential(name, pid);
        }
        log.info("Issued {} demo personhood credentials.", credentials.size());
    }

    /**
     * Issues a personhood credential. {@code personhoodId} must be unique per
     * real human (issuer's job to enforce — the demo just generates a unique
     * 256-bit value per name).
     */
    public PersonhoodCredential issueCredential(String name, BigInteger personhoodId) {
        // Sign Poseidon(personhoodId, 0) — the message bound by the signature.
        // The "0" pads personhoodId into the t=3 Poseidon's two-input slot.
        BigInteger msg = com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash.hash(
                com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3.INSTANCE,
                personhoodId, BigInteger.ZERO);
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(issuerKeypair.sk(), msg);
        var cred = new PersonhoodCredential(name, personhoodId, sig);
        credentials.put(name, cred);
        return cred;
    }

    public JubjubPoint getIssuerPublicKey() {
        return issuerKeypair.pk();
    }

    public PersonhoodCredential get(String name) {
        return credentials.get(name);
    }

    public List<PersonhoodCredential> list() {
        return List.copyOf(credentials.values());
    }

    /** A holder's personhood credential — claims plus the issuer's signature. */
    public record PersonhoodCredential(String name, BigInteger personhoodId,
                                      EdDSAJubjub.Signature signature) {}
}
