package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The holder side of the airdrop (ADR-0009 D3.1): each holder samples its own secret
 * {@code personhoodId} (252 bits, {@link SecureRandom}) and sends the issuer only
 * {@code m = Poseidon(personhoodId, 0)}. The holder keeps {@code personhoodId} and the issuer's
 * signature; only it can compute its nullifiers.
 *
 * <p><b>Custodial demo wallet.</b> In this demo the server holds every holder's wallet, so the
 * demo server (not the issuer component) knows each {@code personhoodId}. That is the operator
 * view (ADR-0009 D10). A real holder keeps {@code personhoodId} on its own device.
 *
 * <p>The wallet file is written atomically and owner-only. On load, every stored credential must
 * verify under the current issuer key, otherwise startup fails (a changed issuer key never
 * passes silently).
 */
@Service
public class HolderWallet {

    private static final Logger log = LoggerFactory.getLogger(HolderWallet.class);
    private static final int PID_BITS = 252;

    private final PersonhoodIssuer issuer;
    private final Path file;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Credential> credentials = new LinkedHashMap<>();

    public HolderWallet(PersonhoodIssuer issuer, AirdropDataDir data) {
        this.issuer = issuer;
        this.file = data.holderWallet();
        load();
    }

    /**
     * Enrols {@code name}: samples a fresh {@code personhoodId} and obtains the issuer's signature
     * on {@code Poseidon(personhoodId, 0)}. A holder that already has a credential keeps it.
     *
     * @throws PersonhoodIssuer.AlreadyIssuedException if the issuer already issued to this person
     *         (for example, a credential lost with the wallet; it cannot be re-issued)
     */
    public synchronized Credential enroll(String name) {
        Credential existing = credentials.get(name);
        if (existing != null) {
            return existing;
        }
        BigInteger pid = samplePersonhoodId();
        BigInteger m = message(pid);
        EdDSAJubjub.Signature sig = issuer.issue(name, m);
        if (!EdDSAJubjub.verify(issuer.publicKey(), m, sig)) {
            throw new IllegalStateException("the issuer's signature does not verify");
        }
        var credential = new Credential(name, pid, sig);
        credentials.put(name, credential);
        persist();
        log.info("Holder {} enrolled with a fresh, holder-chosen personhood identifier", name);
        return credential;
    }

    public synchronized Credential get(String name) {
        return credentials.get(name);
    }

    public synchronized List<String> holders() {
        return List.copyOf(credentials.keySet());
    }

    /** {@code m = Poseidon(personhoodId, 0)}, the only value the issuer receives. */
    public static BigInteger message(BigInteger personhoodId) {
        return PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, personhoodId, BigInteger.ZERO);
    }

    /** The holder's nullifier for {@code epoch}: {@code Poseidon(personhoodId, epoch)}. */
    public static BigInteger nullifier(BigInteger personhoodId, BigInteger epoch) {
        return PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, personhoodId, epoch);
    }

    private BigInteger samplePersonhoodId() {
        BigInteger pid;
        do {
            pid = new BigInteger(PID_BITS, random);
        } while (pid.signum() == 0);
        return pid;
    }

    private void load() {
        JsonNode node = DemoFiles.read(file);
        if (node == null) {
            return;
        }
        JsonNode list = node.get("holders");
        if (list == null || !list.isArray()) {
            throw new IllegalStateException(file + " is corrupt: missing holders");
        }
        JubjubPoint pk = issuer.publicKey();
        for (JsonNode h : list) {
            try {
                String name = DemoFiles.text(h, "name", file);
                BigInteger pid = new BigInteger(DemoFiles.text(h, "personhoodId", file), 16);
                var r = JubjubPoint.fromAffine(new BigInteger(DemoFiles.text(h, "sigRU", file), 16),
                        new BigInteger(DemoFiles.text(h, "sigRV", file), 16));
                var sig = new EdDSAJubjub.Signature(r, new BigInteger(DemoFiles.text(h, "sigS", file), 16));
                if (!EdDSAJubjub.verify(pk, message(pid), sig)) {
                    throw new IllegalStateException(file + ": the credential of " + name
                            + " does not verify under the current issuer key; refusing to start."
                            + " Reset keys and state together with ./demo.sh airdrop --clean-cache.");
                }
                credentials.put(name, new Credential(name, pid, sig));
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException(file + " is corrupt", e);
            }
        }
    }

    private void persist() {
        var out = DemoFiles.object();
        var list = out.putArray("holders");
        credentials.values().forEach(c -> list.addObject()
                .put("name", c.name())
                .put("personhoodId", c.personhoodId().toString(16))
                .put("sigRU", c.signature().r().affineU().toString(16))
                .put("sigRV", c.signature().r().affineV().toString(16))
                .put("sigS", c.signature().s().toString(16)));
        DemoFiles.writeAtomic(file, out);
    }

    /** A holder's personhood credential: its secret identifier and the issuer's signature on m. */
    public record Credential(String name, BigInteger personhoodId, EdDSAJubjub.Signature signature) {
        @Override
        public String toString() {
            return "Credential[name=" + name + ", personhoodId=<redacted>]";
        }
    }
}
