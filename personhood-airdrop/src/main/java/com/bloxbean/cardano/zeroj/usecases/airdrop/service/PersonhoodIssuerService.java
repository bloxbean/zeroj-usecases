package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubMessage;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Personhood credential issuer (think BrightID / Worldcoin / similar), ADR-0009 D3.
 *
 * <p>The holder chooses its own secret {@code personhoodId} and sends only
 * {@code m = Poseidon(personhoodId, 0)}. After its one-human check (out of band; in the demo,
 * the person's name stands for it) the issuer signs {@code m}. It never receives
 * {@code personhoodId}, so it cannot compute any claim's nullifier
 * {@code Poseidon(personhoodId, epoch)}, and cannot link claims to persons.
 *
 * <p><b>One credential per person.</b> The issuer keeps a durable record (atomic, owner-only)
 * of each person it has issued to, written before it signs, and refuses a second issuance.
 * Without this rule, holder-chosen identifiers would let one person obtain two credentials and
 * claim twice. Consequently a lost credential cannot be re-issued.
 *
 * <p>The signing key is random and persisted ({@link AirdropKeys}, ADR-0009 D11). Signing uses
 * ZeroJ's compatibility/offline profile; this demo issuer is an in-process component and must
 * not be exposed as a network-reachable issuance endpoint.
 */
@Service
public class PersonhoodIssuerService implements PersonhoodIssuer {

    private static final Logger log = LoggerFactory.getLogger(PersonhoodIssuerService.class);

    private final EdDSAJubjub.Keypair issuerKeypair;
    private final Path recordFile;
    private final Map<String, String> issued = new LinkedHashMap<>();

    public PersonhoodIssuerService(AirdropKeys keys, AirdropDataDir data) {
        this.issuerKeypair = keys.issuer();
        this.recordFile = data.issuedPersons();
        load();
        log.info("Personhood issuer public key: u=0x{}, v=0x{}; {} person(s) issued so far",
                issuerKeypair.pk().affineU().toString(16), issuerKeypair.pk().affineV().toString(16), issued.size());
    }

    @Override
    public synchronized EdDSAJubjub.Signature issue(String person, BigInteger m) {
        String who = normalize(person);
        JubjubMessage message = canonicalMessage(m);
        if (issued.containsKey(who)) {
            throw new AlreadyIssuedException(who);
        }
        // Record first: a crash after signing must not allow a second credential.
        issued.put(who, Instant.now().toString());
        try {
            persist();
        } catch (RuntimeException e) {
            issued.remove(who);
            throw e;
        }
        log.info("Issued a personhood credential to {}", who);
        return EdDSAJubjub.signCompatibilityOffline(issuerKeypair, message);
    }

    @Override
    public JubjubPoint publicKey() {
        return issuerKeypair.pk();
    }

    public synchronized boolean hasIssued(String person) {
        return issued.containsKey(normalize(person));
    }

    public synchronized List<String> issuedPersons() {
        return List.copyOf(issued.keySet());
    }

    private void load() {
        JsonNode node = DemoFiles.read(recordFile);
        if (node == null) {
            return;
        }
        boolean sameIssuer = issuerKeypair.pk().affineU().toString(16).equals(DemoFiles.text(node, "issuerPkU", recordFile))
                && issuerKeypair.pk().affineV().toString(16).equals(DemoFiles.text(node, "issuerPkV", recordFile));
        if (!sameIssuer) {
            throw new IllegalStateException(recordFile + " was written under another issuer key; refusing to start."
                    + " Reset keys and state together with ./demo.sh airdrop --clean-cache.");
        }
        JsonNode persons = node.get("persons");
        if (persons == null || !persons.isArray()) {
            throw new IllegalStateException(recordFile + " is corrupt: missing persons");
        }
        for (JsonNode p : persons) {
            issued.put(DemoFiles.text(p, "person", recordFile), DemoFiles.text(p, "issuedAt", recordFile));
        }
    }

    private void persist() {
        var out = DemoFiles.object();
        out.put("issuerPkU", issuerKeypair.pk().affineU().toString(16));
        out.put("issuerPkV", issuerKeypair.pk().affineV().toString(16));
        var persons = out.putArray("persons");
        issued.forEach((who, at) -> persons.addObject().put("person", who).put("issuedAt", at));
        DemoFiles.writeAtomic(recordFile, out);
    }

    private static String normalize(String person) {
        if (person == null || person.isBlank()) {
            throw new IllegalArgumentException("person is required");
        }
        return person.trim();
    }

    private static JubjubMessage canonicalMessage(BigInteger fieldElement) {
        if (fieldElement == null) {
            throw new IllegalArgumentException("m is required");
        }
        byte[] raw = fieldElement.toByteArray();
        int sourceOffset = raw.length == JubjubMessage.CANONICAL_BYTES + 1 && raw[0] == 0 ? 1 : 0;
        int length = raw.length - sourceOffset;
        if (fieldElement.signum() < 0 || length > JubjubMessage.CANONICAL_BYTES) {
            throw new IllegalArgumentException("m is not a canonical Jubjub field element");
        }
        byte[] canonical = new byte[JubjubMessage.CANONICAL_BYTES];
        System.arraycopy(raw, sourceOffset, canonical, canonical.length - length, length);
        return JubjubMessage.fromCanonicalFieldBytes(canonical);
    }
}
