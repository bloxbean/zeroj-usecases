package com.bloxbean.cardano.zeroj.usecases.identity.service;

import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubMessage;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;

/**
 * KYC credential issuer.
 *
 * <p>Holds a Jubjub keypair (sk, pk). Signs each issued credential with
 * EdDSA-Jubjub over {@code Poseidon(age, country)}. Maintains the
 * approved-countries Merkle tree (Poseidon-hashed) for in-circuit membership
 * proofs.
 *
 * <h2>Why EdDSA-Jubjub instead of Poseidon-MAC?</h2>
 * The earlier scheme issued credentials as
 * {@code Poseidon(issuerSecret, Poseidon(age, country))} — a shared-secret
 * MAC. The issuer and every holder shared {@code issuerSecret}, which broke
 * the W3C VC trust model (any holder could impersonate any other; the
 * secret had to be transmitted over a channel external to the credential).
 *
 * <p>Now the issuer holds a Jubjub <i>asymmetric</i> keypair and publishes
 * {@code pk}. Holders receive {@code (age, country, signature)}. The
 * signature is verifiable inside a ZK proof against the public key, with
 * no shared secret. This is the foundation for W3C VC, DID, and Atala PRISM
 * interop.
 *
 * <h2>Issuer key</h2>
 * The key is generated with {@link SecureRandom} on first start and persisted in the demo data
 * directory by {@link IssuerKeyStore} (ADR-0009 D11); a restart loads it. Earlier versions derived
 * it from a seed published in this file, so anyone could sign credentials the deployed validator
 * accepted. If the deployment state exists but the key is missing, unreadable or doesn't match,
 * the demo stops instead of creating a new key.
 */
@Service
public class IssuerService {

    private static final Logger log = LoggerFactory.getLogger(IssuerService.class);

    private final CredentialService credentialService;

    /** The demo data directory: the issuer key and its deployment state (ADR-0009 D11). */
    @Value("${demo.data-dir:./data}")
    private String dataDir;

    @Value("${zk.country-tree-depth}")
    private int countryTreeDepth;

    @Value("${credential.min-age}")
    private int minAge;

    private EdDSAJubjub.Keypair issuerKeypair;

    // Approved countries: USA(840), GBR(826), DEU(276), FRA(250), JPN(392)
    private final List<Integer> approvedCountries = List.of(840, 826, 276, 250, 392);

    // Country Merkle tree
    private BigInteger countryRoot;
    private BigInteger[][] countryTree;
    private final Map<BigInteger, Integer> countryToIndex = new HashMap<>();

    // Issued credentials (in-memory store for demo)
    private final List<UserCredential> users = new ArrayList<>();

    public IssuerService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @PostConstruct
    public void setup() {
        // In production this key would live in a KMS / HSM; the demo keeps it in its data directory.
        issuerKeypair = IssuerKeyStore.loadOrCreate(Path.of(dataDir), "identity-kyc", new SecureRandom());
        log.info("Issuer EdDSA-Jubjub key loaded from {}. Public key (u, v):", Path.of(dataDir).toAbsolutePath());
        log.info("  u = 0x{}", issuerKeypair.pk().affineU().toString(16));
        log.info("  v = 0x{}", issuerKeypair.pk().affineV().toString(16));

        buildCountryTree();
        createTestUsers();
    }

    private void buildCountryTree() {
        int maxLeaves = 1 << countryTreeDepth;
        BigInteger[] leaves = new BigInteger[maxLeaves];
        for (int i = 0; i < maxLeaves; i++) {
            if (i < approvedCountries.size()) {
                leaves[i] = BigInteger.valueOf(approvedCountries.get(i));
                countryToIndex.put(leaves[i], i);
            } else {
                leaves[i] = BigInteger.ZERO;
            }
        }

        countryTree = new BigInteger[countryTreeDepth + 1][];
        countryTree[0] = leaves;
        for (int level = 1; level <= countryTreeDepth; level++) {
            int size = countryTree[level - 1].length / 2;
            countryTree[level] = new BigInteger[size];
            for (int i = 0; i < size; i++) {
                countryTree[level][i] = credentialService.computePoseidon(
                        countryTree[level - 1][2 * i], countryTree[level - 1][2 * i + 1]);
            }
        }
        countryRoot = countryTree[countryTreeDepth][0];
        log.info("Country Merkle tree built: {} approved countries, root={}...",
                approvedCountries.size(), countryRoot.toString(16).substring(0, 8));
    }

    private void createTestUsers() {
        issueCredential("Alice", 25, 840);   // USA — eligible
        issueCredential("Bob", 30, 826);     // GBR — eligible
        issueCredential("Charlie", 16, 840); // USA, underage — NOT eligible
        issueCredential("Diana", 22, 76);    // BRA, not approved — NOT eligible
        issueCredential("Eve", 45, 392);     // JPN — eligible

        log.info("Issued {} test credentials (minAge={}, {} approved countries)",
                users.size(), minAge, approvedCountries.size());
        for (var u : users) {
            boolean countryOk = approvedCountries.contains(u.countryCode);
            boolean ageOk = u.age >= minAge;
            log.info("  {} — age={}, country={} → {} {}",
                    u.name, u.age, u.countryCode,
                    ageOk && countryOk ? "ELIGIBLE" : "NOT ELIGIBLE",
                    !ageOk ? "(underage)" : !countryOk ? "(country not approved)" : "");
        }
    }

    /**
     * Issues a signed credential for {@code (age, country)}. The signature
     * binds the issuer to the claim and lets the holder prove the credential
     * in ZK without revealing it.
     */
    public EdDSAJubjub.Signature issueCredential(String name, int age, int countryCode) {
        BigInteger ageBig = BigInteger.valueOf(age);
        BigInteger countryBig = BigInteger.valueOf(countryCode);
        BigInteger claimsMsg = credentialService.computePoseidon(ageBig, countryBig);
        EdDSAJubjub.Signature sig = EdDSAJubjub.signCompatibilityOffline(
                issuerKeypair, canonicalMessage(claimsMsg));

        users.add(new UserCredential(name, age, countryCode, sig));
        return sig;
    }

    public MerkleProof getCountryProof(int countryCode) {
        BigInteger countryBig = BigInteger.valueOf(countryCode);
        Integer idx = countryToIndex.get(countryBig);
        if (idx == null) return null; // country not in approved list

        BigInteger[] siblings = new BigInteger[countryTreeDepth];
        BigInteger[] pathBits = new BigInteger[countryTreeDepth];
        int index = idx;
        for (int i = 0; i < countryTreeDepth; i++) {
            int siblingIdx = (index % 2 == 0) ? index + 1 : index - 1;
            siblings[i] = countryTree[i][siblingIdx];
            pathBits[i] = BigInteger.valueOf(index % 2);
            index /= 2;
        }
        return new MerkleProof(siblings, pathBits);
    }

    public BigInteger getCountryRoot() { return countryRoot; }
    public int getMinAge() { return minAge; }
    /** Issuer's Jubjub public key — published to verifiers. */
    public JubjubPoint getIssuerPublicKey() { return issuerKeypair.pk(); }
    public List<UserCredential> getUsers() { return Collections.unmodifiableList(users); }
    public UserCredential getUser(String name) {
        return users.stream().filter(u -> u.name.equalsIgnoreCase(name)).findFirst().orElse(null);
    }
    public boolean isCountryApproved(int countryCode) {
        return approvedCountries.contains(countryCode);
    }

    private static JubjubMessage canonicalMessage(BigInteger fieldElement) {
        byte[] raw = fieldElement.toByteArray();
        int sourceOffset = raw.length == JubjubMessage.CANONICAL_BYTES + 1 && raw[0] == 0 ? 1 : 0;
        int length = raw.length - sourceOffset;
        if (fieldElement.signum() < 0 || length > JubjubMessage.CANONICAL_BYTES) {
            throw new IllegalArgumentException("claims message is not a canonical Jubjub field element");
        }
        byte[] canonical = new byte[JubjubMessage.CANONICAL_BYTES];
        System.arraycopy(raw, sourceOffset, canonical, canonical.length - length, length);
        return JubjubMessage.fromCanonicalFieldBytes(canonical);
    }

    /**
     * A holder's credential packet: claims plus the issuer's signature.
     * The holder reveals this only to themselves; in proof generation it
     * stays as secret witness data.
     */
    public record UserCredential(String name, int age, int countryCode,
                                 EdDSAJubjub.Signature signature) {}
    public record MerkleProof(BigInteger[] siblings, BigInteger[] pathBits) {}
}
