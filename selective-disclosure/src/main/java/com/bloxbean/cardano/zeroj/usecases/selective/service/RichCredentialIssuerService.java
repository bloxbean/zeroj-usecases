package com.bloxbean.cardano.zeroj.usecases.selective.service;

import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubCurve;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import com.bloxbean.cardano.zeroj.usecases.selective.circuit.CredentialSchema;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Issues multi-field W3C-VC-style credentials. Each credential carries
 * (dobYear, country, role, salaryBracket, name) — all hidden from
 * verifiers. Holders prove arbitrary predicates over these fields without
 * revealing them.
 */
@Service
public class RichCredentialIssuerService {

    private static final Logger log = LoggerFactory.getLogger(RichCredentialIssuerService.class);

    private static final BigInteger ISSUER_SECRET_SEED = new BigInteger(
            "feedfacecafebeef1234567890abcdef0fedcba9876543210feedface00112233", 16);

    private EdDSAJubjub.Keypair issuerKeypair;
    private final Map<String, RichCredential> credentials = new LinkedHashMap<>();

    /**
     * Approved EU country tree (ISO 3166 numeric codes). Same Merkle layout
     * as identity-kyc — Poseidon-hashed binary tree, depth 4.
     */
    public static final List<Integer> EU_COUNTRIES = List.of(840, 826, 276, 250, 392); // USA, GBR, DEU, FRA, JPN

    public static final int COUNTRY_TREE_DEPTH = 4;

    private BigInteger countryRoot;
    private BigInteger[][] countryTree;
    private final Map<BigInteger, Integer> countryToIndex = new LinkedHashMap<>();

    @PostConstruct
    public void setup() {
        BigInteger sk = ISSUER_SECRET_SEED.mod(JubjubCurve.SUBGROUP_ORDER);
        if (sk.signum() == 0) sk = BigInteger.ONE;
        issuerKeypair = EdDSAJubjub.keypairFromSecret(sk);
        log.info("Rich-credential issuer keypair generated. pk.u = 0x{}",
                issuerKeypair.pk().affineU().toString(16));

        buildCountryTree();
        seedTestUsers();
    }

    private void seedTestUsers() {
        // Field choices showcase how a single credential satisfies different predicates.
        issueCredential("Alice",   1995, 840, CredentialSchema.Roles.ENGINEER, 5);
        issueCredential("Bob",     1990, 276, CredentialSchema.Roles.DOCTOR,   4);
        issueCredential("Charlie", 2010, 826, CredentialSchema.Roles.STUDENT,  0);
        issueCredential("Diana",   1985, 250, CredentialSchema.Roles.LAWYER,   7);
        issueCredential("Eve",     1992, 392, CredentialSchema.Roles.NURSE,    3);
        issueCredential("Frank",   1980, 76,  CredentialSchema.Roles.DOCTOR,   6); // BR (non-EU) doctor
        log.info("Issued {} rich credentials.", credentials.size());
    }

    private void buildCountryTree() {
        int max = 1 << COUNTRY_TREE_DEPTH;
        BigInteger[] leaves = new BigInteger[max];
        for (int i = 0; i < max; i++) {
            if (i < EU_COUNTRIES.size()) {
                leaves[i] = BigInteger.valueOf(EU_COUNTRIES.get(i));
                countryToIndex.put(leaves[i], i);
            } else {
                leaves[i] = BigInteger.ZERO;
            }
        }
        countryTree = new BigInteger[COUNTRY_TREE_DEPTH + 1][];
        countryTree[0] = leaves;
        for (int level = 1; level <= COUNTRY_TREE_DEPTH; level++) {
            int sz = countryTree[level - 1].length / 2;
            countryTree[level] = new BigInteger[sz];
            for (int i = 0; i < sz; i++) {
                countryTree[level][i] = com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash.hash(
                        com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3.INSTANCE,
                        countryTree[level - 1][2 * i], countryTree[level - 1][2 * i + 1]);
            }
        }
        countryRoot = countryTree[COUNTRY_TREE_DEPTH][0];
    }

    public RichCredential issueCredential(String name, int dobYear, int countryCode,
                                          BigInteger roleId, int salaryBracket) {
        BigInteger dob = BigInteger.valueOf(dobYear);
        BigInteger ctry = BigInteger.valueOf(countryCode);
        BigInteger sal = BigInteger.valueOf(salaryBracket);
        BigInteger nameH = CredentialSchema.nameHash(name);
        BigInteger msg = CredentialSchema.claimsMessage(dob, ctry, roleId, sal, nameH);
        EdDSAJubjub.Signature sig = EdDSAJubjub.sign(issuerKeypair.sk(), msg);
        var cred = new RichCredential(name, dobYear, countryCode, roleId, salaryBracket, nameH, sig);
        credentials.put(name, cred);
        return cred;
    }

    public CountryProof getCountryProof(int code) {
        Integer idx = countryToIndex.get(BigInteger.valueOf(code));
        if (idx == null) return null;
        BigInteger[] siblings = new BigInteger[COUNTRY_TREE_DEPTH];
        BigInteger[] pathBits = new BigInteger[COUNTRY_TREE_DEPTH];
        int i = idx;
        for (int level = 0; level < COUNTRY_TREE_DEPTH; level++) {
            int sib = (i % 2 == 0) ? i + 1 : i - 1;
            siblings[level] = countryTree[level][sib];
            pathBits[level] = BigInteger.valueOf(i % 2);
            i /= 2;
        }
        return new CountryProof(siblings, pathBits);
    }

    public JubjubPoint issuerPk() { return issuerKeypair.pk(); }
    public BigInteger countryRoot() { return countryRoot; }
    public RichCredential get(String name) { return credentials.get(name); }
    public List<RichCredential> list() { return List.copyOf(credentials.values()); }

    public record RichCredential(String name, int dobYear, int countryCode,
                                 BigInteger roleId, int salaryBracket,
                                 BigInteger nameHash, EdDSAJubjub.Signature signature) {}

    public record CountryProof(BigInteger[] siblings, BigInteger[] pathBits) {}
}
