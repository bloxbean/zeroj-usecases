package com.bloxbean.cardano.zeroj.usecases.identity.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;

/**
 * KYC credential issuer. Issues Poseidon-signed credentials and manages
 * the approved countries Merkle tree.
 */
@Service
public class IssuerService {

    private static final Logger log = LoggerFactory.getLogger(IssuerService.class);

    // Issuer's secret (in production, this would be securely stored)
    private static final BigInteger ISSUER_SECRET = BigInteger.valueOf(999999);

    private final CredentialService credentialService;

    @Value("${zk.country-tree-depth}")
    private int countryTreeDepth;

    @Value("${credential.min-age}")
    private int minAge;

    // Approved countries: USA(840), GBR(826), DEU(276), FRA(250), JPN(392)
    private final List<Integer> approvedCountries = List.of(840, 826, 276, 250, 392);

    // Country Merkle tree
    private BigInteger countryRoot;
    private BigInteger[][] countryTree;
    private final Map<BigInteger, Integer> countryToIndex = new HashMap<>();

    // Issued credentials
    private final List<UserCredential> users = new ArrayList<>();

    public IssuerService(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @PostConstruct
    public void setup() {
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

    public BigInteger issueCredential(String name, int age, int countryCode) {
        BigInteger ageBig = BigInteger.valueOf(age);
        BigInteger countryBig = BigInteger.valueOf(countryCode);
        BigInteger credentialHash = credentialService.computeCredentialHash(ISSUER_SECRET, ageBig, countryBig);

        users.add(new UserCredential(name, age, countryCode, ISSUER_SECRET, credentialHash));
        return credentialHash;
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
    public BigInteger getIssuerSecret() { return ISSUER_SECRET; }
    public List<UserCredential> getUsers() { return Collections.unmodifiableList(users); }
    public UserCredential getUser(String name) {
        return users.stream().filter(u -> u.name.equalsIgnoreCase(name)).findFirst().orElse(null);
    }
    public boolean isCountryApproved(int countryCode) {
        return approvedCountries.contains(countryCode);
    }

    public record UserCredential(String name, int age, int countryCode,
                                  BigInteger credentialSecret, BigInteger credentialHash) {}
    public record MerkleProof(BigInteger[] siblings, BigInteger[] pathBits) {}
}
