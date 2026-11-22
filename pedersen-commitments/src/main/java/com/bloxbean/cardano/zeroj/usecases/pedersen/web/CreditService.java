package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.CreditGate;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.CreditGate.Profile;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.circuit.CreditProfileProof;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Demo B, the committed credential gate, for the UI. The bureau, Alice (the holder) and Mallory
 * (an impostor) are wallets this server creates. The server keeps Alice's profile and blinding,
 * her opening, on her behalf; on-chain there is only the commitment and the issuance record.
 */
@Service
public class CreditService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final BackendService backend;
    private final Funding funding;

    private CreditGate credit;
    private Account bureau;
    private Account alice;
    private Account mallory;
    private byte[] bureauPolicy;

    private Profile profile;
    private PedersenVectorCommitment commitment;
    private Utxo record;
    private String recordTx;
    private final List<Map<String, Object>> claims = new ArrayList<>();

    public CreditService(BackendService backend, Funding funding) {
        this.backend = backend;
        this.funding = funding;
    }

    synchronized void ensureReady() throws Exception {
        if (credit != null) return;
        var c = new CreditGate();
        bureau = funding.newWallet("credit/bureau", 200);
        alice = funding.newWallet("credit/alice", 200);
        mallory = funding.newWallet("credit/mallory", 200);
        bureauPolicy = HexUtil.decodeHexString(CreditGate.bureauPolicy(bureau).getPolicyId());
        credit = c;
    }

    /** The bureau commits to Alice's profile and records the issuance on-chain. */
    public synchronized Map<String, Object> issue(long income, int score, int birthYear, int country) throws Exception {
        ensureReady();
        if (income < 0 || score < 0 || score > 0xffff || birthYear < 0 || birthYear > 0xffff
                || country < 0 || country > 0xffff) {
            throw new IllegalArgumentException("income must be >= 0; score, birth year and country must fit in 16 bits");
        }
        Profile p = new Profile(income, score, birthYear, country, PedersenCommitment.randomBlinding(RANDOM));
        PedersenVectorCommitment c = p.commitment();
        String tx = DemoErrors.require(CreditGate.issueRecord(backend, bureau, alice.baseAddress(),
                PointsService.pkh(alice), c), "Issuance record");
        DevKit.waitForTx(backend, tx);
        String unitPrefix = HexUtil.encodeHexString(bureauPolicy);
        record = DevKit.utxosOf(backend, alice.baseAddress(), tx).stream()
                .filter(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().startsWith(unitPrefix)))
                .findFirst().orElseThrow(() -> new IllegalStateException("issuance record not found"));
        profile = p;
        commitment = c;
        recordTx = tx;
        claims.clear();
        return Map.of("summary", "Bureau issued Alice's profile and recorded it on-chain", "txHash", tx);
    }

    /**
     * Alice ({@code who = "alice"}) or Mallory ({@code "mallory"}, presenting Alice's commitment and
     * a valid proof as if her opening leaked) claims a badge from the lender's gate.
     */
    public synchronized Map<String, Object> claim(String who, long minIncome, int minScore) throws Exception {
        ensureReady();
        if (profile == null) throw new IllegalStateException("issue a profile first");
        if (minIncome < 0 || minScore < 0 || minScore > 0xffff) {
            throw new IllegalArgumentException("thresholds out of range");
        }
        Account claimant = switch (who) {
            case "alice" -> alice;
            case "mallory" -> mallory;
            default -> throw new IllegalArgumentException("unknown claimant: " + who);
        };
        var proof = provePredicate(minIncome, minScore);
        var gate = credit.gate(bureauPolicy, minIncome, minScore);
        String tx = DemoErrors.require(CreditGate.claim(backend, gate, claimant, commitment, record, proof),
                who.equals("mallory") ? "Mallory's claim with Alice's credential" : "Alice's claim");
        DevKit.waitForTx(backend, tx);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("claimant", who);
        entry.put("minIncome", minIncome);
        entry.put("minScore", minScore);
        entry.put("lenderLearns", "qualifies (income ≥ " + minIncome + ", score ≥ " + minScore + ")");
        entry.put("badgePolicy", Plutus.policyId(gate));
        entry.put("txHash", tx);
        claims.add(0, entry);
        return entry;
    }

    private Groth16ProofBLS381 provePredicate(long minIncome, int minScore) {
        try {
            return credit.prove(profile, minIncome, minScore);
        } catch (RuntimeException e) {
            throw new DemoErrors.NoProof("Alice's committed profile does not meet income ≥ " + minIncome
                    + " and score ≥ " + minScore + ", so no proof exists. The lender learns only that no badge"
                    + " was claimed.", e);
        }
    }

    public synchronized Map<String, Object> state() throws Exception {
        ensureReady();
        Map<String, Object> body = new LinkedHashMap<>();
        var schema = CreditProfileProof.SCHEMA;
        body.put("schema", Map.of("id", schema.id(), "version", schema.version(),
                "digest", PointsService.shortHex(schema.digest()),
                "entries", schema.entries().stream().map(e -> e.label() + "/" + e.width()).toList()));
        body.put("constraints", credit.circuit().numConstraints());
        body.put("holderAddress", alice.baseAddress());
        if (profile != null) {
            body.put("private", Map.of("income", profile.income(), "creditScore", profile.creditScore(),
                    "birthYear", profile.birthYear(), "country", profile.country(),
                    "blinding", PointsService.shortHex(profile.blinding())));
            var point = commitment.point().normalized();
            body.put("onChain", Map.of(
                    "recordTx", recordTx,
                    "recordToken", HexUtil.encodeHexString(CreditGate.recordTokenName(commitment, PointsService.pkh(alice)))
                            .substring(0, 16) + "…",
                    "u", PointsService.shortHex(point.affineU()),
                    "v", PointsService.shortHex(point.affineV()),
                    "holder", HexUtil.encodeHexString(PointsService.pkh(alice)).substring(0, 16) + "…"));
        }
        body.put("claims", List.copyOf(claims));
        return body;
    }
}
