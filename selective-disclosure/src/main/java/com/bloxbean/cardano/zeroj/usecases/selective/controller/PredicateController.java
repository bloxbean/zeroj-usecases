package com.bloxbean.cardano.zeroj.usecases.selective.controller;

import com.bloxbean.cardano.zeroj.usecases.selective.service.OnChainGateService;
import com.bloxbean.cardano.zeroj.usecases.selective.service.PredicateProofService;
import com.bloxbean.cardano.zeroj.usecases.selective.service.RichCredentialIssuerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/predicate")
@CrossOrigin
public class PredicateController {

    private static final Logger log = LoggerFactory.getLogger(PredicateController.class);

    private final RichCredentialIssuerService issuer;
    private final PredicateProofService proofs;
    private final OnChainGateService gates;

    private final Map<String, PredicateProofService.ProofBundle> lastProof = new LinkedHashMap<>();

    public PredicateController(RichCredentialIssuerService issuer,
                               PredicateProofService proofs, OnChainGateService gates) {
        this.issuer = issuer;
        this.proofs = proofs;
        this.gates = gates;
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        var users = issuer.list().stream().map(u -> Map.of(
                "name", u.name(),
                "dobYear", u.dobYear(),
                "country", u.countryCode(),
                "role", roleName(u.roleId()),
                "salaryBracket", u.salaryBracket()
        )).toList();
        return ResponseEntity.ok(Map.of(
                "users", users,
                "issuerPkU", "0x" + issuer.issuerPk().affineU().toString(16).substring(0, 16) + "...",
                "currentYear", proofs.currentYear(),
                "adultGateAddr", gates.getAdultGateAddress(),
                "doctorGateAddr", gates.getDoctorGateAddress(),
                "adultGateUtxos", gates.adultGateUtxos(),
                "doctorGateUtxos", gates.doctorGateUtxos()));
    }

    private static String roleName(BigInteger r) {
        long v = r.longValueExact();
        return switch ((int) v) {
            case 1001 -> "Doctor";
            case 1002 -> "Nurse";
            case 2001 -> "Engineer";
            case 3001 -> "Teacher";
            case 4001 -> "Lawyer";
            case 9001 -> "Student";
            default -> "Other";
        };
    }

    @PostMapping("/lock")
    public ResponseEntity<?> lock(@RequestBody Map<String, Object> req) {
        try {
            String gate = (String) req.get("gate");
            int ada = ((Number) req.getOrDefault("adaAmount", 5)).intValue();
            String tx = gates.lockGate(gate, (long) ada * 1_000_000L);
            return ResponseEntity.ok(Map.of("txHash", tx, "gate", gate, "ada", ada));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/prove-adult")
    public ResponseEntity<?> proveAdult(@RequestBody Map<String, String> req) {
        try {
            String name = req.get("name");
            var cred = issuer.get(name);
            if (cred == null) return ResponseEntity.badRequest().body(Map.of("error", "Unknown: " + name));
            var cp = issuer.getCountryProof(cred.countryCode());
            if (cp == null) {
                return ResponseEntity.ok(Map.of("name", name, "eligible", false,
                        "reason", "Country " + cred.countryCode() + " is not in the approved EU set"));
            }
            log.info("Proving adult-resident for {}...", name);
            long t0 = System.currentTimeMillis();
            var bundle = proofs.proveAdultResident(issuer.issuerPk(), cred.signature(), cred,
                    issuer.countryRoot(), cp.siblings(), cp.pathBits());
            long ms = System.currentTimeMillis() - t0;
            lastProof.put("adult:" + name, bundle);
            return ResponseEntity.ok(Map.of(
                    "name", name, "predicate", "adult-resident",
                    "eligible", bundle.eligible(), "provingTimeMs", ms));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/prove-doctor")
    public ResponseEntity<?> proveDoctor(@RequestBody Map<String, String> req) {
        try {
            String name = req.get("name");
            var cred = issuer.get(name);
            if (cred == null) return ResponseEntity.badRequest().body(Map.of("error", "Unknown: " + name));
            log.info("Proving senior-doctor for {}...", name);
            long t0 = System.currentTimeMillis();
            var bundle = proofs.proveSeniorDoctor(issuer.issuerPk(), cred.signature(), cred);
            long ms = System.currentTimeMillis() - t0;
            lastProof.put("doctor:" + name, bundle);
            return ResponseEntity.ok(Map.of(
                    "name", name, "predicate", "senior-doctor",
                    "eligible", bundle.eligible(), "provingTimeMs", ms));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/unlock-adult")
    public ResponseEntity<?> unlockAdult(@RequestBody Map<String, String> req) {
        return doUnlock("adult", req);
    }

    @PostMapping("/unlock-doctor")
    public ResponseEntity<?> unlockDoctor(@RequestBody Map<String, String> req) {
        return doUnlock("doctor", req);
    }

    private ResponseEntity<?> doUnlock(String predicate, Map<String, String> req) {
        try {
            String name = req.get("name");
            var bundle = lastProof.get(predicate + ":" + name);
            if (bundle == null) {
                return ResponseEntity.badRequest().body(Map.of("error",
                        "No proof generated for " + name + " on " + predicate + ". Call prove-" + predicate + " first."));
            }
            BigInteger cy = BigInteger.valueOf(proofs.currentYear());
            String tx;
            if ("adult".equals(predicate)) {
                tx = gates.unlockAdult(bundle.proof(),
                        issuer.issuerPk().affineU(), issuer.issuerPk().affineV(),
                        cy, issuer.countryRoot(), bundle.eligible());
            } else {
                tx = gates.unlockDoctor(bundle.proof(),
                        issuer.issuerPk().affineU(), issuer.issuerPk().affineV(),
                        cy, bundle.eligible());
            }
            return ResponseEntity.ok(Map.of("name", name, "predicate", predicate, "txHash", tx));
        } catch (Exception e) {
            String msg = e.getMessage();
            boolean onChainRejection = isOnChainRejection(msg);
            return ResponseEntity.status(onChainRejection ? 403 : 400)
                    .body(errorBody(e, onChainRejection));
        }
    }

    private static boolean isOnChainRejection(String message) {
        return message != null && (message.contains("script")
                || message.contains("Plutus") || message.contains("evaluating"));
    }

    private static Map<String, Object> errorBody(Throwable throwable, boolean onChainRejection) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", throwable.getMessage());
        body.put("onChainRejection", onChainRejection);
        if (onChainRejection) {
            body.put("onChainValidation", Map.of(
                    "title", "On-chain validator rejected this transaction",
                    "summary", "The transaction was built and evaluated locally, but the Plutus script returned false before it could be submitted.",
                    "detail", scriptEvaluationDetail(throwable)));
        }
        return body;
    }

    private static String scriptEvaluationDetail(Throwable throwable) {
        StringBuilder detail = new StringBuilder();
        Throwable current = throwable;
        while (current != null) {
            String message = current.getMessage();
            if (message != null && !message.isBlank() && detail.indexOf(message) < 0) {
                if (!detail.isEmpty()) {
                    detail.append("\n\nCaused by: ");
                }
                detail.append(message);
            }
            current = current.getCause();
        }
        return detail.isEmpty() ? "Script evaluation failed." : detail.toString();
    }
}
