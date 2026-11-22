package com.bloxbean.cardano.zeroj.usecases.dpp.controller;

import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.ProductEntity;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ApprovedSets;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.Claim;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ClaimOpening;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportDatum;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportReader;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.RoleKeys;
import com.bloxbean.cardano.zeroj.usecases.dpp.service.AuditorService;
import com.bloxbean.cardano.zeroj.usecases.dpp.service.ComplianceService;
import com.bloxbean.cardano.zeroj.usecases.dpp.service.DppCircuitService;
import com.bloxbean.cardano.zeroj.usecases.dpp.service.OnChainDppService;
import com.bloxbean.cardano.zeroj.usecases.dpp.service.ProductService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The demo's HTTP API. It is the operator's view of a custodial demo (ADR-0009 D10): this server
 * holds the manufacturer's and the auditor's keys. The public endpoints ({@code /status},
 * {@code /products}, {@code /passport/{id}}) return no measurements; the manufacturer's own values
 * appear only under {@code /manufacturer/{id}}, the "manufacturer (private)" panel.
 */
@RestController
@RequestMapping("/api/dpp")
public class DppController {

    private static final Logger log = LoggerFactory.getLogger(DppController.class);
    /** The threshold a cheating manufacturer picks for itself in the "skip off-chain check" demonstration. */
    private static final long CHOSEN_THRESHOLD = 65_535;

    private final ProductService productService;
    private final AuditorService auditorService;
    private final ComplianceService complianceService;
    private final OnChainDppService onChainService;
    private final DppCircuitService circuitService;
    private final RoleKeys roleKeys;

    public DppController(ProductService productService, AuditorService auditorService,
                         ComplianceService complianceService, OnChainDppService onChainService,
                         DppCircuitService circuitService, RoleKeys roleKeys) {
        this.productService = productService;
        this.auditorService = auditorService;
        this.complianceService = complianceService;
        this.onChainService = onChainService;
        this.circuitService = circuitService;
        this.roleKeys = roleKeys;
    }

    // ------------------------------------------------------------------ public views (no values)

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        List<Map<String, Object>> products = new ArrayList<>();
        List<Map<String, Object>> batches = new ArrayList<>();
        for (ProductEntity p : productService.all()) {
            ("textile".equals(p.getProductType()) ? batches : products).add(publicView(p));
        }
        var script = onChainService.script();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("products", products);
        body.put("batches", batches);
        body.put("registryRoot", productService.registryRootHex());
        body.put("passportCount", productService.passportCount());
        body.put("totalDbCount", productService.totalCount());
        body.put("thresholds", Map.of("carbon_kg", complianceService.carbonThreshold(),
                "recycled_pct", complianceService.recycledThreshold()));
        body.put("approvedSets", Map.of(
                "euCountryRoot", ApprovedSets.EU_COUNTRIES.root().toString(),
                "inspectorRoot", ApprovedSets.INSPECTORS.root().toString()));
        body.put("policyId", script.policyId());
        body.put("passportAddress", script.address());
        body.put("gatedClaim", script.gated().label());
        body.put("manufacturerPkh", HexUtil.encodeHexString(script.manufacturerPkh()));
        body.put("auditorPkh", HexUtil.encodeHexString(script.auditorPkh()));
        body.put("custody", "operator view: this demo server holds the manufacturer's and the auditor's keys");
        return ResponseEntity.ok(body);
    }

    /** Paginated product list, without measurements. GET /api/dpp/products?page=0&size=20&type=battery */
    @GetMapping("/products")
    public ResponseEntity<?> listProducts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String type) {
        var result = productService.listProducts(page, size, type);
        return ResponseEntity.ok(Map.of(
                "products", result.getContent().stream().map(this::publicView).toList(),
                "page", page,
                "size", size,
                "totalPages", result.getTotalPages(),
                "totalElements", result.getTotalElements()));
    }

    private Map<String, Object> publicView(ProductEntity p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("serialNumber", p.getSerialNumber());
        m.put("name", p.getName());
        m.put("manufacturer", p.getManufacturer());
        m.put("productType", p.getProductType());
        m.put("unitCount", p.getUnitCount());
        m.put("minted", p.isMinted() && !p.isRevoked());
        m.put("revoked", p.isRevoked());
        m.put("passport", productService.passportOutref(p.getSerialNumber()).orElse(null));
        return m;
    }

    /**
     * A reader's check of a passport, from chain data and the reader's own configuration: the
     * passport token at the passport address, the policy's mint history (more than one passport
     * is refused), and each off-chain claim proof against the datum's commitment, with σ from the
     * reader's schema registry.
     */
    @GetMapping("/passport/{id}")
    public ResponseEntity<?> passport(@PathVariable String id) {
        byte[] productId = id.getBytes(StandardCharsets.UTF_8);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", id);
        body.put("policyId", onChainService.script().policyId());
        PassportReader.Status status;
        try {
            status = PassportReader.status(onChainService.mintHistory(productId));
        } catch (RuntimeException e) {
            body.put("accepted", false);
            body.put("reason", "mint history unavailable or incomplete: " + e.getMessage());
            return ResponseEntity.ok(body);
        }
        body.put("status", status.name());
        if (status != PassportReader.Status.ACTIVE) {
            body.put("accepted", false);
            body.put("reason", switch (status) {
                case NONE -> "no passport was ever minted for this product";
                case REVOKED -> "the auditor revoked this passport";
                case DUPLICATE -> "more than one passport was minted for this product: refused";
                default -> "";
            });
            return ResponseEntity.ok(body);
        }
        try {
            Optional<Utxo> utxo = onChainService.findPassport(productId);
            if (utxo.isEmpty()) {
                body.put("accepted", false);
                body.put("reason", "the passport token is not at the passport address");
                return ResponseEntity.ok(body);
            }
            PassportDatum datum = OnChainDppService.datumOf(utxo.get());
            body.put("passport", utxo.get().getTxHash() + "#" + utxo.get().getOutputIndex());
            var registry = PassportReader.SchemaRegistry.demo();
            List<Map<String, Object>> claims = new ArrayList<>();
            for (Claim claim : Claim.values()) {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("claim", claim.label());
                c.put("statement", statement(claim));
                c.put("attested", datum.entry(claim.id()).isPresent());
                if (claim == onChainService.script().gated()) {
                    c.put("verdict", "VERIFIED_ON_CHAIN");
                    c.put("note", "proved in the mint transaction; the policy refuses a passport without it");
                } else {
                    ComplianceService.ClaimProof published = complianceService.proof(id, claim);
                    c.put("verdict", published == null
                            ? (datum.entry(claim.id()).isPresent() ? "NO_PROOF_PUBLISHED" : "NOT_ATTESTED")
                            : PassportReader.verifyClaim(circuitService.circuits(), registry, datum, claim,
                                    complianceService.param(claim), published.proof()).name());
                }
                claims.add(c);
            }
            body.put("accepted", true);
            body.put("claims", claims);
            return ResponseEntity.ok(body);
        } catch (Exception e) {
            body.put("accepted", false);
            body.put("reason", e.getMessage());
            return ResponseEntity.ok(body);
        }
    }

    private String statement(Claim claim) {
        return switch (claim) {
            case CARBON -> "carbon_kg <= " + complianceService.carbonThreshold();
            case RECYCLED -> "recycled_pct >= " + complianceService.recycledThreshold();
            case ORIGIN -> "country in the EU set";
            case INSPECTIONS -> "3 approved inspections in time order";
        };
    }

    // ------------------------------------------------------------------ the manufacturer's private panel

    /** The manufacturer's own values for a product: the "manufacturer (private)" panel. */
    @GetMapping("/manufacturer/{id}")
    public ResponseEntity<?> manufacturerView(@PathVariable String id) {
        var product = productService.find(id);
        if (product.isEmpty()) return ResponseEntity.badRequest().body(Map.of("error", "Unknown product: " + id));
        ProductEntity p = product.get();
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("carbon_kg", p.getCarbonKg());
        values.put("recycled_pct", p.getRecycledPct());
        values.put("country", p.getCountry());
        values.put("inspections", p.getInspections());
        values.put("units", p.getUnitCount());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("view", "manufacturer (private)");
        body.put("id", id);
        body.put("values", values);
        body.put("attested", !auditorService.openingsOf(id).isEmpty());
        return ResponseEntity.ok(body);
    }

    // ------------------------------------------------------------------ actions

    /** Add N random products. POST { "count": 5, "type": "battery" or "textile" } */
    @PostMapping("/products/add")
    public ResponseEntity<?> addProducts(@RequestBody Map<String, Object> request) {
        try {
            int count = Math.min(100, ((Number) request.getOrDefault("count", 5)).intValue());
            String type = (String) request.getOrDefault("type", "battery");
            var serials = productService.addRandomProducts(count, type);
            return ResponseEntity.ok(Map.of("added", serials.size(), "type", type, "ids", serials,
                    "totalProducts", productService.totalCount()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    /**
     * The auditor attests the product (once), then the manufacturer proves every claim from the
     * openings. POST { "id": "BAT-SN001" }
     */
    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> request) {
        try {
            String id = request.get("id");
            var product = productService.find(id);
            if (product.isEmpty()) return ResponseEntity.badRequest().body(Map.of("error", "Unknown product: " + id));
            List<ClaimOpening> openings = auditorService.attest(product.get());
            long start = System.currentTimeMillis();
            var results = complianceService.proveAll(id, openings);
            long totalMs = System.currentTimeMillis() - start;
            boolean allProved = results.stream().allMatch(ComplianceService.ClaimResult::proved);
            var claimResults = results.stream().map(r -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("claim", r.claim().label());
                m.put("compliant", r.proved());
                m.put("statement", statement(r.claim()));
                m.put("provingTimeMs", r.provingTimeMs());
                m.put("gatedOnChain", r.claim() == onChainService.script().gated());
                if (r.error() != null) m.put("detail", r.error());
                return m;
            }).toList();
            return ResponseEntity.ok(Map.of("id", id, "name", product.get().getName(),
                    "allCompliant", allProved, "totalProvingTimeMs", totalMs, "claims", claimResults));
        } catch (Exception e) {
            log.error("Verification failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    /**
     * Mints a product's passport: one transaction the manufacturer builds and the auditor
     * co-signs. Requires a prior /verify. With {@code forceOnChain} and no carbon proof, submits
     * a proof against a threshold the manufacturer chose itself, which the policy refuses.
     * POST { "id": "BAT-SN001", "forceOnChain": false }
     */
    @PostMapping("/mint")
    public ResponseEntity<?> mint(@RequestBody Map<String, Object> request) {
        try {
            String id = (String) request.get("id");
            boolean forceOnChain = Boolean.TRUE.equals(request.get("forceOnChain"));
            if (productService.find(id).isEmpty()) return ResponseEntity.badRequest().body(Map.of("error", "Unknown product: " + id));
            if (productService.passportOutref(id).isPresent()) {
                return ResponseEntity.status(409).body(Map.of("error", "Already minted", "id", id,
                        "existingPassport", productService.passportOutref(id).get()));
            }
            List<ClaimOpening> openings = auditorService.openingsOf(id);
            if (openings.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Call /verify for " + id + " first"));
            }
            Claim gated = onChainService.script().gated();
            var proved = complianceService.proof(id, gated);
            Groth16ProofBLS381 proof;
            if (proved != null) {
                proof = proved.proof();
            } else if (forceOnChain) {
                ClaimOpening carbon = openings.stream().filter(o -> o.claim() == gated).findFirst().orElseThrow();
                proof = complianceService.proveCarbonAgainst(carbon, CHOSEN_THRESHOLD);
            } else {
                return ResponseEntity.status(403).body(Map.of("id", id, "claim", gated.label(),
                        "error", "The " + gated.label() + " claim cannot be proved, so no passport can be minted"
                                + " (enable 'Skip off-chain check' to see the policy refuse a proof against a threshold the manufacturer chose)"));
            }
            PassportDatum datum = PassportDatum.of(id.getBytes(StandardCharsets.UTF_8),
                    RoleKeys.pkh(roleKeys.manufacturer()), openings);
            var signer = auditorService.coSigner(id, onChainService.script());
            var issued = onChainService.issue(datum, proof, signer);
            auditorService.confirmed(id, issued.txHash());
            productService.recordPassport(id, issued.txHash(), issued.outputIndex());
            Map<String, Object> body = new HashMap<>();
            body.put("id", id);
            body.put("txHash", issued.txHash());
            body.put("passport", issued.txHash() + "#" + issued.outputIndex());
            body.put("policyId", onChainService.script().policyId());
            body.put("claims", openings.stream().map(o -> o.claim().label()).toList());
            body.put("message", "Passport minted: the manufacturer built it, the auditor co-signed it, and the policy verified the carbon proof on-chain.");
            return ResponseEntity.ok(body);
        } catch (Exception e) {
            log.error("Mint failed", e);
            boolean onChainRejection = isOnChainRejection(e.getMessage());
            boolean refused = e.getMessage() != null && e.getMessage().contains("auditor");
            return ResponseEntity.status(onChainRejection || refused ? 403 : 400).body(errorBody(e, onChainRejection));
        }
    }

    /** The auditor revokes a passport: spends it and burns its token. POST { "id": "BAT-SN001" } */
    @PostMapping("/revoke")
    public ResponseEntity<?> revoke(@RequestBody Map<String, String> request) {
        try {
            String id = request.get("id");
            if (productService.passportOutref(id).isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "No passport for " + id));
            }
            String txHash = onChainService.revoke(id.getBytes(StandardCharsets.UTF_8));
            productService.recordRevocation(id);
            return ResponseEntity.ok(Map.of("id", id, "txHash", txHash,
                    "message", "Passport revoked by the auditor: token burned."));
        } catch (Exception e) {
            log.error("Revoke failed", e);
            return ResponseEntity.badRequest().body(errorBody(e, isOnChainRejection(e.getMessage())));
        }
    }

    /** Anchor the passport registry root on-chain. */
    @PostMapping("/anchor")
    public ResponseEntity<?> anchor() {
        try {
            byte[] root = productService.registryRoot();
            if (root == null) return ResponseEntity.badRequest().body(Map.of("error", "No passports yet"));
            String txHash = onChainService.anchorRoot(root, productService.passportCount());
            return ResponseEntity.ok(Map.of("txHash", txHash, "registryRoot", productService.registryRootHex(),
                    "passportCount", productService.passportCount()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
        }
    }

    /** Registry info: the root of productId → passport outref, and the passport count. */
    @GetMapping("/registry")
    public ResponseEntity<?> registry() {
        return ResponseEntity.ok(Map.of(
                "registryRoot", productService.registryRootHex(),
                "passportCount", productService.passportCount(),
                "productCount", productService.totalCount(),
                "stores", "productId -> passport outref (no measurements)"));
    }

    private static boolean isOnChainRejection(String message) {
        return message != null && (message.contains("script")
                || message.contains("Plutus") || message.contains("evaluating"));
    }

    private static Map<String, Object> errorBody(Throwable throwable, boolean onChainRejection) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", String.valueOf(throwable.getMessage()));
        body.put("onChainRejection", onChainRejection);
        if (onChainRejection) {
            body.put("onChainValidation", Map.of(
                    "title", "On-chain validator rejected this transaction",
                    "summary", "The transaction was built and evaluated locally, but the passport policy returned false before it could be submitted.",
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
