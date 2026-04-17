package com.bloxbean.cardano.zeroj.usecases.dpp.controller;

import com.bloxbean.cardano.zeroj.usecases.dpp.service.ComplianceService;
import com.bloxbean.cardano.zeroj.usecases.dpp.service.OnChainDppService;
import com.bloxbean.cardano.zeroj.usecases.dpp.service.ProductService;
import com.bloxbean.cardano.zeroj.usecases.dpp.service.DppCircuitService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.*;

@RestController
@RequestMapping("/api/dpp")
@CrossOrigin(origins = "*")
public class DppController {

    private static final Logger log = LoggerFactory.getLogger(DppController.class);

    private final ProductService productService;
    private final ComplianceService complianceService;
    private final OnChainDppService onChainService;
    private final DppCircuitService circuitService;

    // Proof cache: serial → first compliant (or any) claim result
    private final java.util.concurrent.ConcurrentHashMap<String, ComplianceService.ClaimResult> proofCache = new java.util.concurrent.ConcurrentHashMap<>();

    public DppController(ProductService productService, ComplianceService complianceService,
                          OnChainDppService onChainService, DppCircuitService circuitService) {
        this.productService = productService;
        this.complianceService = complianceService;
        this.onChainService = onChainService;
        this.circuitService = circuitService;
    }

    @GetMapping("/status")
    public ResponseEntity<?> status() {
        var products = productService.getProducts().values().stream()
                .map(p -> {
                    var m = new HashMap<String, Object>();
                    m.put("serial", p.serialNumber()); m.put("name", p.name());
                    m.put("manufacturer", p.manufacturer()); m.put("claims", p.claims());
                    m.put("minted", productService.isMinted(p.serialNumber()));
                    m.put("mintTx", productService.getMintTxHash(p.serialNumber()));
                    return m;
                }).toList();
        var batches = productService.getBatches().values().stream()
                .map(b -> {
                    var m = new HashMap<String, Object>();
                    m.put("batchId", b.batchId()); m.put("name", b.name());
                    m.put("brand", b.brand()); m.put("units", b.unitCount());
                    m.put("claims", b.claims());
                    m.put("minted", productService.isMinted(b.batchId()));
                    m.put("mintTx", productService.getMintTxHash(b.batchId()));
                    return m;
                }).toList();

        return ResponseEntity.ok(Map.of(
                "products", products,
                "batches", batches,
                "mpfRoot", productService.getMpfRootHex(),
                "mintedMpfRoot", productService.getMintedMpfRootHex(),
                "mintedCount", productService.getMintedCount(),
                "thresholds", Map.of(
                        "carbon_kg", complianceService.getCarbonThreshold(),
                        "recycled_pct", complianceService.getRecycledThreshold()),
                "productCount", productService.getProducts().size(),
                "batchCount", productService.getBatches().size(),
                "totalDbCount", productService.getTotalProductCount()));
    }

    /** Paginated product list. GET /api/dpp/products?page=0&size=20&type=battery */
    @GetMapping("/products")
    public ResponseEntity<?> listProducts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String type) {
        var result = productService.listProducts(page, size, type);
        return ResponseEntity.ok(Map.of(
                "products", result.getContent(),
                "page", page,
                "size", size,
                "totalPages", result.getTotalPages(),
                "totalElements", result.getTotalElements()));
    }

    /** Add N random products. POST { "count": 5, "type": "battery" or "textile" } */
    @PostMapping("/products/add")
    public ResponseEntity<?> addProducts(@RequestBody Map<String, Object> request) {
        try {
            int count = ((Number) request.getOrDefault("count", 5)).intValue();
            String type = (String) request.getOrDefault("type", "battery");
            var serials = productService.addRandomProducts(count, type);
            return ResponseEntity.ok(Map.of(
                    "added", serials.size(), "type", type, "ids", serials,
                    "mpfRoot", productService.getMpfRootHex(),
                    "totalProducts", productService.getProducts().size(),
                    "totalBatches", productService.getBatches().size()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /** Verify a product's compliance — generates ZK proofs. */
    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> request) {
        try {
            String id = request.get("id");
            String type = request.getOrDefault("type", "product");

            Map<String, Integer> claims;
            String name;
            if ("batch".equals(type) || "textile".equals(type)) {
                var batch = productService.getBatch(id);
                if (batch == null) return ResponseEntity.badRequest().body(Map.of("error", "Unknown batch: " + id));
                claims = batch.claims(); name = batch.name();
            } else {
                var product = productService.getProduct(id);
                if (product == null) return ResponseEntity.badRequest().body(Map.of("error", "Unknown product: " + id));
                claims = product.claims(); name = product.name();
            }

            long start = System.currentTimeMillis();
            var results = complianceService.proveAllClaims(id, claims);
            long totalMs = System.currentTimeMillis() - start;
            boolean allCompliant = results.stream().allMatch(ComplianceService.ClaimResult::compliant);

            // Cache proof for this product (compliant or not — forceOnChain needs it)
            results.stream().findFirst().ifPresent(r -> proofCache.put(id, r));

            var claimResults = results.stream().map(r -> Map.of(
                    "claim", r.claimType(), "compliant", r.compliant(),
                    "provingTimeMs", r.provingTimeMs(), "details", r.details()
            )).toList();

            return ResponseEntity.ok(Map.of(
                    "id", id, "type", type, "name", name,
                    "allCompliant", allCompliant, "totalProvingTimeMs", totalMs,
                    "claims", claimResults));
        } catch (Exception e) {
            log.error("Verification failed", e);
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Mint a DPP NFT for a product (manufacturer mints).
     * Requires prior /verify call to generate the ZK proof.
     * POST { "id": "BAT-SN001" }
     */
    @PostMapping("/mint")
    public ResponseEntity<?> mint(@RequestBody Map<String, Object> request) {
        try {
            String id = (String) request.get("id");
            boolean forceOnChain = Boolean.TRUE.equals(request.get("forceOnChain"));

            // Check if already minted
            if (productService.isMinted(id)) {
                return ResponseEntity.status(409).body(Map.of(
                        "error", "Already minted", "id", id,
                        "existingTx", productService.getMintTxHash(id)));
            }

            var cachedProof = proofCache.get(id);
            if (cachedProof == null) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Call /verify for " + id + " first to generate compliance proof"));
            }

            // Off-chain check (skip if forceOnChain — let the on-chain validator decide)
            if (!cachedProof.compliant() && !forceOnChain) {
                return ResponseEntity.status(403).body(Map.of(
                        "error", "Product is NOT COMPLIANT — cannot mint DPP NFT (enable 'Skip off-chain check' to try on-chain)",
                        "id", id, "claim", cachedProof.claimType()));
            }

            // On-chain Groth16 verification: proof + public inputs submitted to Cardano
            BigInteger prodId = new BigInteger(1, id.getBytes());
            Number measurement = (Number) cachedProof.details().get("measurement");
            BigInteger threshold = BigInteger.valueOf(
                    cachedProof.claimType().equals("carbon")
                            ? complianceService.getCarbonThreshold()
                            : complianceService.getRecycledThreshold());
            BigInteger auditorHash = measurement != null
                    ? circuitService.computeAuditorHash(BigInteger.valueOf(777777), prodId,
                            BigInteger.valueOf(measurement.intValue()))
                    : BigInteger.ZERO;

            String txHash = onChainService.mintDppNft(id, cachedProof.proof(),
                    prodId, threshold, auditorHash, cachedProof.compliant());

            // Mark as minted in registry
            productService.markAsMinted(id, txHash);

            return ResponseEntity.ok(Map.of(
                    "id", id, "txHash", txHash,
                    "policyId", onChainService.getPolicyId(),
                    "claim", cachedProof.claimType(),
                    "message", "DPP NFT minted! Groth16 proof verified ON-CHAIN."));
        } catch (Exception e) {
            log.error("Mint failed", e);
            boolean onChainRejection = e.getMessage() != null &&
                    (e.getMessage().contains("script") || e.getMessage().contains("evaluating"));
            return ResponseEntity.status(onChainRejection ? 403 : 400).body(Map.of(
                    "error", e.getMessage(), "onChainRejection", onChainRejection));
        }
    }

    /** Anchor the minted-registry MPF root on-chain. */
    @PostMapping("/anchor")
    public ResponseEntity<?> anchor() {
        try {
            byte[] root = productService.getMintedMpfRoot();
            if (root == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "No minted products yet"));
            }
            String txHash = onChainService.anchorRoot(root, productService.getMintedCount());
            return ResponseEntity.ok(Map.of(
                    "txHash", txHash,
                    "mintedMpfRoot", productService.getMintedMpfRootHex(),
                    "mintedCount", productService.getMintedCount()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /** Registry info — MPF roots, minting statistics. */
    @GetMapping("/registry")
    public ResponseEntity<?> registry() {
        return ResponseEntity.ok(Map.of(
                "productMpfRoot", productService.getMpfRootHex(),
                "mintedMpfRoot", productService.getMintedMpfRootHex(),
                "productCount", productService.getProducts().size(),
                "batchCount", productService.getBatches().size(),
                "mintedCount", productService.getMintedCount()));
    }
}
