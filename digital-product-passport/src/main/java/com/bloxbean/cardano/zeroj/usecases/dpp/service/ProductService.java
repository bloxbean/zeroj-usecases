package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.vds.mpf.rocksdb.RocksDbNodeStore;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.ProductEntity;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.ProductRepository;
import com.bloxbean.cardano.zeroj.usecases.dpp.mpf.PoseidonCommitmentScheme;
import com.bloxbean.cardano.zeroj.usecases.dpp.mpf.PoseidonCompute;
import com.bloxbean.cardano.zeroj.usecases.dpp.mpf.PoseidonHashFunction;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Product registry backed by Poseidon MPF + RocksDB.
 * <p>
 * All products and batches are stored in a single persistent trie.
 * The root hash commits to the entire product database and is
 * anchored on-chain periodically.
 */
@Service
public class ProductService {

    private static final Logger log = LoggerFactory.getLogger(ProductService.class);

    @Value("${dpp.rocksdb-path}")
    private String rocksdbPath;

    private RocksDbNodeStore nodeStore;
    private MpfTrie trie;  // product registry
    private RocksDbNodeStore mintedNodeStore;
    private MpfTrie mintedTrie;  // minted products registry (tracks duplicates)
    private final Map<String, ProductRecord> products = new ConcurrentHashMap<>();
    private final Map<String, BatchRecord> batches = new ConcurrentHashMap<>();
    private final Map<String, String> mintedProducts = new ConcurrentHashMap<>(); // serial → txHash

    // Country and inspector Merkle trees (small, in-memory Poseidon trees)
    private BigInteger euCountryRoot;
    private BigInteger[][] euCountryTree;
    private final Map<BigInteger, Integer> countryToIndex = new HashMap<>();

    private BigInteger inspectorRoot;
    private BigInteger[][] inspectorTree;
    private final Map<BigInteger, Integer> inspectorToIndex = new HashMap<>();

    private final DppCircuitService circuitService;

    // Approved EU countries (ISO 3166-1 numeric)
    private static final List<Integer> EU_COUNTRIES = List.of(
            276, 250, 380, 724, 620, 528, 56, 40, 300, 246,  // DEU,FRA,ITA,ESP,PRT,NLD,BEL,AUT,GRC,FIN
            372, 203, 616, 348, 642, 100, 191, 428, 440, 233  // IRL,CZE,POL,HUN,ROU,BGR,HRV,LVA,LTU,EST
    );

    // Non-conflict mineral source countries
    private static final List<Integer> SAFE_MINERAL_COUNTRIES = List.of(
            36, 124, 152, 76, 710, 170, 604, 32,   // AUS,CAN,CHL,BRA,ZAF,COL,PER,ARG
            360, 608, 156, 356, 764, 392, 410, 840  // IDN,PHL,CHN,IND,THA,JPN,KOR,USA
    );

    // Approved inspectors
    private static final List<BigInteger> INSPECTOR_KEYS = List.of(
            BigInteger.valueOf(90001), BigInteger.valueOf(90002), BigInteger.valueOf(90003),
            BigInteger.valueOf(90004), BigInteger.valueOf(90005)
    );

    private final ProductRepository productRepository;

    public ProductService(DppCircuitService circuitService, ProductRepository productRepository) {
        this.circuitService = circuitService;
        this.productRepository = productRepository;
    }

    @PostConstruct
    public void init() throws Exception {
        // Create RocksDB-backed MPF with Poseidon — product registry
        Path dbPath = Path.of(rocksdbPath);
        Files.createDirectories(dbPath);
        nodeStore = new RocksDbNodeStore(dbPath.toString());
        trie = new MpfTrie(nodeStore, PoseidonHashFunction.INSTANCE, null, new PoseidonCommitmentScheme());

        // Minted products registry — tracks which products have been minted as NFTs
        Path mintedDbPath = Path.of(rocksdbPath + "-minted");
        Files.createDirectories(mintedDbPath);
        mintedNodeStore = new RocksDbNodeStore(mintedDbPath.toString());
        mintedTrie = new MpfTrie(mintedNodeStore, PoseidonHashFunction.INSTANCE, null, new PoseidonCommitmentScheme());
        log.info("MPF tries initialized (Poseidon + RocksDB at {})", rocksdbPath);

        // Build country and inspector Merkle trees
        euCountryRoot = buildCountryTree(EU_COUNTRIES, countryToIndex);
        inspectorRoot = buildInspectorTree(INSPECTOR_KEYS, inspectorToIndex);

        // Load from H2 if data exists, otherwise create demo data
        var existing = productRepository.findAll();
        if (existing.isEmpty()) {
            log.info("No existing data in H2 — creating demo products...");
            createDemoData();
        } else {
            log.info("Loading {} products from H2 database...", existing.size());
            for (var entity : existing) {
                var claimsMap = entityToClaims(entity);
                if ("textile".equals(entity.getProductType())) {
                    batches.put(entity.getSerialNumber(), new BatchRecord(
                            entity.getSerialNumber(), entity.getName(), entity.getManufacturer(),
                            entity.getUnitCount(), claimsMap));
                } else {
                    products.put(entity.getSerialNumber(), new ProductRecord(
                            entity.getSerialNumber(), entity.getName(), entity.getManufacturer(), claimsMap));
                }
                if (entity.isMinted()) {
                    mintedProducts.put(entity.getSerialNumber(), entity.getMintTxHash());
                }
                // Ensure MPF has the data too
                String key = ("textile".equals(entity.getProductType()) ? "batch:" : "product:") + entity.getSerialNumber();
                if (trie.get(key.getBytes(java.nio.charset.StandardCharsets.UTF_8)) == null) {
                    trie.put(key.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                            serializeClaims(entity.getName(), entity.getManufacturer(), claimsMap)
                                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }
            log.info("Loaded {} products, {} batches ({} minted) from H2",
                    products.size(), batches.size(), mintedProducts.size());
        }
    }

    private Map<String, Integer> entityToClaims(ProductEntity entity) {
        var m = new HashMap<String, Integer>();
        if ("textile".equals(entity.getProductType())) {
            m.put("carbon_per_unit_kg", entity.getCarbonKg());
        } else {
            m.put("carbon_kg", entity.getCarbonKg());
        }
        m.put("recycled_pct", entity.getRecycledPct());
        m.put("country", entity.getCountry());
        if (entity.getInspectionCount() > 0) m.put("inspection_count", entity.getInspectionCount());
        return m;
    }

    @PreDestroy
    public void shutdown() {
        if (nodeStore != null) try { nodeStore.close(); } catch (Exception e) { log.warn("RocksDB close", e); }
        if (mintedNodeStore != null) try { mintedNodeStore.close(); } catch (Exception e) { log.warn("RocksDB close", e); }
    }

    private static Map<String, Integer> claims(Object... kvs) {
        var m = new HashMap<String, Integer>();
        for (int i = 0; i < kvs.length; i += 2) m.put((String) kvs[i], (Integer) kvs[i + 1]);
        return m;
    }

    private void createDemoData() {
        // Battery scenario (per-product)
        registerProduct("BAT-SN001", "EV Battery Pack Alpha", "BatteryAssembly GmbH",
                claims("carbon_kg", 7, "recycled_pct", 45, "country", 276, "inspection_count", 3));
        registerProduct("BAT-SN002", "EV Battery Pack Beta", "BatteryAssembly GmbH",
                claims("carbon_kg", 12, "recycled_pct", 38, "country", 276, "inspection_count", 3));
        // Battery with high carbon (negative case)
        registerProduct("BAT-SN003", "EV Battery Pack Gamma (High Carbon)", "BatteryAssembly GmbH",
                claims("carbon_kg", 65, "recycled_pct", 20, "country", 276, "inspection_count", 3));

        // Textile batch scenario
        registerBatch("TEX-B2024-001", "Organic Cotton T-Shirt", "EcoTextile EU", 100,
                claims("carbon_per_unit_kg", 3, "recycled_pct", 42, "country", 250));
        registerBatch("TEX-B2024-002", "Recycled Polyester Jacket", "EcoTextile EU", 200,
                claims("carbon_per_unit_kg", 8, "recycled_pct", 65, "country", 250));
        // Batch from non-EU country (negative case)
        registerBatch("TEX-B2024-003", "Fast Fashion T-Shirt (Non-EU)", "CheapTextiles Ltd", 500,
                claims("carbon_per_unit_kg", 15, "recycled_pct", 5, "country", 156));

        log.info("Demo data created: {} products, {} batches", products.size(), batches.size());
    }

    public void registerProduct(String serialNumber, String name, String manufacturer,
                                 Map<String, Integer> claims) {
        String key = "product:" + serialNumber;
        String value = serializeClaims(name, manufacturer, claims);
        trie.put(key.getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8));
        products.put(serialNumber, new ProductRecord(serialNumber, name, manufacturer, claims));

        // Persist to H2
        var entity = new ProductEntity(serialNumber, name, manufacturer, "battery",
                claims.getOrDefault("carbon_kg", 0), claims.getOrDefault("recycled_pct", 0),
                claims.getOrDefault("country", 0), claims.getOrDefault("inspection_count", 0), 0);
        productRepository.save(entity);
        log.info("Product registered: {} — {}", serialNumber, name);
    }

    public void registerBatch(String batchId, String name, String brand, int unitCount,
                               Map<String, Integer> claims) {
        String key = "batch:" + batchId;
        var allClaims = new HashMap<>(claims);
        allClaims.put("unit_count", unitCount);
        String value = serializeClaims(name, brand, allClaims);
        trie.put(key.getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8));
        batches.put(batchId, new BatchRecord(batchId, name, brand, unitCount, claims));

        // Persist to H2
        var entity = new ProductEntity(batchId, name, brand, "textile",
                claims.getOrDefault("carbon_per_unit_kg", 0), claims.getOrDefault("recycled_pct", 0),
                claims.getOrDefault("country", 0), 0, unitCount);
        productRepository.save(entity);
        log.info("Batch registered: {} — {} ({} units)", batchId, name, unitCount);
    }

    // --- Random product generation ---

    private static final Random RANDOM = new Random();
    private static final String[] BATTERY_NAMES = {"Lithium Ion Pack", "Solid State Cell", "NMC Battery Module", "LFP Power Unit", "High-Voltage Pack"};
    private static final String[] TEXTILE_NAMES = {"Organic Cotton Tee", "Recycled Poly Jacket", "Hemp Blend Shirt", "Bamboo Dress", "Wool Sweater"};
    private static final String[] MFG_NAMES = {"BatteryTech GmbH", "EnergyCell Corp", "GreenPower EU", "EcoTextile SA", "SustainFab Ltd"};
    private static final int[] EU_CODES = {276, 250, 380, 724, 620, 528, 56, 40};

    /**
     * Add N random products of a given type to the MPF registry.
     */
    public List<String> addRandomProducts(int count, String type) {
        List<String> serials = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            if ("battery".equals(type)) {
                String serial = "BAT-" + System.currentTimeMillis() % 100000 + "-" + (RANDOM.nextInt(9000) + 1000);
                int carbon = RANDOM.nextInt(60) + 1; // 1-60 kg
                int recycled = RANDOM.nextInt(70) + 5; // 5-75%
                int country = EU_CODES[RANDOM.nextInt(EU_CODES.length)];
                registerProduct(serial, BATTERY_NAMES[RANDOM.nextInt(BATTERY_NAMES.length)],
                        MFG_NAMES[RANDOM.nextInt(3)],
                        claims("carbon_kg", carbon, "recycled_pct", recycled, "country", country, "inspection_count", 3));
                serials.add(serial);
            } else {
                String batchId = "TEX-" + System.currentTimeMillis() % 100000 + "-" + (RANDOM.nextInt(900) + 100);
                int carbonPerUnit = RANDOM.nextInt(20) + 1; // 1-20 kg
                int recycled = RANDOM.nextInt(80) + 5; // 5-85%
                int country = RANDOM.nextBoolean() ? EU_CODES[RANDOM.nextInt(EU_CODES.length)] : 156;
                int units = (RANDOM.nextInt(10) + 1) * 50; // 50-500
                registerBatch(batchId, TEXTILE_NAMES[RANDOM.nextInt(TEXTILE_NAMES.length)],
                        MFG_NAMES[3 + RANDOM.nextInt(2)], units,
                        claims("carbon_per_unit_kg", carbonPerUnit, "recycled_pct", recycled, "country", country));
                serials.add(batchId);
            }
        }
        log.info("Added {} random {} products to MPF", count, type);
        return serials;
    }

    // --- Minted registry ---

    public void markAsMinted(String serial, String txHash) {
        mintedTrie.put(serial.getBytes(StandardCharsets.UTF_8), txHash.getBytes(StandardCharsets.UTF_8));
        mintedProducts.put(serial, txHash);

        // Persist to H2
        productRepository.findById(serial).ifPresent(entity -> {
            entity.setMinted(true);
            entity.setMintTxHash(txHash);
            entity.setMintedAt(java.time.LocalDateTime.now());
            productRepository.save(entity);
        });
        log.info("Marked as minted: {} → tx={}", serial, txHash.substring(0, 16));
    }

    public boolean isMinted(String serial) {
        return mintedProducts.containsKey(serial)
                || mintedTrie.get(serial.getBytes(StandardCharsets.UTF_8)) != null;
    }

    public String getMintTxHash(String serial) {
        return mintedProducts.get(serial);
    }

    public byte[] getMintedMpfRoot() {
        return mintedTrie.getRootHash();
    }

    public String getMintedMpfRootHex() {
        byte[] root = getMintedMpfRoot();
        return root != null ? java.util.HexFormat.of().formatHex(root) : "empty";
    }

    public int getMintedCount() {
        return mintedProducts.size();
    }

    // --- Paginated queries (H2-backed) ---

    public Page<ProductEntity> listProducts(int page, int size, String type) {
        if (type != null && !type.isEmpty()) {
            return productRepository.findByProductType(type, PageRequest.of(page, size));
        }
        return productRepository.findAll(PageRequest.of(page, size));
    }

    public long getTotalProductCount() { return productRepository.count(); }
    public long getMintedCountFromDb() { return productRepository.countByMintedTrue(); }

    // --- Product registry ---

    public byte[] getMpfRoot() {
        return trie.getRootHash();
    }

    public String getMpfRootHex() {
        byte[] root = getMpfRoot();
        return root != null ? java.util.HexFormat.of().formatHex(root) : "empty";
    }

    public Optional<byte[]> getProof(String key) {
        return trie.getProofWire(key.getBytes(StandardCharsets.UTF_8));
    }

    public Map<String, ProductRecord> getProducts() { return Collections.unmodifiableMap(products); }
    public Map<String, BatchRecord> getBatches() { return Collections.unmodifiableMap(batches); }
    public ProductRecord getProduct(String serial) { return products.get(serial); }
    public BatchRecord getBatch(String batchId) { return batches.get(batchId); }

    // --- Country Merkle tree ---

    public BigInteger getEuCountryRoot() { return euCountryRoot; }

    public MerkleProof getCountryProof(int countryCode) {
        BigInteger country = BigInteger.valueOf(countryCode);
        Integer idx = countryToIndex.get(country);
        if (idx == null) return null;
        int depth = circuitService.getCountryTreeDepth();
        BigInteger[] siblings = new BigInteger[depth];
        BigInteger[] pathBits = new BigInteger[depth];
        int index = idx;
        for (int i = 0; i < depth; i++) {
            int sibIdx = (index % 2 == 0) ? index + 1 : index - 1;
            siblings[i] = euCountryTree[i][sibIdx];
            pathBits[i] = BigInteger.valueOf(index % 2);
            index /= 2;
        }
        return new MerkleProof(siblings, pathBits);
    }

    public boolean isEuCountry(int code) { return EU_COUNTRIES.contains(code); }

    // --- Inspector Merkle tree ---

    public BigInteger getInspectorRoot() { return inspectorRoot; }

    public MerkleProof getInspectorProof(BigInteger inspectorKey) {
        BigInteger hash = PoseidonCompute.poseidon(inspectorKey, BigInteger.ZERO);
        Integer idx = inspectorToIndex.get(hash);
        if (idx == null) return null;
        int depth = circuitService.getInspectorTreeDepth();
        BigInteger[] siblings = new BigInteger[depth];
        BigInteger[] pathBits = new BigInteger[depth];
        int index = idx;
        for (int i = 0; i < depth; i++) {
            int sibIdx = (index % 2 == 0) ? index + 1 : index - 1;
            siblings[i] = inspectorTree[i][sibIdx];
            pathBits[i] = BigInteger.valueOf(index % 2);
            index /= 2;
        }
        return new MerkleProof(siblings, pathBits);
    }

    public List<BigInteger> getInspectorKeys() { return INSPECTOR_KEYS; }

    // --- Internal ---

    private BigInteger buildCountryTree(List<Integer> countries, Map<BigInteger, Integer> indexMap) {
        int depth = circuitService.getCountryTreeDepth();
        int maxLeaves = 1 << depth;
        BigInteger[] leaves = new BigInteger[maxLeaves];
        for (int i = 0; i < maxLeaves; i++) {
            if (i < countries.size()) {
                leaves[i] = BigInteger.valueOf(countries.get(i));
                indexMap.put(leaves[i], i);
            } else {
                leaves[i] = BigInteger.ZERO;
            }
        }
        euCountryTree = buildMerkleTree(leaves, depth);
        return euCountryTree[depth][0];
    }

    private BigInteger buildInspectorTree(List<BigInteger> keys, Map<BigInteger, Integer> indexMap) {
        int depth = circuitService.getInspectorTreeDepth();
        int maxLeaves = 1 << depth;
        BigInteger[] leaves = new BigInteger[maxLeaves];
        for (int i = 0; i < maxLeaves; i++) {
            if (i < keys.size()) {
                leaves[i] = PoseidonCompute.poseidon(keys.get(i), BigInteger.ZERO);
                indexMap.put(leaves[i], i);
            } else {
                leaves[i] = BigInteger.ZERO;
            }
        }
        inspectorTree = buildMerkleTree(leaves, depth);
        return inspectorTree[depth][0];
    }

    private BigInteger[][] buildMerkleTree(BigInteger[] leaves, int depth) {
        var tree = new BigInteger[depth + 1][];
        tree[0] = leaves;
        for (int level = 1; level <= depth; level++) {
            int size = tree[level - 1].length / 2;
            tree[level] = new BigInteger[size];
            for (int i = 0; i < size; i++) {
                tree[level][i] = PoseidonCompute.poseidon(
                        tree[level - 1][2 * i], tree[level - 1][2 * i + 1]);
            }
        }
        return tree;
    }

    private String serializeClaims(String name, String owner, Map<String, Integer> claims) {
        var sb = new StringBuilder();
        sb.append("name=").append(name).append(";owner=").append(owner);
        claims.forEach((k, v) -> sb.append(";").append(k).append("=").append(v));
        return sb.toString();
    }

    // --- Records ---

    public record ProductRecord(String serialNumber, String name, String manufacturer,
                                 Map<String, Integer> claims) {}
    public record BatchRecord(String batchId, String name, String brand, int unitCount,
                               Map<String, Integer> claims) {}
    public record MerkleProof(BigInteger[] siblings, BigInteger[] pathBits) {}
}
