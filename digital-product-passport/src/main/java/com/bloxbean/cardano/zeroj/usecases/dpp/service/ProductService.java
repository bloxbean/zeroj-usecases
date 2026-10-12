package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.vds.mpf.rocksdb.RocksDbNodeStore;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.ProductEntity;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.ProductRepository;
import com.bloxbean.cardano.zeroj.usecases.dpp.mpf.PoseidonCommitmentScheme;
import com.bloxbean.cardano.zeroj.usecases.dpp.mpf.PoseidonHashFunction;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ApprovedSets;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * The manufacturer's product database (H2) and the public passport registry (Poseidon MPF on
 * RocksDB).
 *
 * <p>The registry maps {@code productId → passport outref} and nothing else (ADR-0009 D1, D10).
 * The previous registry stored each product's measurements in the trie, so anyone holding a
 * proof path or a copy of the trie could read them; it now stores only where each passport is.
 * Measurements stay in the manufacturer's database, which no public endpoint returns.
 */
@Service
public class ProductService {

    private static final Logger log = LoggerFactory.getLogger(ProductService.class);
    private static final long DAY = 86_400;
    private static final long T0 = 1_717_000_000L; // 2024-05-29, unix seconds

    @Value("${dpp.registry-path}")
    private String registryPath;

    private RocksDbNodeStore nodeStore;
    private MpfTrie registry;

    private final ProductRepository productRepository;

    public ProductService(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @PostConstruct
    public void init() throws Exception {
        Path dbPath = Path.of(registryPath);
        Files.createDirectories(dbPath);
        nodeStore = new RocksDbNodeStore(dbPath.toString());
        registry = new MpfTrie(nodeStore, PoseidonHashFunction.INSTANCE, null, new PoseidonCommitmentScheme());
        log.info("Passport registry (Poseidon MPF + RocksDB at {})", registryPath);

        if (productRepository.count() == 0) {
            log.info("No products yet: creating the demo products");
            createDemoData();
        }
        // The registry is derived from the database's passport outrefs; rebuild any missing entry.
        for (ProductEntity e : productRepository.findByMintedTrue()) {
            if (!e.isRevoked() && registry.get(key(e.getSerialNumber())) == null) {
                registry.put(key(e.getSerialNumber()), outref(e).getBytes(StandardCharsets.UTF_8));
            }
        }
        log.info("{} products, {} passports", productRepository.count(), productRepository.countByMintedTrue());
    }

    @PreDestroy
    public void shutdown() {
        if (nodeStore != null) try { nodeStore.close(); } catch (Exception e) { log.warn("RocksDB close", e); }
    }

    private void createDemoData() {
        // Battery scenario (per product)
        register("BAT-SN001", "EV Battery Pack Alpha", "BatteryAssembly GmbH", "battery", 7, 45, 276,
                inspections(11, T0, 13, T0 + DAY, 11, T0 + 2 * DAY), 0);
        register("BAT-SN002", "EV Battery Pack Beta", "BatteryAssembly GmbH", "battery", 12, 38, 276,
                inspections(12, T0, 14, T0 + DAY, 15, T0 + 3 * DAY), 0);
        // High carbon: no carbon proof exists, so no passport (negative case)
        register("BAT-SN003", "EV Battery Pack Gamma (High Carbon)", "BatteryAssembly GmbH", "battery", 65, 20, 276,
                inspections(11, T0, 12, T0 + DAY, 13, T0 + 2 * DAY), 0);

        // Textile batch scenario (one passport per batch)
        register("TEX-B2024-001", "Organic Cotton T-Shirt", "EcoTextile EU", "textile", 3, 42, 250, null, 100);
        register("TEX-B2024-002", "Recycled Polyester Jacket", "EcoTextile EU", "textile", 8, 65, 250, null, 200);
        // Non-EU origin and low recycled content: the passport mints (carbon passes) but those two
        // claims cannot be proved off-chain (negative case)
        register("TEX-B2024-003", "Fast Fashion T-Shirt (Non-EU)", "CheapTextiles Ltd", "textile", 15, 5, 156, null, 500);
    }

    static String inspections(long... idTimePairs) {
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < idTimePairs.length; i += 2) parts.add(idTimePairs[i] + ":" + idTimePairs[i + 1]);
        return String.join(",", parts);
    }

    public ProductEntity register(String serial, String name, String manufacturer, String type,
                                  int carbonKg, int recycledPct, int country, String inspections, int units) {
        if (serial.getBytes(StandardCharsets.UTF_8).length > 32) throw new IllegalArgumentException("product id over 32 bytes");
        var entity = new ProductEntity(serial, name, manufacturer, type, carbonKg, recycledPct, country, inspections, units);
        productRepository.save(entity);
        log.info("Registered {}: {}", serial, name);
        return entity;
    }

    // --- Random product generation ---

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String[] BATTERY_NAMES = {"Lithium Ion Pack", "Solid State Cell", "NMC Battery Module", "LFP Power Unit", "High-Voltage Pack"};
    private static final String[] TEXTILE_NAMES = {"Organic Cotton Tee", "Recycled Poly Jacket", "Hemp Blend Shirt", "Bamboo Dress", "Wool Sweater"};
    private static final String[] MFG_NAMES = {"BatteryTech GmbH", "EnergyCell Corp", "GreenPower EU", "EcoTextile SA", "SustainFab Ltd"};
    private static final int[] EU_CODES = {276, 250, 380, 724, 620, 528, 56, 40};

    /** Adds {@code count} random products or batches. */
    public List<String> addRandomProducts(int count, String type) {
        List<String> serials = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            if ("battery".equals(type)) {
                String serial = "BAT-" + System.currentTimeMillis() % 100000 + "-" + (RANDOM.nextInt(9000) + 1000);
                List<Long> ids = ApprovedSets.INSPECTOR_IDS;
                long t = T0 + RANDOM.nextInt(365) * DAY;
                register(serial, BATTERY_NAMES[RANDOM.nextInt(BATTERY_NAMES.length)], MFG_NAMES[RANDOM.nextInt(3)], "battery",
                        RANDOM.nextInt(60) + 1, RANDOM.nextInt(70) + 5, EU_CODES[RANDOM.nextInt(EU_CODES.length)],
                        inspections(ids.get(RANDOM.nextInt(ids.size())), t, ids.get(RANDOM.nextInt(ids.size())), t + DAY,
                                ids.get(RANDOM.nextInt(ids.size())), t + 2 * DAY), 0);
                serials.add(serial);
            } else {
                String batchId = "TEX-" + System.currentTimeMillis() % 100000 + "-" + (RANDOM.nextInt(900) + 100);
                int country = RANDOM.nextBoolean() ? EU_CODES[RANDOM.nextInt(EU_CODES.length)] : 156;
                register(batchId, TEXTILE_NAMES[RANDOM.nextInt(TEXTILE_NAMES.length)], MFG_NAMES[3 + RANDOM.nextInt(2)], "textile",
                        RANDOM.nextInt(20) + 1, RANDOM.nextInt(80) + 5, country, null, (RANDOM.nextInt(10) + 1) * 50);
                serials.add(batchId);
            }
        }
        log.info("Added {} random {} products", count, type);
        return serials;
    }

    // --- Passport registry ---

    /** Records a passport: the registry gets {@code productId → txHash#index}, nothing else. */
    public void recordPassport(String serial, String txHash, int index) {
        ProductEntity e = productRepository.findById(serial).orElseThrow();
        e.setMinted(true);
        e.setRevoked(false);
        e.setPassportTxHash(txHash);
        e.setPassportIndex(index);
        e.setMintedAt(LocalDateTime.now());
        productRepository.save(e);
        registry.put(key(serial), outref(e).getBytes(StandardCharsets.UTF_8));
        log.info("Passport recorded: {} -> {}", serial, outref(e));
    }

    public void recordRevocation(String serial) {
        ProductEntity e = productRepository.findById(serial).orElseThrow();
        e.setRevoked(true);
        productRepository.save(e);
        registry.delete(key(serial));
        log.info("Passport revoked: {}", serial);
    }

    public Optional<String> passportOutref(String serial) {
        byte[] value = registry.get(key(serial));
        return value == null ? Optional.empty() : Optional.of(new String(value, StandardCharsets.UTF_8));
    }

    public String registryRootHex() {
        byte[] root = registry.getRootHash();
        return root != null ? HexFormat.of().formatHex(root) : "empty";
    }

    public byte[] registryRoot() {
        return registry.getRootHash();
    }

    public Optional<byte[]> registryProof(String serial) {
        return registry.getProofWire(key(serial));
    }

    private static byte[] key(String serial) {
        return serial.getBytes(StandardCharsets.UTF_8);
    }

    private static String outref(ProductEntity e) {
        return e.getPassportTxHash() + "#" + e.getPassportIndex();
    }

    // --- Queries ---

    public Optional<ProductEntity> find(String serial) {
        return productRepository.findById(serial);
    }

    public Page<ProductEntity> listProducts(int page, int size, String type) {
        if (type != null && !type.isEmpty()) {
            return productRepository.findByProductType(type, PageRequest.of(page, size));
        }
        return productRepository.findAll(PageRequest.of(page, size));
    }

    public List<ProductEntity> all() { return productRepository.findAll(); }

    public long totalCount() { return productRepository.count(); }

    public long passportCount() { return productRepository.countByMintedTrue(); }
}
