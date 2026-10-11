package com.bloxbean.cardano.zeroj.usecases.nft.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.TransactionEvaluator;
import com.bloxbean.cardano.client.api.model.EvaluationResult;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.util.HexUtil;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.nft.onchain.NullifierListValidator;
import com.bloxbean.cardano.zeroj.usecases.nft.onchain.ZkProofMintingPolicy;
import org.julclang.clientlib.JulcScriptLoader;
import org.julclang.clientlib.eval.JulcTransactionEvaluator;
import org.julclang.clientlib.eval.SlotConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;

/**
 * On-chain nullifier tracking via sorted linked list on Cardano (ADR-0009 D2).
 * <p>
 * Manages two Julc scripts per event:
 * <ul>
 *   <li>{@link ZkProofMintingPolicy} — Groth16 BLS12-381 proof verification, parameterised by
 *       the event's snapshot root and context id</li>
 *   <li>{@link NullifierListValidator} — sorted linked list (MINT + SPEND), parameterised by the
 *       ZK policy and a seed output that the root must consume (one-shot root)</li>
 * </ul>
 * The operator wallet (the DevKit mnemonic, a public devnet role) pays fees and collateral and
 * supplies the seed. It can submit any insert, but the scripts accept only an insert keyed by a
 * nullifier whose proof verifies.
 */
@Service
@ConditionalOnProperty(name = "nullifier.mode", havingValue = "on-chain")
public class OnChainNullifierService implements NullifierTracker {

    private static final Logger log = LoggerFactory.getLogger(OnChainNullifierService.class);

    static final byte[] ROOT_KEY = "NROOT".getBytes();
    static final byte[] PREFIX = "N".getBytes();
    static final BigInteger PREFIX_LEN = BigInteger.ONE;
    private static final BigInteger MIN_MEM_PADDING = BigInteger.valueOf(50_000);
    private static final BigInteger PADDING_DIVISOR = BigInteger.valueOf(4);
    // Node keys are the low 31 bytes of the 32-byte nullifier token name, so that
    // PREFIX (1 byte) + key (31 bytes) fits Cardano's 32-byte asset name limit.
    static final int NULL_KEY_WIDTH = 31;

    private final BackendService backendService;
    private final Account adminAccount;
    private final ProverService proverService;

    @Value("${cardano.yaci.admin-url:}")
    private String yaciAdminUrl;

    /** The event's scripts; null until {@link #deploy}. */
    private volatile Deployment deployment;

    /** One event's scripts, root seed and list address. */
    public record Deployment(BigInteger snapshotRoot, BigInteger contextId,
                             PlutusScript zkScript, String zkPolicyHex,
                             PlutusScript listScript, String listPolicyHex,
                             String registryAddr, byte[] seedRef) {}

    public OnChainNullifierService(BackendService backendService, Account adminAccount,
                                    ProverService proverService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.proverService = proverService;
    }

    /**
     * Derives the event's scripts from its snapshot root and context, and creates the list root
     * once by consuming a seed output of the operator wallet. Idempotent for the same event; a
     * second, different event in one run is refused.
     */
    public synchronized Deployment deploy(BigInteger snapshotRoot, BigInteger contextId) throws Exception {
        if (deployment != null) {
            if (deployment.snapshotRoot().equals(snapshotRoot) && deployment.contextId().equals(contextId)) {
                return deployment;
            }
            throw new IllegalStateException("this run already deployed an event; restart for a new one");
        }
        log.info("Compiling the event's on-chain scripts...");

        PlutusScript zkScript = zkPolicy(snapshotRoot, contextId);
        byte[] zkPolicyHash = zkScript.getScriptHash();
        String zkPolicyHex = HexUtil.encodeHexString(zkPolicyHash);

        // One-shot root: the list script names an operator output that InitList must consume.
        Utxo seed = walletUtxos().getFirst();
        byte[] seedRef = seedRef(seed);
        PlutusScript listScript = listPolicy(zkPolicyHash, seedRef);
        String listPolicyHex = HexUtil.encodeHexString(listScript.getScriptHash());
        String registryAddr = AddressProvider.getEntAddress(listScript, Networks.testnet()).toBech32();

        var d = new Deployment(snapshotRoot, contextId, zkScript, zkPolicyHex,
                listScript, listPolicyHex, registryAddr, seedRef);
        deployRootSentinel(d, seed);
        deployment = d;
        log.info("ZK policy {}, list policy {}, registry {}...", zkPolicyHex, listPolicyHex,
                registryAddr.substring(0, 30));
        return d;
    }

    /** The event's deployment, or null before {@link #deploy}. */
    public Deployment deployment() {
        return deployment;
    }

    // === NullifierTracker interface ===

    @Override
    public boolean isUsed(BigInteger nullifier) {
        var d = deployment;
        if (d == null) return false;
        try {
            byte[] nullKey = nodeKey(nullifier);
            for (var utxo : queryRegistryUtxos(d)) {
                byte[] nodeKey = extractKeyFromUtxo(d, utxo);
                if (nodeKey != null && Arrays.equals(nodeKey, nullKey)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            throw new IllegalStateException("cannot read the nullifier list", e);
        }
    }

    @Override
    public boolean recordNullifier(BigInteger nullifier) {
        throw new UnsupportedOperationException(
                "Use insertNullifier(proof, ...) for on-chain mode");
    }

    @Override
    public int getUsedCount() {
        var d = deployment;
        if (d == null) return 0;
        try {
            // Count = list nodes - 1 (root sentinel)
            int nodes = 0;
            for (var utxo : queryRegistryUtxos(d)) {
                if (findListToken(d, utxo) != null) nodes++;
            }
            return Math.max(0, nodes - 1);
        } catch (Exception e) {
            log.error("Error counting nullifiers", e);
            return 0;
        }
    }

    // === On-chain operations ===

    /**
     * Insert a nullifier on-chain. Builds and submits a transaction that:
     * 1. Spends the predecessor node in the sorted linked list (the only list input)
     * 2. Mints a list NFT for the new node, keyed by the nullifier's low 31 bytes
     * 3. Mints the ZK token {nullifier: 1}, whose policy verifies the Groth16 proof
     *
     * @return the transaction hash
     */
    public String insertNullifier(Groth16ProofBLS381 proof, BigInteger nullifier) throws Exception {
        var d = requireDeployment();
        var anchor = findAnchor(d, queryRegistryUtxos(d), nodeKey(nullifier));
        if (anchor == null) {
            throw new IllegalStateException("Nullifier already exists or no valid insertion point");
        }
        return insertAt(d, proof, nullifier, anchor);
    }

    /**
     * For tests: the node that already points at {@code nullifier}'s key. Inserting the same key
     * after it breaks the sorted order, so the list script must reject it.
     */
    AnchorInfo anchorForDuplicate(BigInteger nullifier) throws Exception {
        var d = requireDeployment();
        byte[] key = nodeKey(nullifier);
        for (var utxo : queryRegistryUtxos(d)) {
            byte[] tokenName = findListToken(d, utxo);
            byte[] next = parseDatum(utxo);
            if (tokenName != null && next != null && Arrays.equals(next, key)) {
                return new AnchorInfo(utxo, tokenName, next);
            }
        }
        throw new IllegalStateException("no node points at this nullifier");
    }

    /** For tests: submits an insert with the given anchor, without the client-side checks. */
    String insertAt(Groth16ProofBLS381 proof, BigInteger nullifier, AnchorInfo anchor) throws Exception {
        return insertAt(requireDeployment(), proof, nullifier, anchor);
    }

    private String insertAt(Deployment d, Groth16ProofBLS381 proof, BigInteger nullifier,
                            AnchorInfo anchor) throws Exception {
        // Full 32-byte nullifier for the ZK token
        byte[] nullFull = toFixedWidth(nullifier, 32);
        String nullFullHex = HexUtil.encodeHexString(nullFull);
        // The node key: slice(1, 31, nullFull)
        byte[] nullKey = Arrays.copyOfRange(nullFull, 1, 32);
        String nullKeyHex = HexUtil.encodeHexString(nullKey);
        byte[] nodeTokenName = concat(PREFIX, nullKey);
        String nodeTokenHex = HexUtil.encodeHexString(nodeTokenName);

        log.info("Inserting nullifier {} into on-chain linked list", nullKeyHex.substring(0, 16));

        // Get a wallet UTXO for fees
        var walletUtxo = walletUtxos().stream()
                .filter(u -> !u.getTxHash().equals(anchor.utxo.getTxHash())
                        || u.getOutputIndex() != anchor.utxo.getOutputIndex())
                .findFirst()
                .orElseThrow(() -> new RuntimeException("No separate wallet UTXO for fees"));

        // Compress proof for on-chain
        var compressedProof = ProofCompressor.compressProof(proof);

        // ZK minting redeemer: the proof and the nullifier; root and context are script parameters
        var zkRedeemer = ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressedProof.piA()),
                        new BytesPlutusData(compressedProof.piB()),
                        new BytesPlutusData(compressedProof.piC()),
                        BigIntPlutusData.of(nullifier)))
                .build();

        // List insertion redeemer: InsertNode(anchorTokenName, contAnchorOutIdx=0, newElemOutIdx=1)
        var listRedeemer = ConstrPlutusData.builder()
                .alternative(1) // InsertNode is second variant (after InitList)
                .data(ListPlutusData.of(
                        new BytesPlutusData(anchor.tokenName),
                        BigIntPlutusData.of(0),
                        BigIntPlutusData.of(1)))
                .build();

        // Spend redeemer (spend validator only checks the list mint)
        var spendRedeemer = ConstrPlutusData.of(0);

        // Assets
        var listAsset = new Asset("0x" + nodeTokenHex, BigInteger.ONE);
        var zkAsset = new Asset("0x" + nullFullHex, BigInteger.ONE);
        var contAnchorAmounts = continuingAnchorAmounts(anchor.utxo);

        // Datums
        var contAnchorDatum = listElementDatum(nullKey);        // anchor.next = nullKey
        var newNodeDatum = listElementDatum(anchor.oldNextKey);  // newNode.next = anchor's old next

        // Build transaction
        var tx = new ScriptTx()
                .collectFrom(anchor.utxo, spendRedeemer)
                .collectFrom(walletUtxo)
                .mintAsset(d.listScript(), List.of(listAsset), listRedeemer)
                .mintAsset(d.zkScript(), List.of(zkAsset), zkRedeemer)
                .payToContract(d.registryAddr(), contAnchorAmounts, contAnchorDatum)
                .payToContract(d.registryAddr(),
                        List.of(Amount.ada(2),
                                new Amount(d.listPolicyHex() + nodeTokenHex, BigInteger.ONE),
                                new Amount(d.zkPolicyHex() + nullFullHex, BigInteger.ONE)),
                        newNodeDatum)
                .attachSpendingValidator(d.listScript());

        var quickTx = new QuickTxBuilder(backendService);
        var result = quickTx.compose(tx)
                .withTxEvaluator(createJulcEvaluator())
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Nullifier insertion tx failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Nullifier inserted on-chain: tx={}", txHash);
        waitForTx(txHash);
        return txHash;
    }

    public String getRegistryAddress() {
        var d = deployment;
        return d == null ? null : d.registryAddr();
    }

    public String getListPolicyId() {
        var d = deployment;
        return d == null ? null : d.listPolicyHex();
    }

    public String getZkPolicyId() {
        var d = deployment;
        return d == null ? null : d.zkPolicyHex();
    }

    // === Internal helpers ===

    private Deployment requireDeployment() {
        var d = deployment;
        if (d == null) {
            throw new IllegalStateException("the event is not deployed yet; build the snapshot first");
        }
        return d;
    }

    private PlutusScript zkPolicy(BigInteger snapshotRoot, BigInteger contextId) {
        var vk = ProofCompressor.compressVk(proverService.getSetupResult());
        return JulcScriptLoader.load(ZkProofMintingPolicy.class,
                BigIntPlutusData.of(snapshotRoot),
                BigIntPlutusData.of(contextId),
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()));
    }

    private static PlutusScript listPolicy(byte[] zkPolicyHash, byte[] seedRef) {
        return JulcScriptLoader.load(NullifierListValidator.class,
                new BytesPlutusData(ROOT_KEY),
                new BytesPlutusData(PREFIX),
                BigIntPlutusData.of(PREFIX_LEN),
                new BytesPlutusData(zkPolicyHash),
                new BytesPlutusData(seedRef));
    }

    private void deployRootSentinel(Deployment d, Utxo seed) throws Exception {
        log.info("Deploying root sentinel (seed {}#{})...", seed.getTxHash(), seed.getOutputIndex());
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);

        var rootAsset = new Asset("0x" + rootTokenHex, BigInteger.ONE);
        var rootDatum = listElementDatum(new byte[0]); // root→∅
        var initRedeemer = ConstrPlutusData.builder()
                .alternative(0) // InitList
                .data(ListPlutusData.of(BigIntPlutusData.of(0)))
                .build();

        var initTx = new ScriptTx()
                .collectFrom(seed)
                .mintAsset(d.listScript(), List.of(rootAsset), initRedeemer)
                .payToContract(d.registryAddr(),
                        List.of(Amount.ada(2), new Amount(d.listPolicyHex() + rootTokenHex, BigInteger.ONE)),
                        rootDatum);

        var quickTx = new QuickTxBuilder(backendService);
        var result = quickTx.compose(initTx)
                .withTxEvaluator(createJulcEvaluator())
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Root sentinel deployment failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Root sentinel deployed: tx={}", txHash);
        waitForTx(txHash);
    }

    private List<Utxo> walletUtxos() throws Exception {
        var result = backendService.getUtxoService().getUtxos(adminAccount.baseAddress(), 20, 1);
        if (!result.isSuccessful() || result.getValue() == null || result.getValue().isEmpty()) {
            throw new IllegalStateException("No wallet UTxOs; top up " + adminAccount.baseAddress());
        }
        return result.getValue();
    }

    private List<Utxo> queryRegistryUtxos(Deployment d) throws Exception {
        List<Utxo> all = new ArrayList<>();
        for (int page = 1; ; page++) {
            var result = backendService.getUtxoService().getUtxos(d.registryAddr(), 100, page);
            if (!result.isSuccessful() || result.getValue() == null || result.getValue().isEmpty()) break;
            all.addAll(result.getValue());
            if (result.getValue().size() < 100) break;
        }
        return all;
    }

    private List<Amount> continuingAnchorAmounts(Utxo anchorUtxo) {
        List<Amount> amounts = new ArrayList<>();
        amounts.add(Amount.ada(2));
        if (anchorUtxo.getAmount() != null) {
            for (var amount : anchorUtxo.getAmount()) {
                String unit = amount.getUnit();
                if (unit != null && !"lovelace".equals(unit)) {
                    amounts.add(new Amount(unit, amount.getQuantity()));
                }
            }
        }
        return amounts;
    }

    record AnchorInfo(Utxo utxo, byte[] tokenName, byte[] oldNextKey) {}

    /**
     * Find the anchor node for sorted insertion. The anchor is the node where
     * anchorKey < newKey < anchor.nextKey (or anchor is root and newKey < anchor.nextKey,
     * or anchor.nextKey is empty meaning insert at end).
     */
    private AnchorInfo findAnchor(Deployment d, List<Utxo> utxos, byte[] newKey) {
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);

        for (var utxo : utxos) {
            byte[] tokenName = findListToken(d, utxo);
            if (tokenName == null) continue;

            byte[] nextKey = extractNextKey(utxo);
            if (nextKey == null) continue;

            boolean isRoot = HexUtil.encodeHexString(tokenName).equals(rootTokenHex);
            byte[] anchorKey = isRoot ? null : extractKey(tokenName);

            // Check sorted order
            boolean leftOk = isRoot || lessThan(anchorKey, newKey);
            boolean rightOk = nextKey.length == 0 || lessThan(newKey, nextKey);

            if (leftOk && rightOk) {
                return new AnchorInfo(utxo, tokenName, nextKey);
            }
        }
        return null; // nullifier already exists or list is corrupt
    }

    private static byte[] findListToken(Deployment d, Utxo utxo) {
        if (utxo.getAmount() == null) return null;
        String listPolicyHex = d.listPolicyHex();
        for (var amt : utxo.getAmount()) {
            String unit = amt.getUnit();
            if (unit.startsWith(listPolicyHex) && unit.length() > listPolicyHex.length()) {
                String tokenHex = unit.substring(listPolicyHex.length());
                return HexUtil.decodeHexString(tokenHex);
            }
        }
        return null;
    }

    private static byte[] extractKey(byte[] tokenName) {
        if (tokenName.length <= PREFIX.length) return new byte[0];
        return Arrays.copyOfRange(tokenName, PREFIX.length, tokenName.length);
    }

    private static byte[] extractKeyFromUtxo(Deployment d, Utxo utxo) {
        byte[] tokenName = findListToken(d, utxo);
        if (tokenName == null) return null;
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);
        if (HexUtil.encodeHexString(tokenName).equals(rootTokenHex)) return null;
        return extractKey(tokenName);
    }

    private static byte[] extractNextKey(Utxo utxo) {
        var datum = parseDatum(utxo);
        if (datum == null) return null;
        return datum;
    }

    /**
     * Parse the inline datum to extract the nextKey field.
     * Datum = Constr(0, [userData, BData(nextKey)])
     * CCL returns inline datum as CBOR hex string.
     */
    private static byte[] parseDatum(Utxo utxo) {
        try {
            var inlineDatumHex = utxo.getInlineDatum();
            if (inlineDatumHex == null || inlineDatumHex.isEmpty()) return null;
            var plutusData = com.bloxbean.cardano.client.plutus.spec.PlutusData
                    .deserialize(HexUtil.decodeHexString(inlineDatumHex));
            if (plutusData instanceof ConstrPlutusData constr) {
                var fields = constr.getData().getPlutusDataList();
                if (fields.size() >= 2 && fields.get(1) instanceof BytesPlutusData bpd) {
                    return bpd.getValue();
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean lessThan(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        for (int i = 0; i < len; i++) {
            int ai = a[i] & 0xFF;
            int bi = b[i] & 0xFF;
            if (ai < bi) return true;
            if (ai > bi) return false;
        }
        return a.length < b.length;
    }

    /** {@code txId ‖ I2OSP2(index)}, as Julc's {@code ValuesLib.refBytes} encodes an output reference. */
    static byte[] seedRef(Utxo seed) {
        byte[] txId = HexUtil.decodeHexString(seed.getTxHash());
        int index = seed.getOutputIndex();
        return concat(txId, new byte[] {(byte) (index >>> 8), (byte) index});
    }

    /** The node key: the low 31 bytes of the nullifier's 32-byte token name. */
    static byte[] nodeKey(BigInteger nullifier) {
        return Arrays.copyOfRange(toFixedWidth(nullifier, 32), 1, 32);
    }

    static ConstrPlutusData listElementDatum(byte[] nextKey) {
        return ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(
                        ConstrPlutusData.of(0),          // unit userData
                        new BytesPlutusData(nextKey)))
                .build();
    }

    static byte[] toFixedWidth(BigInteger value, int width) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[width];
        int srcStart = Math.max(0, raw.length - width);
        int count = Math.min(raw.length, width);
        int destStart = width - count;
        System.arraycopy(raw, srcStart, result, destStart, count);
        return result;
    }

    private static ListPlutusData vkIcData(List<byte[]> ic) {
        PlutusData[] values = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) {
            values[i] = new BytesPlutusData(ic.get(i));
        }
        return ListPlutusData.of(values);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private TransactionEvaluator createJulcEvaluator() {
        SlotConfig slotConfig = deriveSlotConfig();
        var evaluator = new JulcTransactionEvaluator(
                new DefaultUtxoSupplier(backendService.getUtxoService()),
                new DefaultProtocolParamsSupplier(backendService.getEpochService()),
                new DefaultScriptSupplier(backendService.getScriptService()),
                slotConfig);
        return (tx, utxos) -> {
            var result = evaluator.evaluateTx(tx, utxos);
            if (result.isSuccessful() && result.getValue() != null) {
                for (EvaluationResult eval : result.getValue()) {
                    eval.setExUnits(pad(eval.getExUnits()));
                }
            }
            return result;
        };
    }

    private static ExUnits pad(ExUnits units) {
        var memPadding = units.getMem().divide(PADDING_DIVISOR).max(MIN_MEM_PADDING);
        var stepsPadding = units.getSteps().divide(PADDING_DIVISOR);
        return new ExUnits(units.getMem().add(memPadding), units.getSteps().add(stepsPadding));
    }

    private SlotConfig deriveSlotConfig() {
        if (yaciAdminUrl == null || yaciAdminUrl.isBlank()) {
            log.warn("Could not derive SlotConfig: no Yaci admin URL configured");
            return new SlotConfig(0, System.currentTimeMillis(), 1000);
        }
        try {
            String adminBaseUrl = yaciAdminUrl.endsWith("/")
                    ? yaciAdminUrl.substring(0, yaciAdminUrl.length() - 1)
                    : yaciAdminUrl;
            var client = java.net.http.HttpClient.newHttpClient();
            var request = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(adminBaseUrl + "/local-cluster/api/admin/devnet"))
                    .GET().build();
            var response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                log.warn("Could not derive SlotConfig: HTTP {}", response.statusCode());
                return new SlotConfig(0, System.currentTimeMillis(), 1000);
            }
            String body = response.body();
            long startTime = parseJsonLong(body, "startTime");
            double slotLength = parseJsonDouble(body, "slotLength");
            return new SlotConfig(0, startTime * 1000, (long) (slotLength * 1000));
        } catch (Exception e) {
            log.warn("Could not derive SlotConfig: {}", e.getMessage());
            return new SlotConfig(0, System.currentTimeMillis(), 1000);
        }
    }

    private static long parseJsonLong(String json, String key) {
        var m = java.util.regex.Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        if (!m.find()) throw new IllegalArgumentException("Key not found: " + key);
        return Long.parseLong(m.group(1));
    }

    private static double parseJsonDouble(String json, String key) {
        var m = java.util.regex.Pattern.compile("\"" + key + "\"\\s*:\\s*(-?[\\d.]+)").matcher(json);
        if (!m.find()) throw new IllegalArgumentException("Key not found: " + key);
        return Double.parseDouble(m.group(1));
    }

    private void waitForTx(String txHash) throws Exception {
        for (int i = 0; i < 30; i++) {
            Thread.sleep(2000);
            try {
                var r = backendService.getTransactionService().getTransaction(txHash);
                if (r.isSuccessful() && r.getValue() != null) {
                    log.info("Confirmed: {}", txHash);
                    return;
                }
            } catch (Exception ignored) {}
        }
        log.warn("Tx confirmation timeout: {}", txHash);
    }
}
