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
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.nft.onchain.NullifierListValidator;
import com.bloxbean.cardano.zeroj.usecases.nft.onchain.ZkProofMintingPolicy;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.julc.clientlib.eval.JulcTransactionEvaluator;
import com.bloxbean.cardano.julc.clientlib.eval.SlotConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;

/**
 * On-chain nullifier tracking via sorted linked list on Cardano.
 * <p>
 * Manages two Julc scripts:
 * <ul>
 *   <li>{@link NullifierListValidator} — sorted linked list (MINT + SPEND)</li>
 *   <li>{@link ZkProofMintingPolicy} — Groth16 BLS12-381 proof verification</li>
 * </ul>
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
    // Nullifier keys are 31 bytes (truncated from 32-byte field element)
    // to fit Cardano's 32-byte asset name limit: PREFIX (1 byte) + key (31 bytes) = 32 bytes
    static final int NULL_KEY_WIDTH = 31;

    private final BackendService backendService;
    private final Account adminAccount;
    private final ProverService proverService;

    private PlutusScript listScript;
    private PlutusScript zkScript;
    private String listPolicyHex;
    private String zkPolicyHex;
    private String registryAddr;
    private boolean initialized;

    public OnChainNullifierService(BackendService backendService, Account adminAccount,
                                    ProverService proverService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.proverService = proverService;
    }

    /**
     * Compile scripts and deploy the root sentinel. Call after ProverService is ready.
     */
    public synchronized void initialize() throws Exception {
        if (initialized) return;

        log.info("Compiling on-chain nullifier scripts...");

        // Compress VK from prover setup
        var vk = ProofCompressor.compressVk(proverService.getSetupResult());

        // Compile ZK proof minting policy with VK params
        zkScript = JulcScriptLoader.load(ZkProofMintingPolicy.class,
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()));
        byte[] zkPolicyHash = zkScript.getScriptHash();
        zkPolicyHex = HexUtil.encodeHexString(zkPolicyHash);
        log.info("ZK minting policy: {}", zkPolicyHex);

        // Compile linked list validator with ZK policy hash
        listScript = JulcScriptLoader.load(NullifierListValidator.class,
                new BytesPlutusData(ROOT_KEY),
                new BytesPlutusData(PREFIX),
                BigIntPlutusData.of(PREFIX_LEN),
                new BytesPlutusData(zkPolicyHash));
        listPolicyHex = HexUtil.encodeHexString(listScript.getScriptHash());
        registryAddr = AddressProvider.getEntAddress(listScript, Networks.testnet()).toBech32();
        log.info("List policy: {}, registry: {}...", listPolicyHex, registryAddr.substring(0, 30));

        // Deploy root sentinel if not already present
        if (!hasRootSentinel()) {
            deployRootSentinel();
        } else {
            log.info("Root sentinel already deployed.");
        }

        initialized = true;
        log.info("On-chain nullifier service ready.");
    }

    // === NullifierTracker interface ===

    @Override
    public boolean isUsed(BigInteger nullifier) {
        try {
            ensureInitialized();
            byte[] nullKey = toFixedWidth(nullifier, NULL_KEY_WIDTH);
            var utxos = queryRegistryUtxos();
            for (var utxo : utxos) {
                var datum = parseDatum(utxo);
                if (datum != null) {
                    byte[] nodeKey = extractKeyFromUtxo(utxo);
                    if (nodeKey != null && Arrays.equals(nodeKey, nullKey)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            log.error("Error checking nullifier", e);
            return false;
        }
    }

    @Override
    public boolean recordNullifier(BigInteger nullifier) {
        throw new UnsupportedOperationException(
                "Use insertNullifier(proof, ...) for on-chain mode");
    }

    @Override
    public int getUsedCount() {
        try {
            ensureInitialized();
            var utxos = queryRegistryUtxos();
            // Count = total UTXOs - 1 (root sentinel)
            return Math.max(0, utxos.size() - 1);
        } catch (Exception e) {
            log.error("Error counting nullifiers", e);
            return 0;
        }
    }

    // === On-chain operations ===

    /**
     * Insert a nullifier on-chain. Builds and submits a transaction that:
     * 1. Spends the predecessor node in the sorted linked list
     * 2. Mints a list NFT for the new node (validates sorted insertion)
     * 3. Mints a ZK token (validates Groth16 proof)
     *
     * @return the transaction hash
     */
    public String insertNullifier(Groth16ProofBLS381 proof,
                                   BigInteger snapshotRoot, BigInteger contextId,
                                   BigInteger nullifier) throws Exception {
        ensureInitialized();

        // Full 32-byte nullifier for ZK token (fits Cardano 32-byte asset name limit)
        byte[] nullFull = toFixedWidth(nullifier, 32);
        String nullFullHex = HexUtil.encodeHexString(nullFull);
        // Truncated 31-byte key for list node token (PREFIX 1 byte + 31 bytes = 32)
        byte[] nullKey = toFixedWidth(nullifier, NULL_KEY_WIDTH);
        String nullKeyHex = HexUtil.encodeHexString(nullKey);
        byte[] nodeTokenName = concat(PREFIX, nullKey);
        String nodeTokenHex = HexUtil.encodeHexString(nodeTokenName);
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);

        log.info("Inserting nullifier {} into on-chain linked list", nullKeyHex.substring(0, 16));

        // Find the anchor (predecessor) node
        var utxos = queryRegistryUtxos();
        var anchor = findAnchor(utxos, nullKey);
        if (anchor == null) {
            throw new RuntimeException("Nullifier already exists or no valid insertion point");
        }

        // Get a wallet UTXO for fees
        var walletUtxos = backendService.getUtxoService().getUtxos(adminAccount.baseAddress(), 10, 1);
        if (!walletUtxos.isSuccessful() || walletUtxos.getValue().isEmpty()) {
            throw new RuntimeException("No wallet UTXOs for fees");
        }
        var walletUtxo = walletUtxos.getValue().stream()
                .filter(u -> !u.getTxHash().equals(anchor.utxo.getTxHash())
                        || u.getOutputIndex() != anchor.utxo.getOutputIndex())
                .findFirst()
                .orElseThrow(() -> new RuntimeException("No separate wallet UTXO for fees"));

        // Compute input indices (inputs are sorted by TxOutRef)
        int anchorIdx = computeInputIndex(List.of(anchor.utxo, walletUtxo), anchor.utxo);

        // Compress proof for on-chain
        var compressedProof = ProofCompressor.compressProof(proof);

        // ZK minting redeemer — uses full 32-byte nullifier for proof verification
        var zkRedeemer = ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressedProof.piA()),
                        new BytesPlutusData(compressedProof.piB()),
                        new BytesPlutusData(compressedProof.piC()),
                        new BytesPlutusData(toMinimalBytes(snapshotRoot)),
                        new BytesPlutusData(toMinimalBytes(contextId)),
                        new BytesPlutusData(toMinimalBytes(BigInteger.ONE)),
                        new BytesPlutusData(nullFull)))
                .build();

        // List insertion redeemer: InsertNode(anchorIdx, contAnchorOutIdx=0, newElemOutIdx=1)
        var listRedeemer = ConstrPlutusData.builder()
                .alternative(1) // InsertNode is second variant (after InitList)
                .data(ListPlutusData.of(
                        BigIntPlutusData.of(anchorIdx),
                        BigIntPlutusData.of(0),
                        BigIntPlutusData.of(1)))
                .build();

        // Spend redeemer (spend validator just checks mint field)
        var spendRedeemer = ConstrPlutusData.of(0);

        // Assets
        var listAsset = new Asset("0x" + nodeTokenHex, BigInteger.ONE);
        var zkAsset = new Asset("0x" + nullFullHex, BigInteger.ONE);

        // Datums
        var contAnchorDatum = listElementDatum(nullKey);        // anchor.next = nullKey
        var newNodeDatum = listElementDatum(anchor.oldNextKey);  // newNode.next = anchor's old next

        // Anchor token (root or node NFT)
        String anchorTokenHex = HexUtil.encodeHexString(anchor.tokenName);

        // Build transaction
        var tx = new ScriptTx()
                .collectFrom(anchor.utxo, spendRedeemer)
                .collectFrom(walletUtxo)
                .mintAsset(listScript, List.of(listAsset), listRedeemer)
                .mintAsset(zkScript, List.of(zkAsset), zkRedeemer)
                .payToContract(registryAddr,
                        List.of(Amount.ada(2), new Amount(listPolicyHex + anchorTokenHex, BigInteger.ONE)),
                        contAnchorDatum)
                .payToContract(registryAddr,
                        List.of(Amount.ada(2),
                                new Amount(listPolicyHex + nodeTokenHex, BigInteger.ONE),
                                new Amount(zkPolicyHex + nullFullHex, BigInteger.ONE)),
                        newNodeDatum)
                .attachSpendingValidator(listScript);

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
        return registryAddr;
    }

    public String getListPolicyId() {
        return listPolicyHex;
    }

    public String getZkPolicyId() {
        return zkPolicyHex;
    }

    // === Internal helpers ===

    private void ensureInitialized() throws Exception {
        if (!initialized) initialize();
    }

    private boolean hasRootSentinel() throws Exception {
        var utxos = queryRegistryUtxos();
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);
        for (var utxo : utxos) {
            if (utxo.getAmount() != null) {
                for (var amt : utxo.getAmount()) {
                    if (amt.getUnit().contains(rootTokenHex)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private void deployRootSentinel() throws Exception {
        log.info("Deploying root sentinel...");
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);

        var rootAsset = new Asset("0x" + rootTokenHex, BigInteger.ONE);
        var rootDatum = listElementDatum(new byte[0]); // root→∅
        var initRedeemer = ConstrPlutusData.builder()
                .alternative(0) // InitList
                .data(ListPlutusData.of(BigIntPlutusData.of(0)))
                .build();

        var initTx = new ScriptTx()
                .mintAsset(listScript, List.of(rootAsset), initRedeemer)
                .payToContract(registryAddr,
                        List.of(Amount.ada(2), new Amount(listPolicyHex + rootTokenHex, BigInteger.ONE)),
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

    private List<Utxo> queryRegistryUtxos() throws Exception {
        var result = backendService.getUtxoService().getUtxos(registryAddr, 100, 1);
        if (!result.isSuccessful() || result.getValue() == null) {
            return Collections.emptyList();
        }
        return result.getValue();
    }

    record AnchorInfo(Utxo utxo, byte[] tokenName, byte[] oldNextKey) {}

    /**
     * Find the anchor node for sorted insertion. The anchor is the node where
     * anchorKey < newKey < anchor.nextKey (or anchor is root and newKey < anchor.nextKey,
     * or anchor.nextKey is empty meaning insert at end).
     */
    private AnchorInfo findAnchor(List<Utxo> utxos, byte[] newKey) {
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);

        for (var utxo : utxos) {
            byte[] tokenName = findListToken(utxo);
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

    private byte[] findListToken(Utxo utxo) {
        if (utxo.getAmount() == null) return null;
        for (var amt : utxo.getAmount()) {
            String unit = amt.getUnit();
            if (unit.startsWith(listPolicyHex) && unit.length() > listPolicyHex.length()) {
                String tokenHex = unit.substring(listPolicyHex.length());
                return HexUtil.decodeHexString(tokenHex);
            }
        }
        return null;
    }

    private byte[] extractKey(byte[] tokenName) {
        if (tokenName.length <= PREFIX.length) return new byte[0];
        return Arrays.copyOfRange(tokenName, PREFIX.length, tokenName.length);
    }

    private byte[] extractKeyFromUtxo(Utxo utxo) {
        byte[] tokenName = findListToken(utxo);
        if (tokenName == null) return null;
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);
        if (HexUtil.encodeHexString(tokenName).equals(rootTokenHex)) return null;
        return extractKey(tokenName);
    }

    private byte[] extractNextKey(Utxo utxo) {
        var datum = parseDatum(utxo);
        if (datum == null) return null;
        return datum;
    }

    /**
     * Parse the inline datum to extract the nextKey field.
     * Datum = Constr(0, [userData, BData(nextKey)])
     * CCL returns inline datum as CBOR hex string.
     */
    private byte[] parseDatum(Utxo utxo) {
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

    /**
     * Compute input index in the sorted order (by TxOutRef: txHash then outputIndex).
     * Matches Cardano ledger's canonical input ordering.
     */
    static int computeInputIndex(List<Utxo> allInputs, Utxo target) {
        var sorted = new ArrayList<>(allInputs);
        sorted.sort(Comparator.comparing(Utxo::getTxHash)
                .thenComparingInt(Utxo::getOutputIndex));
        for (int i = 0; i < sorted.size(); i++) {
            var u = sorted.get(i);
            if (u.getTxHash().equals(target.getTxHash())
                    && u.getOutputIndex() == target.getOutputIndex()) {
                return i;
            }
        }
        throw new RuntimeException("UTXO not found in input list");
    }

    static ConstrPlutusData listElementDatum(byte[] nextKey) {
        return ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(
                        ConstrPlutusData.of(0),          // unit userData
                        new BytesPlutusData(nextKey)))
                .build();
    }

    private static byte[] toFixedWidth(BigInteger value, int width) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[width];
        int srcStart = Math.max(0, raw.length - width);
        int count = Math.min(raw.length, width);
        int destStart = width - count;
        System.arraycopy(raw, srcStart, result, destStart, count);
        return result;
    }

    private static byte[] toMinimalBytes(BigInteger v) {
        byte[] b = v.toByteArray();
        return (b.length > 1 && b[0] == 0) ? Arrays.copyOfRange(b, 1, b.length) : b;
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
        try {
            var client = java.net.http.HttpClient.newHttpClient();
            var request = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create("http://localhost:10000/local-cluster/api/admin/devnet"))
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
