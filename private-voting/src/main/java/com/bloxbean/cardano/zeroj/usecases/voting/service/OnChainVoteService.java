package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.voting.onchain.VoteListValidator;
import com.bloxbean.cardano.zeroj.usecases.voting.onchain.VoteZkMintingPolicy;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;

@Service
public class OnChainVoteService {

    private static final Logger log = LoggerFactory.getLogger(OnChainVoteService.class);

    static final byte[] ROOT_KEY = "VROOT".getBytes();
    static final byte[] PREFIX = "V".getBytes();
    static final BigInteger PREFIX_LEN = BigInteger.ONE;
    static final int NULL_KEY_WIDTH = 31;

    private final BackendService backendService;
    private final Account adminAccount;
    private final VoteCircuitService circuitService;

    private PlutusScript listScript;
    private PlutusScript zkScript;
    private String listPolicyHex;
    private String zkPolicyHex;
    private String registryAddr;
    private boolean initialized;

    public OnChainVoteService(BackendService backendService, Account adminAccount,
                               VoteCircuitService circuitService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.circuitService = circuitService;
    }

    public synchronized void initialize() throws Exception {
        if (initialized) return;

        log.info("Compiling on-chain vote validators...");

        var vk = ProofCompressor.compressVk(circuitService.getSetupResult());

        zkScript = JulcScriptLoader.load(VoteZkMintingPolicy.class,
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()));
        byte[] zkPolicyHash = zkScript.getScriptHash();
        zkPolicyHex = HexUtil.encodeHexString(zkPolicyHash);
        log.info("ZK minting policy: {}", zkPolicyHex);

        listScript = JulcScriptLoader.load(VoteListValidator.class,
                new BytesPlutusData(ROOT_KEY),
                new BytesPlutusData(PREFIX),
                BigIntPlutusData.of(PREFIX_LEN),
                new BytesPlutusData(zkPolicyHash));
        listPolicyHex = HexUtil.encodeHexString(listScript.getScriptHash());
        registryAddr = AddressProvider.getEntAddress(listScript, Networks.testnet()).toBech32();
        log.info("List policy: {}, registry: {}...", listPolicyHex, registryAddr.substring(0, 30));

        if (!hasRootSentinel()) {
            deployRootSentinel();
        } else {
            log.info("Root sentinel already deployed.");
        }

        initialized = true;
        log.info("On-chain vote service ready.");
    }

    /**
     * Submit a vote on-chain. Inserts nullifier into sorted linked list
     * with commitment stored in the node's userData.
     *
     * @return the transaction hash
     */
    public String submitVote(Groth16ProofBLS381 proof,
                              BigInteger electionId, BigInteger voterRoot,
                              BigInteger nullifier, BigInteger commitment) throws Exception {
        ensureInitialized();

        byte[] nullFull = toFixedWidth(nullifier, 32);
        String nullFullHex = HexUtil.encodeHexString(nullFull);
        byte[] nullKey = toFixedWidth(nullifier, NULL_KEY_WIDTH);
        String nullKeyHex = HexUtil.encodeHexString(nullKey);
        byte[] nodeTokenName = concat(PREFIX, nullKey);
        String nodeTokenHex = HexUtil.encodeHexString(nodeTokenName);
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);

        log.info("Submitting vote on-chain (nullifier={}...)", nullKeyHex.substring(0, 16));

        var utxos = queryRegistryUtxos();
        var anchor = findAnchor(utxos, nullKey);
        if (anchor == null) {
            throw new RuntimeException("Nullifier already exists — double vote attempt");
        }

        var walletUtxos = backendService.getUtxoService().getUtxos(adminAccount.baseAddress(), 10, 1);
        if (!walletUtxos.isSuccessful() || walletUtxos.getValue().isEmpty()) {
            throw new RuntimeException("No wallet UTXOs for fees");
        }
        var walletUtxo = walletUtxos.getValue().stream()
                .filter(u -> !u.getTxHash().equals(anchor.utxo.getTxHash())
                        || u.getOutputIndex() != anchor.utxo.getOutputIndex())
                .findFirst()
                .orElseThrow(() -> new RuntimeException("No separate wallet UTXO"));

        int anchorIdx = computeInputIndex(List.of(anchor.utxo, walletUtxo), anchor.utxo);

        var compressedProof = ProofCompressor.compressProof(proof);

        // ZK redeemer: electionId, voterRoot, nullifier(full), commitment
        var zkRedeemer = ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressedProof.piA()),
                        new BytesPlutusData(compressedProof.piB()),
                        new BytesPlutusData(compressedProof.piC()),
                        new BytesPlutusData(toMinimalBytes(electionId)),
                        new BytesPlutusData(toMinimalBytes(voterRoot)),
                        new BytesPlutusData(nullFull),
                        new BytesPlutusData(toMinimalBytes(commitment))))
                .build();

        // List redeemer: InsertNode(anchorIdx, 0, 1)
        var listRedeemer = ConstrPlutusData.builder()
                .alternative(1)
                .data(ListPlutusData.of(
                        BigIntPlutusData.of(anchorIdx),
                        BigIntPlutusData.of(0),
                        BigIntPlutusData.of(1)))
                .build();

        var spendRedeemer = ConstrPlutusData.of(0);

        var listAsset = new Asset("0x" + nodeTokenHex, BigInteger.ONE);
        var zkAsset = new Asset("0x" + nullFullHex, BigInteger.ONE);

        // Anchor datum stays the same (just update nextKey)
        var contAnchorDatum = listElementDatum(ConstrPlutusData.of(0), nullKey);

        // New node stores commitment in userData
        var commitmentData = BigIntPlutusData.of(commitment);
        var newNodeDatum = listElementDatum(commitmentData, anchor.oldNextKey);

        String anchorTokenHex = HexUtil.encodeHexString(anchor.tokenName);

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

        var result = new QuickTxBuilder(backendService)
                .compose(tx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Vote tx failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Vote submitted on-chain: tx={}", txHash);
        waitForTx(txHash);
        return txHash;
    }

    public boolean isNullifierUsed(BigInteger nullifier) {
        try {
            ensureInitialized();
            byte[] nullKey = toFixedWidth(nullifier, NULL_KEY_WIDTH);
            var utxos = queryRegistryUtxos();
            for (var utxo : utxos) {
                byte[] nodeKey = extractKeyFromUtxo(utxo);
                if (nodeKey != null && Arrays.equals(nodeKey, nullKey)) return true;
            }
            return false;
        } catch (Exception e) {
            log.error("Error checking nullifier", e);
            return false;
        }
    }

    /**
     * Get all vote nodes from the linked list (for tally).
     * Returns list of (nullifier key bytes, commitment BigInteger).
     */
    public List<VoteNode> getVoteNodes() throws Exception {
        ensureInitialized();
        var utxos = queryRegistryUtxos();
        List<VoteNode> nodes = new ArrayList<>();
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);

        for (var utxo : utxos) {
            byte[] tokenName = findListToken(utxo);
            if (tokenName == null) continue;
            if (HexUtil.encodeHexString(tokenName).equals(rootTokenHex)) continue;

            // Get full nullifier from the ZK token (32 bytes)
            byte[] fullNullifier = findZkToken(utxo);
            BigInteger commitment = extractCommitment(utxo);
            if (fullNullifier != null && commitment != null) {
                nodes.add(new VoteNode(fullNullifier, commitment));
            }
        }
        return nodes;
    }

    private byte[] findZkToken(Utxo utxo) {
        if (utxo.getAmount() == null) return null;
        for (var amt : utxo.getAmount()) {
            String unit = amt.getUnit();
            if (unit.startsWith(zkPolicyHex) && unit.length() > zkPolicyHex.length()) {
                return HexUtil.decodeHexString(unit.substring(zkPolicyHex.length()));
            }
        }
        return null;
    }

    public int getVoteCount() {
        try {
            ensureInitialized();
            return queryRegistryUtxos().size() - 1; // minus root
        } catch (Exception e) {
            return 0;
        }
    }

    public String getRegistryAddress() { return registryAddr; }

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
                    if (amt.getUnit().contains(rootTokenHex)) return true;
                }
            }
        }
        return false;
    }

    private void deployRootSentinel() throws Exception {
        log.info("Deploying root sentinel...");
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);

        var rootAsset = new Asset("0x" + rootTokenHex, BigInteger.ONE);
        var rootDatum = listElementDatum(ConstrPlutusData.of(0), new byte[0]);
        var initRedeemer = ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(BigIntPlutusData.of(0)))
                .build();

        var initTx = new ScriptTx()
                .mintAsset(listScript, List.of(rootAsset), initRedeemer)
                .payToContract(registryAddr,
                        List.of(Amount.ada(2), new Amount(listPolicyHex + rootTokenHex, BigInteger.ONE)),
                        rootDatum);

        var result = new QuickTxBuilder(backendService)
                .compose(initTx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Root sentinel deployment failed: " + result.getResponse());
        }

        log.info("Root sentinel deployed: tx={}", result.getValue());
        waitForTx(result.getValue());
    }

    private List<Utxo> queryRegistryUtxos() throws Exception {
        var result = backendService.getUtxoService().getUtxos(registryAddr, 100, 1);
        if (!result.isSuccessful() || result.getValue() == null) return Collections.emptyList();
        return result.getValue();
    }

    record AnchorInfo(Utxo utxo, byte[] tokenName, byte[] oldNextKey) {}

    private AnchorInfo findAnchor(List<Utxo> utxos, byte[] newKey) {
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);
        for (var utxo : utxos) {
            byte[] tokenName = findListToken(utxo);
            if (tokenName == null) continue;
            byte[] nextKey = extractNextKey(utxo);
            if (nextKey == null) continue;

            boolean isRoot = HexUtil.encodeHexString(tokenName).equals(rootTokenHex);
            byte[] anchorKey = isRoot ? null : extractKey(tokenName);

            boolean leftOk = isRoot || lessThan(anchorKey, newKey);
            boolean rightOk = nextKey.length == 0 || lessThan(newKey, nextKey);

            if (leftOk && rightOk) return new AnchorInfo(utxo, tokenName, nextKey);
        }
        return null;
    }

    private byte[] findListToken(Utxo utxo) {
        if (utxo.getAmount() == null) return null;
        for (var amt : utxo.getAmount()) {
            String unit = amt.getUnit();
            if (unit.startsWith(listPolicyHex) && unit.length() > listPolicyHex.length()) {
                return HexUtil.decodeHexString(unit.substring(listPolicyHex.length()));
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
        if (HexUtil.encodeHexString(tokenName).equals(HexUtil.encodeHexString(ROOT_KEY))) return null;
        return extractKey(tokenName);
    }

    private byte[] extractNextKey(Utxo utxo) {
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

    private BigInteger extractCommitment(Utxo utxo) {
        try {
            var inlineDatumHex = utxo.getInlineDatum();
            if (inlineDatumHex == null || inlineDatumHex.isEmpty()) return null;
            var plutusData = com.bloxbean.cardano.client.plutus.spec.PlutusData
                    .deserialize(HexUtil.decodeHexString(inlineDatumHex));
            if (plutusData instanceof ConstrPlutusData constr) {
                var fields = constr.getData().getPlutusDataList();
                if (fields.size() >= 1 && fields.get(0) instanceof BigIntPlutusData bipd) {
                    return bipd.getValue();
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    static int computeInputIndex(List<Utxo> allInputs, Utxo target) {
        var sorted = new ArrayList<>(allInputs);
        sorted.sort(Comparator.comparing(Utxo::getTxHash)
                .thenComparingInt(Utxo::getOutputIndex));
        for (int i = 0; i < sorted.size(); i++) {
            var u = sorted.get(i);
            if (u.getTxHash().equals(target.getTxHash())
                    && u.getOutputIndex() == target.getOutputIndex()) return i;
        }
        throw new RuntimeException("UTXO not found in input list");
    }

    /**
     * Build a ListElement datum: Constr(0, [userData, BData(nextKey)])
     */
    static ConstrPlutusData listElementDatum(com.bloxbean.cardano.client.plutus.spec.PlutusData userData, byte[] nextKey) {
        return ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(userData, new BytesPlutusData(nextKey)))
                .build();
    }

    private static boolean lessThan(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        for (int i = 0; i < len; i++) {
            int ai = a[i] & 0xFF, bi = b[i] & 0xFF;
            if (ai < bi) return true;
            if (ai > bi) return false;
        }
        return a.length < b.length;
    }

    private static byte[] toFixedWidth(BigInteger value, int width) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[width];
        int srcStart = Math.max(0, raw.length - width);
        int count = Math.min(raw.length, width);
        System.arraycopy(raw, srcStart, result, width - count, count);
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

    public record VoteNode(byte[] fullNullifier, BigInteger commitment) {}
}
