package com.bloxbean.cardano.zeroj.usecases.voting.service;

import com.bloxbean.cardano.client.account.Account;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.voting.crypto.JubjubElGamal;
import com.bloxbean.cardano.zeroj.usecases.voting.onchain.VoteListValidator;
import com.bloxbean.cardano.zeroj.usecases.voting.onchain.VoteZkMintingPolicy;
import org.julclang.clientlib.JulcScriptLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The vote list on Cardano (ADR-0005): per-election script deployment, ballot submission and
 * reading ballots back for the tally.
 *
 * <p>Each finalized election gets its own scripts, because the election id, voter root, election
 * key and deadline are script parameters. The list root is created once, by consuming a seed
 * output named in the list script's parameters.
 */
@Service
public class OnChainVoteService {

    private static final Logger log = LoggerFactory.getLogger(OnChainVoteService.class);

    static final byte[] ROOT_KEY = "VROOT".getBytes();
    static final byte[] PREFIX = "V".getBytes();
    static final BigInteger PREFIX_LEN = BigInteger.ONE;
    static final int NULL_KEY_WIDTH = 31;

    private static final ObjectMapper JSON = new ObjectMapper();

    @Value("${cardano.yaci.base-url:http://localhost:8080/api/v1/}")
    private String storeUrl = "http://localhost:8080/api/v1/";

    private final BackendService backendService;
    private final Account adminAccount;
    private final VoteCircuitService circuitService;

    /** The scripts of the election currently deployed, or {@code null}. */
    private volatile Deployment deployment;

    public OnChainVoteService(BackendService backendService, Account adminAccount,
                              VoteCircuitService circuitService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.circuitService = circuitService;
    }

    /** One election's scripts and addresses. */
    record Deployment(BigInteger electionId, PlutusScript zkScript, String zkPolicyHex,
                      PlutusScript listScript, String listPolicyHex, String registryAddr, byte[] seedRef) {}

    /** A ballot read back from the vote list. */
    public record BallotNode(byte[] nullifier, JubjubElGamal.Ciphertext ciphertext) {}

    /**
     * Derives the election's scripts from its configuration and creates the list root, once.
     * Idempotent for the same election.
     */
    public synchronized Deployment deploy(ElectionService.ElectionConfig config) throws Exception {
        if (deployment != null && deployment.electionId().equals(config.electionId())) {
            return deployment;
        }
        log.info("Deploying vote scripts for election '{}'...", config.name());

        PlutusScript zkScript = ballotPolicy(config);
        byte[] zkPolicyHash = zkScript.getScriptHash();

        // One-shot root: the list script names a wallet output that InitList must consume.
        Utxo seed = walletUtxos().getFirst();
        byte[] seedRef = seedRef(seed);
        PlutusScript listScript = listPolicy(zkPolicyHash, seedRef);
        String listPolicyHex = HexUtil.encodeHexString(listScript.getScriptHash());
        String registryAddr = AddressProvider.getEntAddress(listScript, Networks.testnet()).toBech32();

        var d = new Deployment(config.electionId(), zkScript, HexUtil.encodeHexString(zkPolicyHash),
                listScript, listPolicyHex, registryAddr, seedRef);
        deployRoot(d, seed);
        deployment = d;
        log.info("Ballot policy {}, list policy {}, registry {}...", d.zkPolicyHex(), listPolicyHex,
                registryAddr.substring(0, 30));
        return d;
    }

    /**
     * Submits a proved ballot: inserts a node keyed by the nullifier into the vote list, holding
     * the ballot in its datum, and mints the nullifier token whose policy verifies the proof.
     * The transaction expires at the voting deadline.
     *
     * @return the transaction hash
     */
    public String submitBallot(ElectionService.ElectionConfig config,
                               VoteCircuitService.BallotProof ballot) throws Exception {
        Deployment d = deploy(config);
        byte[] nullKey = nullifierKey(ballot.nullifier());
        log.info("Submitting ballot on-chain (nullifier={}...)", HexUtil.encodeHexString(nullKey).substring(0, 16));
        var anchor = findAnchor(d, registryUtxos(d), nullKey, false);
        return submitBallotAt(config, ballot, anchor, deadlineSlot(config.votingDeadlineMillis()));
    }

    /**
     * Builds and submits the insert for {@code ballot} after {@code anchor}, valid until slot
     * {@code ttl}. {@link #submitBallot} chooses both honestly; tests pass others to show that the
     * scripts, not this client, reject a duplicate or a late ballot.
     */
    String submitBallotAt(ElectionService.ElectionConfig config, VoteCircuitService.BallotProof ballot,
                          AnchorInfo anchor, long ttl) throws Exception {
        Deployment d = deploy(config);
        byte[] nullFull = toFixedWidth(ballot.nullifier(), 32);
        byte[] nullKey = nullifierKey(ballot.nullifier());
        byte[] nodeTokenName = concat(PREFIX, nullKey);

        var compressed = ProverToCardano.compressProof(ballot.proof());
        var zkRedeemer = ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(compressed.piA()),
                new BytesPlutusData(compressed.piB()),
                new BytesPlutusData(compressed.piC()))).build();
        var listRedeemer = ConstrPlutusData.builder().alternative(1).data(ListPlutusData.of(
                new BytesPlutusData(anchor.tokenName()),
                BigIntPlutusData.of(0),
                BigIntPlutusData.of(1))).build();

        var c = ballot.ciphertext();
        var contAnchorDatum = listElementDatum(anchor.userData(), nullKey);
        var newNodeDatum = listElementDatum(ballotDatum(c), anchor.oldNextKey());

        var tx = new ScriptTx()
                .collectFrom(anchor.utxo(), ConstrPlutusData.of(0))
                .mintAsset(d.listScript(), List.of(new Asset("0x" + HexUtil.encodeHexString(nodeTokenName), BigInteger.ONE)),
                        listRedeemer)
                .mintAsset(d.zkScript(), List.of(new Asset("0x" + HexUtil.encodeHexString(nullFull), BigInteger.ONE)),
                        zkRedeemer)
                .payToContract(d.registryAddr(), continuingAnchorAmounts(anchor.utxo()), contAnchorDatum)
                .payToContract(d.registryAddr(),
                        List.of(Amount.ada(2),
                                new Amount(d.listPolicyHex() + HexUtil.encodeHexString(nodeTokenName), BigInteger.ONE),
                                new Amount(d.zkPolicyHex() + HexUtil.encodeHexString(nullFull), BigInteger.ONE)),
                        newNodeDatum)
                .attachSpendingValidator(d.listScript());

        Result<String> result = new QuickTxBuilder(backendService)
                .compose(tx)
                .validTo(ttl)
                .withTxEvaluator(LocalJulcEvaluator.create(backendService))
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();
        if (!result.isSuccessful()) {
            throw new IllegalStateException("Ballot tx failed: " + result.getResponse());
        }
        log.info("Ballot submitted on-chain: tx={}", result.getValue());
        waitForTx(result.getValue());
        return result.getValue();
    }

    public boolean isNullifierUsed(ElectionService.ElectionConfig config, BigInteger nullifier) throws Exception {
        Deployment d = deploy(config);
        byte[] nullKey = nullifierKey(nullifier);
        for (var utxo : registryUtxos(d)) {
            byte[] tokenName = findToken(utxo, d.listPolicyHex());
            if (tokenName != null && !Arrays.equals(tokenName, ROOT_KEY)
                    && Arrays.equals(extractKey(tokenName), nullKey)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The ballot set {@code 𝔅} (ADR-0005 V11): the vote list walked from its root along
     * {@code nextKey}. Fails closed, never returning a subset, if the walk breaks, if any UTxO
     * holding a list token is not on the walk, or if a node is malformed. A node must hold exactly
     * one list token and exactly one nullifier token {@code N}, be keyed by the low 31 bytes of
     * {@code N}, and carry a ballot of canonical subgroup points. UTxOs at the address without a
     * list token are junk and are ignored.
     */
    public List<BallotNode> getBallots(ElectionService.ElectionConfig config) throws Exception {
        Deployment d = deploy(config);
        Map<String, Utxo> byListToken = new HashMap<>();
        for (var utxo : registryUtxos(d)) {
            var listTokens = tokensUnder(utxo, d.listPolicyHex());
            if (listTokens.isEmpty()) continue;
            if (listTokens.size() != 1 || listTokens.getFirst().quantity().compareTo(BigInteger.ONE) != 0) {
                throw new IllegalStateException("malformed list node " + utxo.getTxHash() + "#" + utxo.getOutputIndex());
            }
            if (byListToken.put(HexUtil.encodeHexString(listTokens.getFirst().name()), utxo) != null) {
                throw new IllegalStateException("list token held by two UTxOs");
            }
        }
        Utxo root = byListToken.get(HexUtil.encodeHexString(ROOT_KEY));
        ListDatum rootDatum = root == null ? null : elementDatum(root);
        if (rootDatum == null) throw new IllegalStateException("vote list root missing or malformed");

        List<BallotNode> nodes = new ArrayList<>();
        byte[] previous = new byte[0];
        byte[] next = rootDatum.nextKey();
        while (next.length > 0) {
            if (next.length != NULL_KEY_WIDTH || Arrays.compareUnsigned(previous, next) >= 0) {
                throw new IllegalStateException("vote list keys are not strictly increasing");
            }
            Utxo node = byListToken.get(HexUtil.encodeHexString(concat(PREFIX, next)));
            if (node == null) throw new IllegalStateException("vote list is broken at key " + HexUtil.encodeHexString(next));
            var nullifiers = tokensUnder(node, d.zkPolicyHex());
            if (nullifiers.size() != 1 || nullifiers.getFirst().quantity().compareTo(BigInteger.ONE) != 0
                    || nullifiers.getFirst().name().length != 32
                    || !Arrays.equals(Arrays.copyOfRange(nullifiers.getFirst().name(), 1, 32), next)) {
                throw new IllegalStateException("vote node " + HexUtil.encodeHexString(next) + " does not hold its nullifier");
            }
            ListDatum datum = elementDatum(node);
            if (datum == null || !(datum.userData() instanceof ConstrPlutusData ballot)
                    || ballot.getAlternative() != 0 || ballot.getData().getPlutusDataList().size() != 4) {
                throw new IllegalStateException("vote node " + HexUtil.encodeHexString(next) + " has no ballot");
            }
            var f = ballot.getData().getPlutusDataList();
            nodes.add(new BallotNode(nullifiers.getFirst().name(), JubjubElGamal.Ciphertext.fromAffine(
                    integer(f.get(0)), integer(f.get(1)), integer(f.get(2)), integer(f.get(3)))));
            previous = next;
            next = datum.nextKey();
        }
        if (nodes.size() + 1 != byListToken.size()) {
            throw new IllegalStateException("vote list walk covers " + (nodes.size() + 1) + " of "
                    + byListToken.size() + " list-token UTxOs");
        }
        return nodes;
    }

    /**
     * What a verifier needs to recompute this election's script hashes (ADR-0005 manifest):
     * the parameters come from the election configuration; the seed is the output that created
     * the list root.
     */
    public record ScriptBinding(String ballotPolicyId, String listPolicyId, String registryAddress, String seedRef) {}

    public ScriptBinding scriptBinding(ElectionService.ElectionConfig config) throws Exception {
        Deployment d = deploy(config);
        return new ScriptBinding(d.zkPolicyHex(), d.listPolicyHex(), d.registryAddr(), HexUtil.encodeHexString(d.seedRef()));
    }

    /** The ballot policy hash a verifier derives from the manifest alone. */
    public String recomputeBallotPolicyId(ElectionService.ElectionConfig config) throws Exception {
        return HexUtil.encodeHexString(ballotPolicy(config).getScriptHash());
    }

    /** The list policy hash a verifier derives from the manifest alone. */
    public String recomputeListPolicyId(ElectionService.ElectionConfig config, byte[] seedRef) throws Exception {
        return HexUtil.encodeHexString(listPolicy(ballotPolicy(config).getScriptHash(), seedRef).getScriptHash());
    }

    /** The chain's current POSIX time in milliseconds, from the latest block. */
    public long chainTimeMillis() throws Exception {
        var latest = backendService.getBlockService().getLatestBlock();
        if (!latest.isSuccessful() || latest.getValue() == null) {
            throw new IllegalStateException("Cannot read the latest block: " + latest.getResponse());
        }
        return latest.getValue().getTime() * 1000;
    }

    /** Whether {@code config}'s scripts are deployed (without deploying them). */
    public boolean isDeployed(ElectionService.ElectionConfig config) {
        return deployment != null && deployment.electionId().equals(config.electionId());
    }

    /** The parameter-applied scripts, CBOR hex: hash them to check the policy ids. */
    public record ScriptCbor(String ballotPolicy, String listPolicy) {}

    public ScriptCbor scriptCbor(ElectionService.ElectionConfig config) throws Exception {
        Deployment d = deploy(config);
        return new ScriptCbor(d.zkScript().getCborHex(), d.listScript().getCborHex());
    }

    /**
     * Whether the list root token was minted exactly once, with quantity 1, by a transaction that
     * spent the manifest's seed output. Binds the seed (and so the list policy) to chain data, not
     * to this process's memory. Reads the Blockfrost-shaped asset history and transaction UTxOs
     * that Yaci Store serves.
     */
    public boolean rootSpendsSeed(ElectionService.ElectionConfig config) throws Exception {
        Deployment d = deploy(config);
        String seedTx = HexUtil.encodeHexString(Arrays.copyOfRange(d.seedRef(), 0, 32));
        int seedIndex = ((d.seedRef()[32] & 0xff) << 8) | (d.seedRef()[33] & 0xff);
        String rootUnit = d.listPolicyHex() + HexUtil.encodeHexString(ROOT_KEY);

        String mintTx = null;
        int mints = 0;
        for (JsonNode event : getJson("assets/" + rootUnit + "/history")) {
            if (!"MINT".equals(event.path("mint_type").asText())) return false;   // never burned
            mints++;
            if (event.path("quantity").asLong() != 1) return false;
            mintTx = event.path("tx_hash").asText();
        }
        if (mints != 1) return false;
        for (JsonNode in : getJson("txs/" + mintTx + "/utxos").path("inputs")) {
            if (seedTx.equals(in.path("tx_hash").asText()) && in.path("output_index").asInt(-1) == seedIndex) {
                return true;
            }
        }
        return false;
    }

    private JsonNode getJson(String path) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(storeUrl + path)).GET().build();
        var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("GET " + path + " returned " + response.statusCode());
        }
        return JSON.readTree(response.body());
    }

    public String getRegistryAddress() {
        return deployment == null ? null : deployment.registryAddr();
    }

    public String getBallotPolicyId() {
        return deployment == null ? null : deployment.zkPolicyHex();
    }

    // ------------------------------------------------------------------
    //  Internals
    // ------------------------------------------------------------------

    /**
     * The last slot whose start time is at or before the deadline. The ledger turns the
     * transaction's TTL into the validity range's upper bound, which the ballot policy compares
     * with {@code votingDeadline}. Uses the latest block's (slot, time) pair and one-second slots.
     */
    private long deadlineSlot(long deadlineMillis) throws Exception {
        var latest = backendService.getBlockService().getLatestBlock();
        if (!latest.isSuccessful() || latest.getValue() == null) {
            throw new IllegalStateException("Cannot read the latest block: " + latest.getResponse());
        }
        long slot = latest.getValue().getSlot();
        long time = latest.getValue().getTime();
        long ttl = slot + (Math.floorDiv(deadlineMillis, 1000L) - time);
        if (ttl <= slot) {
            throw new IllegalStateException("Voting has closed");
        }
        return ttl;
    }

    private PlutusScript ballotPolicy(ElectionService.ElectionConfig config) {
        var vk = ProverToCardano.compressVk(circuitService.ballotSetup());
        var key = config.electionKey().normalized();
        return JulcScriptLoader.load(VoteZkMintingPolicy.class,
                BigIntPlutusData.of(config.electionId()),
                BigIntPlutusData.of(config.voterRoot()),
                BigIntPlutusData.of(key.affineU()),
                BigIntPlutusData.of(key.affineV()),
                BigIntPlutusData.of(config.votingDeadlineMillis()),
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                icData(vk.ic()));
    }

    private static PlutusScript listPolicy(byte[] zkPolicyHash, byte[] seedRef) {
        return JulcScriptLoader.load(VoteListValidator.class,
                new BytesPlutusData(ROOT_KEY),
                new BytesPlutusData(PREFIX),
                BigIntPlutusData.of(PREFIX_LEN),
                new BytesPlutusData(zkPolicyHash),
                new BytesPlutusData(seedRef));
    }

    private void deployRoot(Deployment d, Utxo seed) throws Exception {
        String rootTokenHex = HexUtil.encodeHexString(ROOT_KEY);
        var initRedeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(BigIntPlutusData.of(0))).build();
        var initTx = new ScriptTx()
                .collectFrom(seed)
                .mintAsset(d.listScript(), List.of(new Asset("0x" + rootTokenHex, BigInteger.ONE)), initRedeemer)
                .payToContract(d.registryAddr(),
                        List.of(Amount.ada(2), new Amount(d.listPolicyHex() + rootTokenHex, BigInteger.ONE)),
                        listElementDatum(ConstrPlutusData.of(0), new byte[0]));
        Result<String> result = new QuickTxBuilder(backendService)
                .compose(initTx)
                .withTxEvaluator(LocalJulcEvaluator.create(backendService))
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();
        if (!result.isSuccessful()) {
            throw new IllegalStateException("Vote list root deployment failed: " + result.getResponse());
        }
        log.info("Vote list root created: tx={}", result.getValue());
        waitForTx(result.getValue());
    }

    private List<Utxo> walletUtxos() throws Exception {
        var result = backendService.getUtxoService().getUtxos(adminAccount.baseAddress(), 20, 1);
        if (!result.isSuccessful() || result.getValue() == null || result.getValue().isEmpty()) {
            throw new IllegalStateException("No wallet UTxOs; top up " + adminAccount.baseAddress());
        }
        return result.getValue();
    }

    private List<Utxo> registryUtxos(Deployment d) throws Exception {
        List<Utxo> all = new ArrayList<>();
        for (int page = 1; ; page++) {
            var result = backendService.getUtxoService().getUtxos(d.registryAddr(), 100, page);
            if (!result.isSuccessful() || result.getValue() == null || result.getValue().isEmpty()) break;
            all.addAll(result.getValue());
            if (result.getValue().size() < 100) break;
        }
        return Collections.unmodifiableList(all);
    }

    private List<Amount> continuingAnchorAmounts(Utxo anchorUtxo) {
        List<Amount> amounts = new ArrayList<>();
        amounts.add(Amount.ada(2));
        for (var amount : anchorUtxo.getAmount()) {
            if (!"lovelace".equals(amount.getUnit())) {
                amounts.add(new Amount(amount.getUnit(), amount.getQuantity()));
            }
        }
        return amounts;
    }

    record AnchorInfo(Utxo utxo, byte[] tokenName, byte[] oldNextKey, PlutusData userData) {}

    record ListDatum(PlutusData userData, byte[] nextKey) {}

    /**
     * The node after which {@code newKey} belongs. Refuses a key that is already in the list
     * (a second ballot by the same voter) unless {@code predecessorOfDuplicate}, in which case it
     * returns the node that points at the existing key — the anchor a double-voter would have to
     * use, which the list script rejects.
     */
    private AnchorInfo findAnchor(Deployment d, List<Utxo> utxos, byte[] newKey, boolean predecessorOfDuplicate) {
        AnchorInfo found = null;
        for (var utxo : utxos) {
            byte[] tokenName = findToken(utxo, d.listPolicyHex());
            if (tokenName == null) continue;
            ListDatum datum = elementDatum(utxo);
            if (datum == null) continue;
            boolean isRoot = Arrays.equals(tokenName, ROOT_KEY);
            byte[] anchorKey = isRoot ? null : extractKey(tokenName);
            if (!isRoot && Arrays.equals(anchorKey, newKey)) {
                if (!predecessorOfDuplicate) {
                    throw new IllegalStateException("Nullifier already in the vote list — double vote attempt");
                }
                continue;
            }
            boolean leftOk = isRoot || Arrays.compareUnsigned(anchorKey, newKey) < 0;
            boolean rightOk = datum.nextKey().length == 0 || Arrays.compareUnsigned(newKey, datum.nextKey()) < 0;
            boolean pointsAtDuplicate = predecessorOfDuplicate && Arrays.equals(datum.nextKey(), newKey);
            if ((leftOk && rightOk) || pointsAtDuplicate) {
                found = new AnchorInfo(utxo, tokenName, datum.nextKey(), datum.userData());
            }
        }
        if (found == null) throw new IllegalStateException("No anchor found in the vote list");
        return found;
    }

    /** Test hook: the anchor a second ballot under an existing nullifier would have to use. */
    AnchorInfo anchorForDuplicate(ElectionService.ElectionConfig config, BigInteger nullifier) throws Exception {
        Deployment d = deploy(config);
        return findAnchor(d, registryUtxos(d), nullifierKey(nullifier), true);
    }

    /** Test hook: the honest anchor for {@code nullifier}. */
    AnchorInfo anchorFor(ElectionService.ElectionConfig config, BigInteger nullifier) throws Exception {
        Deployment d = deploy(config);
        return findAnchor(d, registryUtxos(d), nullifierKey(nullifier), false);
    }

    /** Test hook: the slot whose start is {@code posixMillis}, from the latest block. */
    long slotAt(long posixMillis) throws Exception {
        var latest = backendService.getBlockService().getLatestBlock();
        return latest.getValue().getSlot() + (Math.floorDiv(posixMillis, 1000L) - latest.getValue().getTime());
    }

    private static byte[] nullifierKey(BigInteger nullifier) {
        byte[] full = toFixedWidth(nullifier, 32);
        return Arrays.copyOfRange(full, 32 - NULL_KEY_WIDTH, 32);
    }

    record Token(byte[] name, BigInteger quantity) {}

    /** Every token (name and quantity) {@code utxo} holds under {@code policyHex}. */
    private static List<Token> tokensUnder(Utxo utxo, String policyHex) {
        List<Token> tokens = new ArrayList<>();
        if (utxo.getAmount() == null) return tokens;
        for (var amt : utxo.getAmount()) {
            String unit = amt.getUnit();
            if (unit != null && unit.startsWith(policyHex) && unit.length() >= policyHex.length()) {
                tokens.add(new Token(HexUtil.decodeHexString(unit.substring(policyHex.length())), amt.getQuantity()));
            }
        }
        return tokens;
    }

    private static byte[] findToken(Utxo utxo, String policyHex) {
        if (utxo.getAmount() == null) return null;
        for (var amt : utxo.getAmount()) {
            String unit = amt.getUnit();
            if (unit.startsWith(policyHex) && unit.length() > policyHex.length()) {
                return HexUtil.decodeHexString(unit.substring(policyHex.length()));
            }
        }
        return null;
    }

    private static byte[] extractKey(byte[] tokenName) {
        return Arrays.copyOfRange(tokenName, PREFIX.length, tokenName.length);
    }

    private static ListDatum elementDatum(Utxo utxo) {
        try {
            var inlineDatumHex = utxo.getInlineDatum();
            if (inlineDatumHex == null || inlineDatumHex.isEmpty()) return null;
            var data = PlutusData.deserialize(HexUtil.decodeHexString(inlineDatumHex));
            if (data instanceof ConstrPlutusData constr && constr.getAlternative() == 0) {
                var fields = constr.getData().getPlutusDataList();
                if (fields.size() == 2 && fields.get(1) instanceof BytesPlutusData next) {
                    return new ListDatum(fields.get(0), next.getValue());
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static BigInteger integer(PlutusData data) {
        if (data instanceof BigIntPlutusData i) return i.getValue();
        throw new IllegalArgumentException("expected an integer field");
    }

    /** {@code Ballot(Au, Av, Bu, Bv)} = {@code Constr 0 [I, I, I, I]}. */
    static ConstrPlutusData ballotDatum(JubjubElGamal.Ciphertext c) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                BigIntPlutusData.of(c.handle().affineU()),
                BigIntPlutusData.of(c.handle().affineV()),
                BigIntPlutusData.of(c.ballot().affineU()),
                BigIntPlutusData.of(c.ballot().affineV()))).build();
    }

    /** {@code ListElement(userData, nextKey)} = {@code Constr 0 [userData, B nextKey]}. */
    static ConstrPlutusData listElementDatum(PlutusData userData, byte[] nextKey) {
        return ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(userData, new BytesPlutusData(nextKey))).build();
    }

    /** {@code txId ‖ I2OSP2(index)}, as Julc's {@code ValuesLib.refBytes} encodes an output reference. */
    static byte[] seedRef(Utxo seed) {
        byte[] txId = HexUtil.decodeHexString(seed.getTxHash());
        int index = seed.getOutputIndex();
        return concat(txId, new byte[] {(byte) (index >>> 8), (byte) index});
    }

    static byte[] toFixedWidth(BigInteger value, int width) {
        byte[] raw = value.toByteArray();
        byte[] result = new byte[width];
        int srcStart = Math.max(0, raw.length - width);
        int count = Math.min(raw.length, width);
        System.arraycopy(raw, srcStart, result, width - count, count);
        return result;
    }

    private static ListPlutusData icData(List<byte[]> ic) {
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
            } catch (Exception ignored) {
                // not indexed yet
            }
        }
        log.warn("Tx confirmation timeout: {}", txHash);
    }
}
