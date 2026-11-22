package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.address.CredentialType;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.transaction.spec.Transaction;
import com.bloxbean.cardano.client.transaction.util.TransactionUtil;
import com.bloxbean.cardano.client.util.HexUtil;
import com.fasterxml.jackson.databind.JsonNode;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.usecases.airdrop.onchain.FaucetMintingPolicy;
import org.julclang.clientlib.JulcScriptLoader;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * On-chain airdrop service (ADR-0009 D3). Submits the Groth16 proof to the
 * {@link FaucetMintingPolicy}, which mints one receipt token named after the nullifier and
 * requires the payout to go to the proved recipient's key credential.
 *
 * <p><b>Deployment.</b> On first start the faucet picks a seed outref from its own (fresh,
 * random) admin wallet and records it, with the keys it was deployed with, in
 * {@code airdrop-deployment.json}. The seed fixes {@code deploymentId}, and with the configured
 * round {@code n} the policy's epoch domain tag ({@link AirdropEpoch}). A recorded deployment
 * whose keys differ from the loaded keys stops startup (fail closed).
 *
 * <p><b>One payout per nullifier.</b> Before signing a payout, the faucet refuses a nullifier
 * already in its {@link PaidNullifierLedger} or whose receipt was ever minted (Yaci Store's mint
 * history of the unit, wherever the receipt went), and records it durably. The faucet's ADA sits at the admin's key address, so only the admin's
 * signature can release it. The policy has no on-chain "minted once" state: a replay with the
 * claimant's own funds can mint a second receipt, but takes no faucet payout (receipt
 * uniqueness on-chain is deferred).
 */
@Service
public class OnChainAirdropService {

    private static final Logger log = LoggerFactory.getLogger(OnChainAirdropService.class);

    private final BackendService backendService;
    private final Account adminAccount;
    private final AirdropKeys keys;
    private final AirdropProofService proofService;
    private final PersonhoodIssuer issuer;
    private final PaidNullifierLedger ledger;
    private final Path deploymentFile;
    private final long round;
    private final long payoutLovelace;
    private final boolean topUpEnabled;
    private final String adminUrl;
    private final int topUpAda;
    private final ClaimChain chain;

    private PlutusScript mintingScript;
    private String policyHex;
    private String receiptAddress;
    private BigInteger policyEpoch;
    private Deployment deployment;
    private boolean initialized;

    public OnChainAirdropService(BackendService backendService, AirdropKeys keys,
                                 AirdropProofService proofService, PersonhoodIssuer issuer,
                                 PaidNullifierLedger ledger, AirdropDataDir data,
                                 @Value("${faucet.round}") long round,
                                 @Value("${faucet.ada-per-claim}") int adaPerClaim,
                                 @Value("${demo.topup.enabled:true}") boolean topUpEnabled,
                                 @Value("${cardano.yaci.admin-url:http://localhost:10000}") String adminUrl,
                                 @Value("${faucet.admin-topup-ada:1000}") int topUpAda,
                                 @Value("${cardano.blockfrost.base-url:}") String storeUrlOverride,
                                 @Value("${cardano.yaci.base-url:http://localhost:8080/api/v1/}") String storeUrl) {
        this(backendService, keys, proofService, issuer, ledger, data, round, adaPerClaim, topUpEnabled, adminUrl,
                topUpAda, new ClaimChain.Backend(backendService,
                        storeUrlOverride != null && !storeUrlOverride.isBlank() ? storeUrlOverride : storeUrl));
    }

    OnChainAirdropService(BackendService backendService, AirdropKeys keys,
                          AirdropProofService proofService, PersonhoodIssuer issuer,
                          PaidNullifierLedger ledger, AirdropDataDir data, long round, int adaPerClaim,
                          boolean topUpEnabled, String adminUrl, int topUpAda, ClaimChain chain) {
        if (round < 1 || round >= AirdropEpoch.MAX_ROUND_EXCLUSIVE) {
            throw new IllegalArgumentException("faucet.round must satisfy 1 ≤ n < 2^32: " + round);
        }
        if (adaPerClaim < 1) {
            throw new IllegalArgumentException("faucet.ada-per-claim must be at least 1");
        }
        this.backendService = backendService;
        this.keys = keys;
        this.adminAccount = keys.admin();
        this.proofService = proofService;
        this.issuer = issuer;
        this.ledger = ledger;
        this.deploymentFile = data.deployment();
        this.round = round;
        this.payoutLovelace = adaPerClaim * 1_000_000L;
        this.topUpEnabled = topUpEnabled;
        this.adminUrl = adminUrl;
        this.topUpAda = topUpAda;
        this.chain = chain;
    }

    /**
     * Loads (and checks) the recorded deployment, or deploys. A recorded deployment that does not
     * match the loaded keys stops startup. If the chain is not reachable yet, the first deployment
     * is retried on the first claim.
     */
    @PostConstruct
    public synchronized void initialize() throws Exception {
        if (initialized) return;
        deployment = loadDeployment();
        if (deployment == null && ledger.size() > 0) {
            // Paid nullifiers without the deployment they were paid under: redeploying would
            // pick a new seed, a new epoch and fresh nullifiers for every holder.
            throw new IllegalStateException(deploymentFile + " is missing but paid nullifiers are recorded;"
                    + " refusing to redeploy. Reset keys and state together with ./demo.sh airdrop --clean-cache.");
        }
        if (topUpEnabled) {
            topUpAdmin();
        }
        if (deployment == null) {
            try {
                deployment = deploy();
            } catch (ChainUnavailableException e) {
                log.warn("Faucet not deployed yet ({}); will retry on the first claim", e.getMessage());
                return;
            }
        }
        compilePolicy();
        initialized = true;
    }

    private void compilePolicy() throws Exception {
        log.info("Compiling faucet minting policy (with on-chain Groth16 verification)...");
        var vk = ProofCompressor.compressVk(proofService.getSetupResult());
        var issuerPk = issuer.publicKey();
        policyEpoch = AirdropEpoch.policyEpoch(deployment.deploymentId(), round);

        mintingScript = JulcScriptLoader.load(FaucetMintingPolicy.class,
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()),
                BigIntPlutusData.of(issuerPk.affineU()),
                BigIntPlutusData.of(issuerPk.affineV()),
                BigIntPlutusData.of(policyEpoch),
                BigIntPlutusData.of(BigInteger.valueOf(payoutLovelace)));

        policyHex = HexUtil.encodeHexString(mintingScript.getScriptHash());
        receiptAddress = AddressProvider.getEntAddress(mintingScript, Networks.testnet()).toBech32();
        log.info("Faucet minting policy: {} (seed {}#{}, round {})", policyHex,
                deployment.seedTxHash(), deployment.seedIndex(), round);
    }

    /**
     * Submits an airdrop claim: mints one receipt (asset name = nullifier) under the faucet
     * policy, with the public inputs in its inline datum, and pays {@code payout} lovelace to
     * {@code recipientAddressBech32}, whose payment credential must be a key hash.
     *
     * @return Cardano tx hash
     * @throws PaidNullifierLedger.AlreadyPaidException if the nullifier was already paid or receipted
     */
    public String submitClaim(Groth16ProofBLS381 proof, BigInteger nullifier,
                              String recipientAddressBech32) throws Exception {
        ensureInitialized();
        byte[] recipientKeyHash = recipientKeyHash(recipientAddressBech32);
        String txHash = payOnce(policyHex + PaidNullifierLedger.key(nullifier), nullifier, () -> {
            Transaction signed = new QuickTxBuilder(backendService)
                    .compose(claimTx(ProofCompressor.compressProof(proof), nullifier,
                            recipientKeyHash, recipientAddressBech32))
                    .withTxEvaluator(LocalJulcEvaluator.create(backendService))
                    .withSigner(SignerProviders.signerFrom(adminAccount))
                    .feePayer(adminAccount.baseAddress())
                    .collateralPayer(adminAccount.baseAddress())
                    .buildAndSign();
            return new SignedClaim(signed.serialize(), TransactionUtil.getTxHash(signed));
        });
        waitForTx(txHash);
        return txHash;
    }

    /** A signed claim transaction, not yet submitted. */
    record SignedClaim(byte[] cbor, String txHash) {}

    /** Builds and signs a claim; called only after its nullifier is reserved. */
    interface ClaimSigner {
        SignedClaim buildAndSign() throws Exception;
    }

    /**
     * Pays {@code nullifier} at most once (ADR-0009 D3.5):
     * <ol>
     *   <li>refuse it if the ledger records it, or if its receipt {@code receiptUnit} was ever
     *       minted (any address; the lookup failing also refuses);</li>
     *   <li>record it durably, then build and sign the payout;</li>
     *   <li>release the record only if no signed transaction was submitted (build or signing
     *       failed), or if the node gave a definitive validation rejection and the transaction
     *       is not on-chain. A transport error, a duplicate or mempool answer, any other
     *       rejection, or a failed lookup keeps the record (fail closed).</li>
     * </ol>
     */
    String payOnce(String receiptUnit, BigInteger nullifier, ClaimSigner signer) throws Exception {
        String nullifierHex = PaidNullifierLedger.key(nullifier);
        synchronized (this) {
            if (ledger.isRecorded(nullifier) || chain.receiptMinted(receiptUnit)) {
                throw new PaidNullifierLedger.AlreadyPaidException(nullifier);
            }
            // Recorded before the payout is signed.
            ledger.reserve(nullifier);
            log.info("Submitting airdrop claim: nullifier={}...", nullifierHex.substring(0, 16));

            SignedClaim signed;
            try {
                signed = signer.buildAndSign();
            } catch (Exception e) {
                // Nothing signed left the faucet.
                ledger.release(nullifier);
                throw e;
            }
            Result<String> result = chain.submit(signed.cbor());   // a throw keeps the record
            if (!result.isSuccessful()) {
                if (definitiveRejection(result) && notOnChain(signed.txHash())) {
                    ledger.release(nullifier);
                    log.info("Claim rejected by the node; nullifier {}... released", nullifierHex.substring(0, 16));
                } else {
                    log.warn("Claim submission outcome unknown; nullifier {}... stays recorded", nullifierHex.substring(0, 16));
                }
                throw new RuntimeException("Claim submission failed: " + result.getResponse());
            }
            ledger.markPaid(nullifier, signed.txHash());
            log.info("Airdrop claim submitted: nullifier={}..., tx={}", nullifierHex.substring(0, 16), signed.txHash());
            return signed.txHash();
        }
    }

    /** Ledger validation failures: the node refused the transaction and does not hold it. */
    private static final List<String> DEFINITIVE = List.of(
            "ApplyTxError", "UtxowFailure", "UtxoFailure", "BadInputsUTxO", "ValueNotConservedUTxO",
            "MissingVKeyWitnesses", "FeeTooSmallUTxO", "OutsideValidityIntervalUTxO", "ScriptFailure",
            "PlutusFailure", "ValidationTagMismatch", "ExtraneousScriptWitnesses");

    /** Answers that may mean the transaction was, or still may be, accepted. */
    private static final List<String> AMBIGUOUS = List.of(
            "mempool", "already", "duplicate", "known", "timeout", "timed out");

    /**
     * An HTTP 400 whose body names a ledger validation failure and nothing that could mean the
     * transaction is already known or still pending.
     */
    static boolean definitiveRejection(Result<String> result) {
        if (result.code() != 400) return false;
        String body = String.valueOf(result.getResponse());
        String lower = body.toLowerCase(Locale.ROOT);
        for (String marker : AMBIGUOUS) {
            if (lower.contains(marker)) return false;
        }
        for (String marker : DEFINITIVE) {
            if (body.contains(marker)) return true;
        }
        return false;
    }

    private boolean notOnChain(String txHash) {
        try {
            return !chain.txOnChain(txHash);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * The claim transaction body: mint the receipt to the receipt address with the public inputs
     * as its datum, and pay {@code payout} to the recipient. Inputs, fee and signer are the
     * caller's (the faucet's admin wallet in {@link #submitClaim}).
     */
    ScriptTx claimTx(SnarkjsToCardano.ProofCompressed compressed,
                     BigInteger nullifier, byte[] recipientKeyHash, String recipientAddressBech32) {
        return claimTx(compressed, nullifier, recipientKeyHash, recipientAddressBech32, receiptAddress);
    }

    /** As {@link #claimTx}, with the receipt sent to {@code receiptTo} (tests send it elsewhere). */
    ScriptTx claimTx(SnarkjsToCardano.ProofCompressed compressed, BigInteger nullifier,
                     byte[] recipientKeyHash, String recipientAddressBech32, String receiptTo) {
        var pk = issuer.publicKey();
        var redeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressed.piA()),
                        new BytesPlutusData(compressed.piB()),
                        new BytesPlutusData(compressed.piC())))
                .build();

        // Datum: 6 public inputs [pkU, pkV, epoch, nullifier, recipient, eligible].
        var datum = ListPlutusData.of(
                BigIntPlutusData.of(pk.affineU()),
                BigIntPlutusData.of(pk.affineV()),
                BigIntPlutusData.of(policyEpoch),
                BigIntPlutusData.of(nullifier),
                BigIntPlutusData.of(new BigInteger(1, recipientKeyHash)),
                BigIntPlutusData.of(BigInteger.ONE)); // eligible

        String tokenNameHex = PaidNullifierLedger.key(nullifier);
        var receipt = new Asset("0x" + tokenNameHex, BigInteger.ONE);
        return new ScriptTx()
                .mintAsset(mintingScript, List.of(receipt), redeemer)
                .payToContract(receiptTo,
                        List.of(Amount.ada(2), new Amount(policyHex + tokenNameHex, BigInteger.ONE)),
                        datum)
                .payToAddress(recipientAddressBech32, Amount.lovelace(BigInteger.valueOf(payoutLovelace)));
    }

    /**
     * The recipient's 28-byte payment key hash. Only addresses whose payment credential is a key
     * hash are accepted; a script credential, a stake address or a Byron address is refused, with
     * no fallback (ADR-0009 D3.4).
     */
    public static byte[] recipientKeyHash(String addressBech32) {
        Address addr;
        try {
            addr = new Address(addressBech32);
        } catch (Exception e) {
            throw new IllegalArgumentException("recipient is not a Shelley address: " + addressBech32);
        }
        var credential = addr.getPaymentCredential()
                .orElseThrow(() -> new IllegalArgumentException("recipient has no payment credential"));
        if (credential.getType() != CredentialType.Key) {
            throw new IllegalArgumentException("recipient's payment credential must be a key hash, not a script");
        }
        byte[] hash = credential.getBytes();
        if (hash == null || hash.length != 28) {
            throw new IllegalArgumentException("recipient's payment key hash must be 28 bytes");
        }
        return hash;
    }

    /** Whether the faucet has recorded {@code nullifier} as paid. */
    public boolean alreadyClaimed(BigInteger nullifier) {
        return ledger.isRecorded(nullifier);
    }

    public int totalClaims() {
        return ledger.size();
    }

    public String getPolicyId() {
        return policyHex;
    }

    PlutusScript mintingScript() {
        return mintingScript;
    }

    /** The policy's epoch domain tag, or {@code null} before deployment. */
    public BigInteger getPolicyEpoch() {
        return policyEpoch;
    }

    public long getRound() {
        return round;
    }

    public long getPayoutLovelace() {
        return payoutLovelace;
    }

    public String getAdminAddress() {
        return adminAccount.baseAddress();
    }

    private void ensureInitialized() throws Exception {
        if (!initialized) initialize();
        if (!initialized) throw new IllegalStateException("The faucet is not deployed yet (chain unreachable)");
    }

    // ------------------------------------------------------------------
    //  Deployment state

    /** The faucet's seed outref and the keys it was deployed with. */
    record Deployment(String seedTxHash, int seedIndex, String issuerPkU, String issuerPkV, String adminKeyHash) {
        BigInteger deploymentId() {
            return AirdropEpoch.deploymentId(seedTxHash, seedIndex);
        }
    }

    private Deployment loadDeployment() {
        JsonNode node = DemoFiles.read(deploymentFile);
        if (node == null) return null;
        Deployment d;
        try {
            d = new Deployment(DemoFiles.text(node, "seedTxHash", deploymentFile),
                    Integer.parseInt(DemoFiles.text(node, "seedIndex", deploymentFile)),
                    DemoFiles.text(node, "issuerPkU", deploymentFile),
                    DemoFiles.text(node, "issuerPkV", deploymentFile),
                    DemoFiles.text(node, "adminKeyHash", deploymentFile));
            d.deploymentId();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(deploymentFile + " is corrupt", e);
        }
        var pk = issuer.publicKey();
        boolean matches = d.issuerPkU().equals(pk.affineU().toString(16))
                && d.issuerPkV().equals(pk.affineV().toString(16))
                && d.adminKeyHash().equals(HexUtil.encodeHexString(keys.adminKeyHash()));
        if (!matches) {
            throw new IllegalStateException("The recorded airdrop deployment (" + deploymentFile + ") was made with"
                    + " other keys than the ones loaded; refusing to start. Restore the keys, or reset keys and"
                    + " state together with ./demo.sh airdrop --clean-cache.");
        }
        log.info("Loaded airdrop deployment: seed {}#{}", d.seedTxHash(), d.seedIndex());
        return d;
    }

    /**
     * Picks the seed: an outref at the faucet's own admin address. The admin key is fresh per
     * deployment, so no other deployment can pick the same outref.
     */
    private Deployment deploy() throws Exception {
        Utxo seed = null;
        for (int attempt = 0; attempt < 30 && seed == null; attempt++) {
            Result<List<Utxo>> utxos;
            try {
                utxos = backendService.getUtxoService().getUtxos(adminAccount.baseAddress(), 100, 1);
            } catch (Exception e) {
                throw new ChainUnavailableException(e.getMessage());
            }
            if (utxos.isSuccessful() && utxos.getValue() != null && !utxos.getValue().isEmpty()) {
                seed = utxos.getValue().stream()
                        .min(Comparator.comparing(Utxo::getTxHash).thenComparingInt(Utxo::getOutputIndex))
                        .orElseThrow();
            } else if (!topUpEnabled) {
                break;
            } else {
                Thread.sleep(2_000);
            }
        }
        if (seed == null) {
            throw new ChainUnavailableException("the faucet admin wallet " + adminAccount.baseAddress()
                    + " has no UTxO to use as the deployment seed; fund it");
        }
        var pk = issuer.publicKey();
        var d = new Deployment(seed.getTxHash(), seed.getOutputIndex(),
                pk.affineU().toString(16), pk.affineV().toString(16),
                HexUtil.encodeHexString(keys.adminKeyHash()));
        var out = DemoFiles.object();
        out.put("seedTxHash", d.seedTxHash());
        out.put("seedIndex", Integer.toString(d.seedIndex()));
        out.put("issuerPkU", d.issuerPkU());
        out.put("issuerPkV", d.issuerPkV());
        out.put("adminKeyHash", d.adminKeyHash());
        DemoFiles.writeAtomic(deploymentFile, out);
        log.info("Deployed the airdrop faucet: seed {}#{} → {}", d.seedTxHash(), d.seedIndex(), deploymentFile);
        return d;
    }

    /** Funds the faucet admin wallet through Yaci DevKit's top-up API (devnet only). */
    private void topUpAdmin() {
        try {
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(adminUrl + "/local-cluster/api/addresses/topup"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "{\"address\":\"" + adminAccount.baseAddress() + "\",\"adaAmount\":" + topUpAda + "}"))
                    .build();
            var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            log.info("Topped up the faucet admin wallet {} with {} ADA (HTTP {})",
                    adminAccount.baseAddress(), topUpAda, response.statusCode());
        } catch (Exception e) {
            log.warn("DevKit top-up of the faucet admin wallet failed: {}", e.getMessage());
        }
    }

    private static ListPlutusData vkIcData(List<byte[]> ic) {
        PlutusData[] values = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) {
            values[i] = new BytesPlutusData(ic.get(i));
        }
        return ListPlutusData.of(values);
    }

    private void waitForTx(String txHash) {
        try {
            for (int i = 0; i < 60; i++) {
                Thread.sleep(1000);
                var r = backendService.getTransactionService().getTransaction(txHash);
                if (r != null && r.isSuccessful() && r.getValue() != null) return;
            }
        } catch (Exception ignored) {}
    }

    private static final class ChainUnavailableException extends Exception {
        ChainUnavailableException(String message) {
            super(message);
        }
    }
}
