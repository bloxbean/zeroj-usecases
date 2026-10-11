package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.TxSigner;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.metadata.cbor.CBORMetadata;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.dpp.config.CardanoConfig;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.Claim;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportDatum;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportReader;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportScript;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportTransactions;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.RoleKeys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The passport policy on chain (ADR-0009 D1): one {@code DppPassport} instance for this
 * manufacturer and auditor, gating the carbon claim at the configured threshold. Issues and
 * revokes passports, and reads them back from the chain as a reader would.
 */
@Service
public class OnChainDppService {

    private static final Logger log = LoggerFactory.getLogger(OnChainDppService.class);
    private static final BigInteger MIN_BALANCE = BigInteger.valueOf(20_000_000);

    private final BackendService backendService;
    private final Account fundingAccount;
    private final RoleKeys roleKeys;
    private final DppCircuitService circuitService;
    private final ComplianceService complianceService;
    private final CardanoConfig cardanoConfig;

    @Value("${cardano.network}")
    private String network;

    @Value("${cardano.yaci.admin-url}")
    private String adminUrl;

    @Value("${dpp.topup-enabled:true}")
    private boolean topupEnabled;

    private PassportScript script;

    public OnChainDppService(BackendService backendService, Account adminAccount, RoleKeys roleKeys,
                             DppCircuitService circuitService, ComplianceService complianceService,
                             CardanoConfig cardanoConfig) {
        this.backendService = backendService;
        this.fundingAccount = adminAccount;
        this.roleKeys = roleKeys;
        this.circuitService = circuitService;
        this.complianceService = complianceService;
        this.cardanoConfig = cardanoConfig;
    }

    @PostConstruct
    public void init() {
        var vk = circuitService.circuits().circuit(Claim.CARBON).compressedVk();
        script = new PassportScript(RoleKeys.pkh(roleKeys.manufacturer()), RoleKeys.pkh(roleKeys.auditor()),
                Claim.CARBON, complianceService.carbonThreshold(), vk, Networks.testnet());
        // Fail closed if this deployment's policy differs from the one already recorded.
        roleKeys.bindPolicy(script.policyId());
        log.info("Passport policy (and address) {}: {}", script.policyId(), script.address());
    }

    public PassportScript script() { return script; }

    /** A minted passport: its transaction and output index. */
    public record Issued(String txHash, int outputIndex) {}

    /**
     * Submits the passport transaction: the manufacturer builds and signs, {@code auditorSigner}
     * co-signs. Throws with the script evaluator's message if the policy refuses it.
     */
    public Issued issue(PassportDatum datum, Groth16ProofBLS381 proof, TxSigner auditorSigner) throws Exception {
        ensureFunded(roleKeys.manufacturer());
        Result<String> result = PassportTransactions.issue(backendService, script, roleKeys.manufacturer(),
                auditorSigner, datum, proof);
        if (!result.isSuccessful()) throw new IllegalStateException("Mint failed: " + result.getResponse());
        String txHash = result.getValue();
        waitForTx(txHash);
        Utxo passport = findPassport(datum.productId())
                .orElseThrow(() -> new IllegalStateException("passport output not found after " + txHash));
        log.info("Passport minted for {}: {}#{}", new String(datum.productId()), txHash, passport.getOutputIndex());
        return new Issued(txHash, passport.getOutputIndex());
    }

    /** The auditor revokes a passport: spends it and burns its token. */
    public String revoke(byte[] productId) throws Exception {
        ensureFunded(roleKeys.auditor());
        Utxo passport = findPassport(productId).orElseThrow(() -> new IllegalStateException("no passport on chain"));
        Result<String> result = PassportTransactions.revoke(backendService, script, roleKeys.auditor(), passport, productId);
        if (!result.isSuccessful()) throw new IllegalStateException("Revoke failed: " + result.getResponse());
        waitForTx(result.getValue());
        return result.getValue();
    }

    /**
     * The passport UTxO for {@code productId}: the token found at the passport address, never
     * elsewhere. Throws if more than one is there, or if any page cannot be read.
     */
    public Optional<Utxo> findPassport(byte[] productId) throws Exception {
        String unit = script.unit(productId);
        List<Utxo> found = new ArrayList<>();
        for (int page = 1; ; page++) {
            var result = backendService.getUtxoService().getUtxos(script.address(), 100, page);
            if (!result.isSuccessful()) {
                // An address without UTxOs is a 404 on Blockfrost-compatible APIs; anything else is an error.
                if (result.code() == 404) break;
                throw new IllegalStateException("cannot read the passport address: " + result.getResponse());
            }
            if (result.getValue() == null || result.getValue().isEmpty()) break;
            for (Utxo u : result.getValue()) {
                if (u.getAmount().stream().anyMatch(a -> a.getUnit().equals(unit))) found.add(u);
            }
            if (result.getValue().size() < 100) break;
        }
        if (found.size() > 1) throw new IllegalStateException("more than one passport for this product at the passport address");
        return found.stream().findFirst();
    }

    /** The passport datum of an on-chain passport. */
    public static PassportDatum datumOf(Utxo passport) throws Exception {
        if (passport.getInlineDatum() == null) throw new IllegalStateException("passport without an inline datum");
        return PassportDatum.fromPlutusData(PlutusData.deserialize(HexUtil.decodeHexString(passport.getInlineDatum())));
    }

    /** The policy's complete mint history for {@code productId}, from the chain indexer; throws if unavailable. */
    public List<PassportReader.MintEvent> mintHistory(byte[] productId) {
        return PassportReader.fetchHistory(cardanoConfig.indexerBaseUrl(), script.unit(productId));
    }

    /** Anchors the registry root on chain in the metadata of a funding-wallet transaction (label 7270). */
    public String anchorRoot(byte[] root, long count) throws Exception {
        CBORMetadata metadata = new CBORMetadata();
        metadata.put(BigInteger.valueOf(7270), HexUtil.encodeHexString(root));
        var tx = new Tx()
                .payToAddress(fundingAccount.baseAddress(), Amount.ada(1))
                .attachMetadata(metadata)
                .from(fundingAccount.baseAddress());
        var result = new QuickTxBuilder(backendService).compose(tx)
                .withSigner(SignerProviders.signerFrom(fundingAccount)).complete();
        if (!result.isSuccessful()) throw new IllegalStateException("Anchor failed: " + result.getResponse());
        waitForTx(result.getValue());
        log.info("Registry root anchored: tx={} ({} passports)", result.getValue(), count);
        return result.getValue();
    }

    // ------------------------------------------------------------------ funding

    /**
     * Funds a random role wallet when it runs low: through DevKit's top-up endpoint on DevKit,
     * otherwise from the funding wallet.
     */
    private void ensureFunded(Account account) throws Exception {
        if (lovelace(account.baseAddress()).compareTo(MIN_BALANCE) >= 0) return;
        if (topupEnabled && "yaci".equals(network)) {
            log.info("Topping up {} through DevKit", account.baseAddress());
            var request = HttpRequest.newBuilder()
                    .uri(URI.create(adminUrl + "/local-cluster/api/addresses/topup"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "{\"address\":\"" + account.baseAddress() + "\",\"adaAmount\":1000}"))
                    .build();
            HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } else {
            log.info("Funding {} from the funding wallet", account.baseAddress());
            var tx = new Tx().payToAddress(account.baseAddress(), Amount.ada(100)).from(fundingAccount.baseAddress());
            var result = new QuickTxBuilder(backendService).compose(tx)
                    .withSigner(SignerProviders.signerFrom(fundingAccount)).complete();
            if (!result.isSuccessful()) throw new IllegalStateException("Funding failed: " + result.getResponse());
            waitForTx(result.getValue());
        }
        for (int i = 0; i < 30 && lovelace(account.baseAddress()).compareTo(MIN_BALANCE) < 0; i++) Thread.sleep(2000);
    }

    private BigInteger lovelace(String address) throws Exception {
        BigInteger total = BigInteger.ZERO;
        for (int page = 1; ; page++) {
            var result = backendService.getUtxoService().getUtxos(address, 100, page);
            if (!result.isSuccessful() || result.getValue() == null || result.getValue().isEmpty()) break;
            for (Utxo u : result.getValue()) {
                for (Amount a : u.getAmount()) {
                    if ("lovelace".equals(a.getUnit())) total = total.add(a.getQuantity());
                }
            }
            if (result.getValue().size() < 100) break;
        }
        return total;
    }

    private void waitForTx(String txHash) throws Exception {
        for (int i = 0; i < 40; i++) {
            Thread.sleep(2000);
            try {
                var r = backendService.getTransactionService().getTransaction(txHash);
                if (r.isSuccessful() && r.getValue() != null) { log.info("Confirmed: {}", txHash); return; }
            } catch (Exception ignored) {
                // not indexed yet
            }
        }
        throw new IllegalStateException("transaction not confirmed: " + txHash);
    }
}
