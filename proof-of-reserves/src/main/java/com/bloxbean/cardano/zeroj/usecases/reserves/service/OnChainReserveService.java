package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
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
import com.bloxbean.cardano.zeroj.usecases.reserves.config.CustodianKeyStore;
import com.bloxbean.cardano.zeroj.usecases.reserves.config.DeploymentState;
import com.bloxbean.cardano.zeroj.usecases.reserves.onchain.ReserveAttestation;
import com.bloxbean.cardano.zeroj.usecases.reserves.verify.YaciStoreIndexer;
import jakarta.annotation.PostConstruct;
import org.julclang.clientlib.JulcScriptLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Publishes and releases {@link ReserveAttestation} tokens (ADR-0009 D4).
 *
 * <p>An attestation is one transaction: the custodian signs, mints {@code {I2OSP8(period): 1}} with
 * the solvency proof as the redeemer, and locks the token at the script address with the inline
 * datum {@code Attestation(period, liabilitiesRoot, totalLiabilities, totalReserves)}. The script
 * verifies the proof against that datum, so there is no separate lock-then-verify step and a datum
 * without the token proves nothing.
 *
 * <p>The deployment (custodian key hash, {@code genesisMs}, {@code periodMs}, policy id) is
 * persisted with the custodian key (ADR-0009 D11). A restart must reproduce the same policy id;
 * otherwise startup fails closed.
 */
@Service
public class OnChainReserveService {

    private static final Logger log = LoggerFactory.getLogger(OnChainReserveService.class);
    private static final BigInteger LOCKED_LOVELACE = BigInteger.valueOf(3_000_000);

    private final BackendService backendService;
    private final Account custodian;
    private final ReserveCircuitService circuitService;
    private final Path dataDir;
    private final long configuredPeriodMs;
    private final String indexerUrl;
    private final String adminUrl;
    private final boolean topUpEnabled;

    private PlutusScript script;
    private String scriptAddr;
    private String policyId;
    private DeploymentState deployment;
    private boolean funded;
    private Callable<Long> genesisClock = this::chainTimeMs;

    public OnChainReserveService(BackendService backendService, Account custodianAccount,
                                 ReserveCircuitService circuitService,
                                 @Value("${demo.data-dir:./data}") String dataDir,
                                 @Value("${reserves.period-ms:300000}") long periodMs,
                                 @Value("${cardano.yaci.base-url}") String indexerUrl,
                                 @Value("${cardano.yaci.admin-url:http://localhost:10000}") String adminUrl,
                                 @Value("${demo.topup.enabled:true}") boolean topUpEnabled) {
        this.backendService = backendService;
        this.custodian = custodianAccount;
        this.circuitService = circuitService;
        this.dataDir = Path.of(dataDir);
        this.configuredPeriodMs = periodMs;
        this.indexerUrl = indexerUrl;
        this.adminUrl = adminUrl;
        this.topUpEnabled = topUpEnabled;
    }

    /**
     * Loads the deployment or creates it. Existing state must match the custodian key and must
     * reproduce its policy id with the current verification key; anything else stops startup.
     */
    @PostConstruct
    public synchronized void initialize() throws Exception {
        if (script != null) return;
        String pkh = CustodianKeyStore.keyHash(custodian);
        DeploymentState existing = DeploymentState.exists(dataDir) ? DeploymentState.read(dataDir) : null;
        // Periods are judged against chain time (validity bounds, the customer check), so a new
        // deployment starts its clock at the chain tip, not at this host's clock.
        long genesisMs = existing != null ? existing.genesisMs() : genesisClock.call();
        long periodMs = existing != null ? existing.periodMs() : configuredPeriodMs;
        if (existing != null && existing.periodMs() != configuredPeriodMs) {
            log.warn("reserves.period-ms={} differs from the deployed periodMs={}; keeping the deployed value",
                    configuredPeriodMs, existing.periodMs());
        }

        log.info("Compiling reserve attestation script...");
        PlutusScript compiled = script(pkh, genesisMs, periodMs);
        String compiledPolicy = HexUtil.encodeHexString(compiled.getScriptHash());
        DeploymentState state = new DeploymentState(pkh, genesisMs, periodMs, compiledPolicy);
        if (existing != null) {
            if (!existing.equals(state)) {
                throw new IllegalStateException("The reserves deployment in " + dataDir + " (policy "
                        + existing.policyId() + ") does not match this custodian key and verification key (policy "
                        + compiledPolicy + "). Reset with ./demo.sh proof-of-reserves --clean-cache.");
            }
        } else {
            state.write(dataDir);
        }
        deployment = state;
        script = compiled;
        policyId = compiledPolicy;
        scriptAddr = AddressProvider.getEntAddress(compiled, Networks.testnet()).toBech32();
        log.info("Attestation policy {} at {} (period {} ms from {})", policyId, scriptAddr, periodMs, genesisMs);
    }

    /** Tests only: the clock a new deployment takes {@code genesisMs} from (default: the chain tip). */
    void useGenesisClock(Callable<Long> clock) {
        this.genesisClock = clock;
    }

    /** {@code ReserveAttestation} applied to the custodian, the clock and the solvency VK. */
    PlutusScript script(String custodianPkh, long genesisMs, long periodMs) {
        var vk = ProverToCardano.compressVk(circuitService.getSetupResult());
        return JulcScriptLoader.load(ReserveAttestation.class,
                new BytesPlutusData(HexUtil.decodeHexString(custodianPkh)),
                BigIntPlutusData.of(genesisMs),
                BigIntPlutusData.of(periodMs),
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                icData(vk.ic()));
    }

    /**
     * Mints the attestation for {@code period}. Refuses a period whose token already has mint
     * history: a second attestation would make every customer check refuse the period.
     */
    public String publishAttestation(Groth16ProofBLS381 proof, long period,
                                     BigInteger totalReserves, BigInteger liabilitiesRoot,
                                     BigInteger totalLiabilities) throws Exception {
        ensureFunded();
        String tokenHex = HexUtil.encodeHexString(AttestationPeriods.tokenName(period));
        String unit = policyId + tokenHex;
        if (!new YaciStoreIndexer(indexerUrl).assetHistory(unit, 1, 1).isEmpty()) {
            throw new AlreadyAttestedException("Period " + period + " is already attested; the next period starts at "
                    + periods().end(period) + " (POSIX ms)");
        }
        log.info("Minting attestation for period {}...", period);
        PlutusData datum = attestationDatum(period, liabilitiesRoot, totalLiabilities, totalReserves);
        var compressed = ProverToCardano.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressed.piA()),
                        new BytesPlutusData(compressed.piB()),
                        new BytesPlutusData(compressed.piC())))
                .build();
        var tx = new ScriptTx()
                .mintAsset(script, List.of(new Asset("0x" + tokenHex, BigInteger.ONE)), redeemer)
                .payToContract(scriptAddr, List.of(Amount.lovelace(LOCKED_LOVELACE), new Amount(unit, BigInteger.ONE)), datum);
        String txHash = submit(tx, null);
        log.info("Attestation minted for period {}: tx={}", period, txHash);
        return txHash;
    }

    /**
     * Burns {@code period}'s attestation and releases its lovelace. The script accepts only a
     * transaction whose validity starts at or after the period's end, so this waits for it.
     */
    public String releaseAttestation(long period) throws Exception {
        ensureFunded();
        String tokenHex = HexUtil.encodeHexString(AttestationPeriods.tokenName(period));
        String unit = policyId + tokenHex;
        Utxo locked = null;
        var utxos = backendService.getUtxoService().getUtxos(scriptAddr, 100, 1);
        if (utxos.isSuccessful() && utxos.getValue() != null) {
            for (Utxo u : utxos.getValue()) {
                if (u.getAmount().stream().anyMatch(a -> a.getUnit().equals(unit))) locked = u;
            }
        }
        if (locked == null) throw new IllegalStateException("No attestation output for period " + period);
        long end = periods().end(period);
        while (chainTimeMs() < end) Thread.sleep(1_000);
        var burn = ConstrPlutusData.builder().alternative(1).data(ListPlutusData.of(BigIntPlutusData.of(0))).build();
        var tx = new ScriptTx()
                .collectFrom(locked, ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of()).build())
                .mintAsset(script, List.of(new Asset("0x" + tokenHex, BigInteger.ONE.negate())), burn)
                .payToAddress(custodian.baseAddress(), Amount.lovelace(LOCKED_LOVELACE))
                .attachSpendingValidator(script);
        String txHash = submit(tx, slotAtOrAfter(end));
        log.info("Attestation for period {} released: tx={}", period, txHash);
        return txHash;
    }

    /** {@code Attestation(period, liabilitiesRoot, totalLiabilities, totalReserves)}. */
    public static PlutusData attestationDatum(long period, BigInteger liabilitiesRoot,
                                              BigInteger totalLiabilities, BigInteger totalReserves) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                BigIntPlutusData.of(period),
                BigIntPlutusData.of(liabilitiesRoot),
                BigIntPlutusData.of(totalLiabilities),
                BigIntPlutusData.of(totalReserves))).build();
    }

    /** The chain's current POSIX time in milliseconds, from the latest block. */
    public long chainTimeMs() throws Exception {
        var latest = backendService.getBlockService().getLatestBlock();
        if (!latest.isSuccessful() || latest.getValue() == null) {
            throw new IllegalStateException("cannot read the latest block: " + latest.getResponse());
        }
        return latest.getValue().getTime() * 1000;
    }

    public AttestationPeriods periods() {
        return new AttestationPeriods(deployment.genesisMs(), deployment.periodMs());
    }

    public DeploymentState deployment() { return deployment; }
    public String getPolicyId() { return policyId; }
    public String getScriptAddress() { return scriptAddr; }
    public String getCustodianAddress() { return custodian.baseAddress(); }

    private String submit(ScriptTx tx, Long validFromSlot) throws Exception {
        byte[] pkh = custodian.hdKeyPair().getPublicKey().getKeyHash();
        var builder = new QuickTxBuilder(backendService)
                .compose(tx)
                .withTxEvaluator(LocalJulcEvaluator.create(backendService))
                .withSigner(SignerProviders.signerFrom(custodian))
                .withRequiredSigners(pkh)
                .feePayer(custodian.baseAddress())
                .collateralPayer(custodian.baseAddress());
        if (validFromSlot != null) builder = builder.validFrom(validFromSlot);
        var result = builder.complete();
        if (!result.isSuccessful()) {
            throw new RuntimeException("Attestation transaction failed: " + result.getResponse());
        }
        String txHash = result.getValue();
        waitForTx(txHash);
        return txHash;
    }

    /** The first slot whose start is at or after {@code posixMs} (DevKit: one-second slots). */
    private long slotAtOrAfter(long posixMs) throws Exception {
        var latest = backendService.getBlockService().getLatestBlock().getValue();
        return latest.getSlot() + (Math.floorDiv(posixMs + 999, 1000L) - latest.getTime());
    }

    /** Tops up the custodian through DevKit's admin API on first use, if it holds nothing. */
    private synchronized void ensureFunded() throws Exception {
        if (funded) return;
        var utxos = backendService.getUtxoService().getUtxos(custodian.baseAddress(), 10, 1);
        boolean empty = !utxos.isSuccessful() || utxos.getValue() == null || utxos.getValue().isEmpty();
        if (empty && topUpEnabled) {
            topUp(custodian.baseAddress(), 1000);
        } else if (empty) {
            log.warn("Top-up disabled: fund the custodian at {} yourself", custodian.baseAddress());
        }
        funded = true;
    }

    private void topUp(String address, int ada) throws Exception {
        var request = HttpRequest.newBuilder()
                .uri(URI.create(adminUrl + "/local-cluster/api/addresses/topup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"address\":\"" + address + "\",\"adaAmount\":" + ada + "}"))
                .build();
        for (int attempt = 1; ; attempt++) {
            var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 == 2) break;
            if (attempt == 5) throw new IllegalStateException("top-up returned " + response.statusCode() + ": " + response.body());
            log.warn("Top-up refused ({}); retrying", response.statusCode());
            Thread.sleep(3_000L * attempt);
        }
        for (int i = 0; i < 40; i++) {
            var utxos = backendService.getUtxoService().getUtxos(address, 10, 1);
            if (utxos.isSuccessful() && utxos.getValue() != null && !utxos.getValue().isEmpty()) {
                log.info("Funded custodian with {} ADA: {}", ada, address);
                return;
            }
            Thread.sleep(1_000);
        }
        throw new IllegalStateException("top-up for " + address + " not visible after 40 s");
    }

    private void waitForTx(String txHash) throws Exception {
        for (int i = 0; i < 30; i++) {
            Thread.sleep(2000);
            try {
                var r = backendService.getTransactionService().getTransaction(txHash);
                if (r.isSuccessful() && r.getValue() != null) { log.info("Confirmed: {}", txHash); return; }
            } catch (Exception ignored) {}
        }
    }

    /** The period already has an attestation token, so a second one is refused off-chain. */
    public static final class AlreadyAttestedException extends IllegalStateException {
        AlreadyAttestedException(String message) {
            super(message);
        }
    }

    private static ListPlutusData icData(List<byte[]> ic) {
        PlutusData[] values = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) {
            values[i] = new BytesPlutusData(ic.get(i));
        }
        return ListPlutusData.of(values);
    }
}
