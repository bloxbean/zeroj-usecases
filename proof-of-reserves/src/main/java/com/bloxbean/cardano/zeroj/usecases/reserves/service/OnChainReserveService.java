package com.bloxbean.cardano.zeroj.usecases.reserves.service;

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
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.reserves.onchain.ReserveAttestationValidator;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

@Service
public class OnChainReserveService {

    private static final Logger log = LoggerFactory.getLogger(OnChainReserveService.class);

    private final BackendService backendService;
    private final Account adminAccount;
    private final ReserveCircuitService circuitService;

    private PlutusScript script;
    private String scriptAddr;
    private boolean initialized;

    public OnChainReserveService(BackendService backendService, Account adminAccount,
                                  ReserveCircuitService circuitService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.circuitService = circuitService;
    }

    public synchronized void initialize() throws Exception {
        if (initialized) return;

        log.info("Compiling reserve attestation validator...");
        var vk = ProofCompressor.compressVk(circuitService.getSetupResult());

        script = JulcScriptLoader.load(ReserveAttestationValidator.class,
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()));

        scriptAddr = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        initialized = true;
        log.info("Attestation script: {}...", scriptAddr.substring(0, 40));
    }

    /**
     * Publish solvency attestation on-chain.
     * Locks ADA at the script address with public inputs as datum.
     * The Groth16 proof is in the redeemer (for future unlock/update).
     */
    public String publishAttestation(Groth16ProofBLS381 proof,
                                      BigInteger totalReserves, BigInteger liabilitiesRoot,
                                      BigInteger totalLiabilities, boolean solvent) throws Exception {
        ensureInitialized();
        log.info("Publishing solvency attestation (solvent={})...", solvent);

        // Datum = public inputs [totalReserves, liabilitiesRoot, totalLiabilities, isSolvent]
        var datum = ListPlutusData.of(
                BigIntPlutusData.of(totalReserves),
                BigIntPlutusData.of(liabilitiesRoot),
                BigIntPlutusData.of(totalLiabilities),
                BigIntPlutusData.of(solvent ? BigInteger.ONE : BigInteger.ZERO));

        // Lock with datum (anyone can read the attestation)
        var lockTx = new Tx()
                .payToContract(scriptAddr, Amount.ada(2), datum)
                .from(adminAccount.baseAddress());

        var result = new QuickTxBuilder(backendService)
                .compose(lockTx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Attestation lock failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Attestation published: tx={}", txHash);
        waitForTx(txHash);

        // Now unlock with the proof to prove on-chain
        return unlockWithProof(proof, totalReserves, liabilitiesRoot, totalLiabilities, solvent, txHash);
    }

    private String unlockWithProof(Groth16ProofBLS381 proof,
                                    BigInteger totalReserves, BigInteger liabilitiesRoot,
                                    BigInteger totalLiabilities, boolean solvent,
                                    String lockTxHash) throws Exception {
        // Find the script UTXO
        var utxoResult = backendService.getUtxoService().getUtxos(scriptAddr, 10, 1);
        if (!utxoResult.isSuccessful() || utxoResult.getValue().isEmpty()) {
            throw new RuntimeException("No attestation UTXO found");
        }
        Utxo scriptUtxo = utxoResult.getValue().get(0);

        var compressed = ProofCompressor.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressed.piA()),
                        new BytesPlutusData(compressed.piB()),
                        new BytesPlutusData(compressed.piC())))
                .build();

        var unlockTx = new ScriptTx()
                .collectFrom(scriptUtxo, redeemer)
                .payToAddress(adminAccount.baseAddress(), Amount.ada(1.5))
                .attachSpendingValidator(script);

        var result = new QuickTxBuilder(backendService)
                .compose(unlockTx)
                .withTxEvaluator(LocalJulcEvaluator.create(backendService))
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Attestation proof verification failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Solvency proof verified on-chain: tx={}", txHash);
        waitForTx(txHash);
        return txHash;
    }

    public String getScriptAddress() throws Exception {
        ensureInitialized();
        return scriptAddr;
    }

    private void ensureInitialized() throws Exception {
        if (!initialized) initialize();
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

    private static ListPlutusData vkIcData(List<byte[]> ic) {
        PlutusData[] values = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) {
            values[i] = new BytesPlutusData(ic.get(i));
        }
        return ListPlutusData.of(values);
    }
}
