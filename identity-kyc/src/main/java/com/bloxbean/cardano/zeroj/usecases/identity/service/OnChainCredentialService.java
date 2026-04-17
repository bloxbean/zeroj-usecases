package com.bloxbean.cardano.zeroj.usecases.identity.service;

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
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.identity.onchain.CredentialGatedValidator;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Arrays;

@Service
public class OnChainCredentialService {

    private static final Logger log = LoggerFactory.getLogger(OnChainCredentialService.class);

    private final BackendService backendService;
    private final Account adminAccount;
    private final CredentialService credentialService;

    private PlutusScript script;
    private String scriptAddr;
    private boolean initialized;

    public OnChainCredentialService(BackendService backendService, Account adminAccount,
                                     CredentialService credentialService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.credentialService = credentialService;
    }

    public synchronized void initialize() throws Exception {
        if (initialized) return;

        log.info("Compiling credential-gated validator...");
        var vk = ProofCompressor.compressVk(credentialService.getSetupResult());

        script = JulcScriptLoader.load(CredentialGatedValidator.class,
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                new BytesPlutusData(vk.ic().get(0)),
                new BytesPlutusData(vk.ic().get(1)),
                new BytesPlutusData(vk.ic().get(2)),
                new BytesPlutusData(vk.ic().get(3)),
                new BytesPlutusData(vk.ic().get(4)));

        scriptAddr = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        log.info("Credential-gated script: {}", scriptAddr.substring(0, 40) + "...");
        initialized = true;
    }

    /**
     * Lock ADA at the credential-gated script address.
     */
    public String lockFunds(BigInteger lovelace) throws Exception {
        ensureInitialized();
        log.info("Locking {} lovelace at credential-gated script...", lovelace);

        var datum = ConstrPlutusData.of(0); // unit datum

        var lockTx = new Tx()
                .payToContract(scriptAddr, Amount.lovelace(lovelace), datum)
                .from(adminAccount.baseAddress());

        var result = new QuickTxBuilder(backendService)
                .compose(lockTx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Lock failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Locked: tx={}", txHash);
        waitForTx(txHash);
        return txHash;
    }

    /**
     * Unlock ADA using a ZK credential proof.
     */
    public String unlockWithProof(Groth16ProofBLS381 proof,
                                    BigInteger credentialHash, BigInteger minAge,
                                    BigInteger countryRoot, boolean eligible) throws Exception {
        ensureInitialized();

        log.info("Unlocking with ZK credential proof (eligible={})...", eligible);

        // Find a script UTXO
        var utxoResult = backendService.getUtxoService().getUtxos(scriptAddr, 10, 1);
        if (!utxoResult.isSuccessful() || utxoResult.getValue().isEmpty()) {
            throw new RuntimeException("No locked funds at script address");
        }
        Utxo scriptUtxo = utxoResult.getValue().get(0);

        // Build redeemer with proof + public inputs
        var compressed = ProofCompressor.compressProof(proof);
        var redeemer = ConstrPlutusData.builder()
                .alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressed.piA()),
                        new BytesPlutusData(compressed.piB()),
                        new BytesPlutusData(compressed.piC()),
                        new BytesPlutusData(toMinimalBytes(credentialHash)),
                        new BytesPlutusData(toMinimalBytes(minAge)),
                        new BytesPlutusData(toMinimalBytes(countryRoot)),
                        new BytesPlutusData(toMinimalBytes(eligible ? BigInteger.ONE : BigInteger.ZERO))))
                .build();

        var unlockTx = new ScriptTx()
                .collectFrom(scriptUtxo, redeemer)
                .payToAddress(adminAccount.baseAddress(), Amount.ada(4.5))
                .attachSpendingValidator(script);

        var result = new QuickTxBuilder(backendService)
                .compose(unlockTx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Unlock failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Unlocked with credential proof: tx={}", txHash);
        waitForTx(txHash);
        return txHash;
    }

    public String getScriptAddress() throws Exception {
        ensureInitialized();
        return scriptAddr;
    }

    public int getLockedUtxoCount() {
        try {
            ensureInitialized();
            var r = backendService.getUtxoService().getUtxos(scriptAddr, 100, 1);
            return (r.isSuccessful() && r.getValue() != null) ? r.getValue().size() : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private void ensureInitialized() throws Exception {
        if (!initialized) initialize();
    }

    private static byte[] toMinimalBytes(BigInteger v) {
        byte[] b = v.toByteArray();
        return (b.length > 1 && b[0] == 0) ? Arrays.copyOfRange(b, 1, b.length) : b;
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
