package com.bloxbean.cardano.zeroj.usecases.recovery.service;

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
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.recovery.onchain.RecoveryProofValidator;

import java.math.BigInteger;
import java.util.List;

/**
 * Deploys the {@link RecoveryProofValidator} and drives the on-chain recovery gate: lock a
 * recovery-attestation UTxO carrying the public inputs {@code [commitment, addr]} as datum, then
 * unlock it with the Groth16 proof — which succeeds only if the proof verifies on-chain.
 */
public class OnChainRecoveryService {

    private final BackendService backendService;
    private final Account adminAccount;
    private final RecoveryCircuitService circuitService;

    private PlutusScript script;
    private String scriptAddr;

    public OnChainRecoveryService(BackendService backendService, Account adminAccount,
                                  RecoveryCircuitService circuitService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.circuitService = circuitService;
    }

    public synchronized void initialize() {
        if (script != null) return;
        var vk = ProofCompressor.compressVk(circuitService.getSetupResult());
        script = JulcScriptLoader.load(RecoveryProofValidator.class,
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()));
        scriptAddr = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
    }

    public String scriptAddress() { initialize(); return scriptAddr; }

    /** Lock the recovery attestation (datum = [commitment, addr]), then verify by unlocking with the proof. */
    public String verifyRecoveryOnChain(Groth16ProofBLS381 proof, BigInteger commitment, BigInteger addr)
            throws Exception {
        initialize();
        var datum = ListPlutusData.of(BigIntPlutusData.of(commitment), BigIntPlutusData.of(addr));

        var lockTx = new Tx().payToContract(scriptAddr, Amount.ada(2), datum).from(adminAccount.baseAddress());
        var lock = new QuickTxBuilder(backendService).compose(lockTx)
                .withSigner(SignerProviders.signerFrom(adminAccount)).complete();
        if (!lock.isSuccessful()) throw new RuntimeException("recovery lock failed: " + lock.getResponse());
        waitForTx(lock.getValue());

        var utxos = backendService.getUtxoService().getUtxos(scriptAddr, 20, 1);
        Utxo scriptUtxo = utxos.getValue().stream()
                .filter(u -> u.getTxHash().equals(lock.getValue())).findFirst()
                .orElse(utxos.getValue().get(utxos.getValue().size() - 1));

        var c = ProofCompressor.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(new BytesPlutusData(c.piA()), new BytesPlutusData(c.piB()),
                        new BytesPlutusData(c.piC()))).build();

        var unlockTx = new ScriptTx().collectFrom(scriptUtxo, redeemer)
                .payToAddress(adminAccount.baseAddress(), Amount.ada(1.5))
                .attachSpendingValidator(script);
        var unlock = new QuickTxBuilder(backendService).compose(unlockTx)
                .withTxEvaluator(LocalJulcEvaluator.create(backendService))
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();
        if (!unlock.isSuccessful()) throw new RuntimeException("on-chain recovery proof verify failed: " + unlock.getResponse());
        waitForTx(unlock.getValue());
        return unlock.getValue();
    }

    private void waitForTx(String txHash) throws Exception {
        for (int i = 0; i < 30; i++) {
            Thread.sleep(2000);
            try {
                var r = backendService.getTransactionService().getTransaction(txHash);
                if (r.isSuccessful() && r.getValue() != null) return;
            } catch (Exception ignored) {}
        }
    }

    private static ListPlutusData vkIcData(List<byte[]> ic) {
        PlutusData[] values = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) values[i] = new BytesPlutusData(ic.get(i));
        return ListPlutusData.of(values);
    }
}
