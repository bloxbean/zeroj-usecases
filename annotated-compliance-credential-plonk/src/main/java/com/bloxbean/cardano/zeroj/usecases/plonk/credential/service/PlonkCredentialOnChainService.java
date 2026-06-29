package com.bloxbean.cardano.zeroj.usecases.plonk.credential.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.zeroj.onchain.julc.plonk.validator.PlonkBLS12381MultiInputVerifier;

public final class PlonkCredentialOnChainService {
    private static final int TX_WAIT_ATTEMPTS = Integer.getInteger("zeroj.yaci.txWaitAttempts", 90);
    private static final long TX_WAIT_MILLIS = Long.getLong("zeroj.yaci.txWaitMillis", 2_000L);

    private final BackendService backendService;
    private final Account adminAccount;

    public PlonkCredentialOnChainService(BackendService backendService, Account adminAccount) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
    }

    public Result verifyOnChain(PlonkCredentialProofService.ProofBundle bundle) throws Exception {
        long startNanos = System.nanoTime();
        long scriptStartNanos = System.nanoTime();
        PlutusScript script = JulcScriptLoader.load(
                PlonkBLS12381MultiInputVerifier.class,
                PlonkCardanoData.verifierParams(bundle.vk(), bundle.publicInputs().length));
        String scriptAddress = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        System.out.println("[plonk-credential] onChainScriptLoad=" + elapsedMillis(scriptStartNanos) + "ms");

        PlutusData datum = PlonkCardanoData.datum(bundle.publicInputs());
        PlutusData redeemer = PlonkCardanoData.redeemer(bundle.cardanoProof());

        var lockTx = new Tx()
                .payToContract(scriptAddress, Amount.ada(3), datum)
                .from(adminAccount.baseAddress());

        var lockResult = new QuickTxBuilder(backendService)
                .compose(lockTx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .complete();

        long lockWaitStartNanos = System.nanoTime();
        if (!lockResult.isSuccessful()) {
            throw new IllegalStateException("PlonK credential lock tx failed: " + lockResult.getResponse());
        }
        String lockTxHash = lockResult.getValue();
        waitForTx(lockTxHash);
        System.out.println("[plonk-credential] lockConfirmed=" + elapsedMillis(lockWaitStartNanos) + "ms");

        Utxo scriptUtxo = findScriptUtxo(scriptAddress, lockTxHash);
        var unlockTx = new ScriptTx()
                .collectFrom(scriptUtxo, redeemer)
                .payToAddress(adminAccount.baseAddress(), Amount.ada(2))
                .attachSpendingValidator(script);

        var unlockResult = new QuickTxBuilder(backendService)
                .compose(unlockTx)
                .withTxEvaluator(LocalJulcEvaluator.create(backendService))
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();

        long unlockWaitStartNanos = System.nanoTime();
        if (!unlockResult.isSuccessful()) {
            throw new IllegalStateException("PlonK credential unlock tx failed: " + unlockResult.getResponse());
        }
        String unlockTxHash = unlockResult.getValue();
        waitForTx(unlockTxHash);
        System.out.println("[plonk-credential] unlockConfirmed=" + elapsedMillis(unlockWaitStartNanos) + "ms");
        System.out.println("[plonk-credential] onChainTotal=" + elapsedMillis(startNanos) + "ms");
        return new Result(scriptAddress, lockTxHash, unlockTxHash);
    }

    private Utxo findScriptUtxo(String scriptAddress, String txHash) throws Exception {
        for (int attempt = 0; attempt < 30; attempt++) {
            var result = backendService.getUtxoService().getUtxos(scriptAddress, 100, 1);
            if (result.isSuccessful()) {
                for (Utxo utxo : result.getValue()) {
                    if (txHash.equals(utxo.getTxHash())) {
                        return utxo;
                    }
                }
            }
            Thread.sleep(TX_WAIT_MILLIS);
        }
        throw new IllegalStateException("No PlonK credential script UTXO found for tx " + txHash);
    }

    private void waitForTx(String txHash) throws Exception {
        for (int i = 0; i < TX_WAIT_ATTEMPTS; i++) {
            Thread.sleep(TX_WAIT_MILLIS);
            try {
                var result = backendService.getTransactionService().getTransaction(txHash);
                if (result.isSuccessful() && result.getValue() != null) {
                    return;
                }
            } catch (Exception ignored) {
            }
        }
        throw new IllegalStateException("Timed out waiting for tx confirmation: " + txHash);
    }

    public record Result(String scriptAddress, String lockTxHash, String unlockTxHash) {
    }

    private static long elapsedMillis(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }
}
