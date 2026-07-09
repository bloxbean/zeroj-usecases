package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.usecases.recovery.onchain.OwnershipProofValidator;

import java.math.BigInteger;
import java.util.List;

/**
 * Deploys the {@link OwnershipProofValidator} — the <b>practical</b> recovery gate (ADR-0029 M5) —
 * and drives it on-chain: lock a UTxO whose datum is the address's payment key hash (the derivation
 * circuit's 28 public inputs), then unlock it with a Groth16 proof of the full CIP-1852 derivation.
 * The unlock succeeds only if the spender proved knowledge of the <em>root key</em> behind the
 * address — the real ownership statement, no registered secret.
 */
public class OnChainOwnershipService {

    private final BackendService backendService;
    private final Account adminAccount;
    private final SnarkjsToCardano.VkCompressed vk;
    private final Network network;

    private PlutusScript script;
    private String scriptAddr;

    public OnChainOwnershipService(BackendService backendService, Account adminAccount,
                                   SnarkjsToCardano.VkCompressed vk, Network network) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.vk = vk;
        this.network = network;
    }

    public synchronized void initialize() {
        if (script != null) return;
        script = JulcScriptLoader.load(OwnershipProofValidator.class,
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()));
        scriptAddr = AddressProvider.getEntAddress(script, network).toBech32();
    }

    public String scriptAddress() { initialize(); return scriptAddr; }

    /**
     * Lock the ownership gate (datum = the 28 pkh bytes, in circuit public-input order), then
     * verify by unlocking with the derivation proof. Returns the unlock tx hash.
     */
    public String verifyOwnershipOnChain(SnarkjsToCardano.ProofCompressed c, byte[] pkh) throws Exception {
        initialize();
        PlutusData[] pub = new PlutusData[pkh.length];
        for (int i = 0; i < pkh.length; i++) pub[i] = BigIntPlutusData.of(BigInteger.valueOf(pkh[i] & 0xff));
        var datum = ListPlutusData.of(pub);

        // 10 ADA locked / 2 back: this validator's execution fee (28 public-input scalar-muls +
        // pairings) is far larger than the commitment gate's — leave headroom so change stays
        // above min-ADA when both outputs land on the admin address.
        var lockTx = new Tx().payToContract(scriptAddr, Amount.ada(10), datum).from(adminAccount.baseAddress());
        var lock = new QuickTxBuilder(backendService).compose(lockTx)
                .withSigner(SignerProviders.signerFrom(adminAccount)).complete();
        if (!lock.isSuccessful()) throw new RuntimeException("ownership lock failed: " + lock.getResponse());
        waitForTx(lock.getValue());

        var utxos = backendService.getUtxoService().getUtxos(scriptAddr, 20, 1);
        Utxo scriptUtxo = utxos.getValue().stream()
                .filter(u -> u.getTxHash().equals(lock.getValue())).findFirst()
                .orElse(utxos.getValue().get(utxos.getValue().size() - 1));

        var redeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(new BytesPlutusData(c.piA()), new BytesPlutusData(c.piB()),
                        new BytesPlutusData(c.piC()))).build();

        var unlockTx = new ScriptTx().collectFrom(scriptUtxo, redeemer)
                .payToAddress(adminAccount.baseAddress(), Amount.ada(2))
                .attachSpendingValidator(script);
        var unlock = new QuickTxBuilder(backendService).compose(unlockTx)
                .withTxEvaluator(LocalJulcEvaluator.create(backendService))
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();
        if (!unlock.isSuccessful())
            throw new RuntimeException("on-chain ownership proof verify failed: " + unlock.getResponse());
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
