package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.function.helper.ScriptUtxoFinders;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.transaction.spec.TransactionInput;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;

import static com.bloxbean.cardano.client.common.CardanoConstants.LOVELACE;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.usecases.recovery.onchain.OwnershipProofValidator;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

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
        //
        // Also carve out a dedicated 5 ADA pure-ADA output back to the admin, used as explicit
        // collateral for the unlock below. On public backends (Blockfrost) the admin's UTxOs may
        // hold native tokens and the UTxO API lags after the lock spends its funding input — so
        // the default collateral selector can grab a token-bearing and/or already-spent UTxO
        // (CollateralContainsNonADA / BadInputsUTxO). A fresh, confirmed, ADA-only output from
        // this very lock tx sidesteps both. Yaci DevKit never hit this (no lag, ADA-only wallet).
        var lockTx = new Tx()
                .payToContract(scriptAddr, Amount.ada(10), datum)
                .payToAddress(adminAccount.baseAddress(), Amount.ada(5))
                .from(adminAccount.baseAddress());
        var lock = new QuickTxBuilder(backendService).compose(lockTx)
                .withSigner(SignerProviders.signerFrom(adminAccount)).completeAndWait();
        if (!lock.isSuccessful()) throw new RuntimeException("ownership lock failed: " + lock.getResponse());
        waitForTx(lock.getValue());
        checkIfUtxoAvailable(lock.getValue(), scriptAddr);

        // Locate the freshly-locked UTxO by its inline datum (the pkh public inputs), not by
        // position. Prefer the output from this lock tx in case a stale same-datum UTxO from a
        // prior run still sits at the script address.
        var utxoSupplier = new DefaultUtxoSupplier(backendService.getUtxoService());
        List<Utxo> datumMatches = ScriptUtxoFinders.findAllByInlineDatum(utxoSupplier, scriptAddr, datum);
        Utxo scriptUtxo = datumMatches.stream()
                .filter(u -> u.getTxHash().equals(lock.getValue())).findFirst()
                .or(() -> datumMatches.stream().findFirst())
                .orElseThrow(() -> new RuntimeException(
                        "No script UTxO with expected datum found at " + scriptAddr));

        // Fresh, ADA-only collateral produced by the lock tx above (see comment there).
        Utxo collateralUtxo = findFreshAdaCollateral(adminAccount.baseAddress(), lock.getValue());
        var collateralInput = new TransactionInput(collateralUtxo.getTxHash(), collateralUtxo.getOutputIndex());

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
                .withCollateralInputs(collateralInput)
                .completeAndWait();
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

    protected void checkIfUtxoAvailable(String txHash, String address) {
        Optional<Utxo> utxo = Optional.empty();
        int count = 0;
        while (utxo.isEmpty()) {
            if (count++ >= 20)
                break;
            List<Utxo> utxos = new DefaultUtxoSupplier(backendService.getUtxoService()).getAll(address);
            utxo = utxos.stream().filter(u -> u.getTxHash().equals(txHash))
                    .findFirst();
            System.out.println("Try to get new output... txhash: " + txHash);
            try {
                Thread.sleep(1000);
            } catch (Exception e) {}
        }
    }

    /**
     * Poll the admin address for the ADA-only collateral output minted by the lock tx. Waits for
     * the backend's UTxO view to catch up (Blockfrost lags), so we never pin collateral to a
     * spent input. Returns a confirmed, token-free UTxO of at least the default 5 ADA collateral.
     */
    private Utxo findFreshAdaCollateral(String address, String lockTxHash) throws Exception {
        var supplier = new DefaultUtxoSupplier(backendService.getUtxoService());
        for (int i = 0; i < 30; i++) {
            Optional<Utxo> collateral = supplier.getAll(address).stream()
                    .filter(u -> lockTxHash.equals(u.getTxHash()))
                    .filter(OnChainOwnershipService::isAdaOnly)
                    .filter(u -> lovelaceOf(u) >= 5_000_000L)
                    .findFirst();
            if (collateral.isPresent()) return collateral.get();
            Thread.sleep(1000);
        }
        throw new RuntimeException("No ADA-only collateral output from lock tx " + lockTxHash
                + " found at " + address);
    }

    private static boolean isAdaOnly(Utxo utxo) {
        return utxo.getAmount().stream().allMatch(a -> LOVELACE.equals(a.getUnit()));
    }

    private static long lovelaceOf(Utxo utxo) {
        return utxo.getAmount().stream()
                .filter(a -> LOVELACE.equals(a.getUnit()))
                .map(Amount::getQuantity)
                .findFirst().map(BigInteger::longValue).orElse(0L);
    }

    private static ListPlutusData vkIcData(List<byte[]> ic) {
        PlutusData[] values = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) values[i] = new BytesPlutusData(ic.get(i));
        return ListPlutusData.of(values);
    }
}
