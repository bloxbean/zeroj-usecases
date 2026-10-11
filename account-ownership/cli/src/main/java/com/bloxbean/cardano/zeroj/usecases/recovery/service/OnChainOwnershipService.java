package com.bloxbean.cardano.zeroj.usecases.recovery.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.MinAdaCalculator;
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
import com.bloxbean.cardano.client.transaction.spec.TransactionOutput;
import com.bloxbean.cardano.client.transaction.spec.Value;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.client.util.HexUtil;

import static com.bloxbean.cardano.client.common.CardanoConstants.LOVELACE;
import org.julclang.clientlib.JulcScriptLoader;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import com.bloxbean.cardano.zeroj.usecases.recovery.onchain.OwnershipProofValidator;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Deploys the {@link OwnershipProofValidator} — the <b>practical</b> recovery gate (ADR-0029 M5) —
 * and drives it on-chain: lock a voucher UTxO whose datum names the address's payment key hash (the
 * circuit's first public input, packed), then unlock it with a Groth16 proof of the full CIP-1852
 * derivation. The unlock succeeds only if the spender proved knowledge of the <em>root key</em>
 * behind the address — the real ownership statement, no registered secret.
 *
 * <p>The unlock pays through outputs tagged with the voucher's outref (ADR-0009 D6): the refund to
 * the proof's recipient, and the remainder ({@code voucher − refund − maxFee}) back to the funder's
 * enterprise address. Creation refuses terms the validator would reject, and a positive remainder
 * below the min-UTxO of its tagged output.</p>
 */
public class OnChainOwnershipService {

    /** Demo refund the recipient is paid on unlock (2 ADA); the datum encodes this as the minimum. */
    public static final long DEMO_REFUND_LOVELACE = 2_000_000L;
    /**
     * The fee slack the voucher allows (2 ADA). Whoever submits the unlock may keep {@code maxFee}
     * minus the actual fee, so a funder sets it close to the expected fee.
     */
    public static final long DEMO_MAX_FEE_LOVELACE = 2_000_000L;
    /** The voucher's value: 10 ADA. */
    public static final long VOUCHER_LOVELACE = 10_000_000L;

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
     * Lock the ownership gate (datum = {@code OwnershipDatum(pkh, refundAmount, funderPkh, maxFee)}),
     * then verify by unlocking with the recipient-bound derivation proof — the unlock pays the bound
     * recipient at least {@code refundLovelace} and the remainder back to the admin (the funder),
     * which the validator enforces. Uses {@link #DEMO_MAX_FEE_LOVELACE}. Returns the unlock tx hash.
     */
    public String verifyOwnershipOnChain(SnarkjsToCardano.ProofCompressed c, byte[] pkh,
                                         byte[] recipientPkh, String recipientAddress,
                                         long refundLovelace) throws Exception {
        return verifyOwnershipOnChain(c, pkh, recipientPkh, recipientAddress, refundLovelace, DEMO_MAX_FEE_LOVELACE);
    }

    /** As {@link #verifyOwnershipOnChain(SnarkjsToCardano.ProofCompressed, byte[], byte[], String, long)}, with an explicit {@code maxFee}. */
    public String verifyOwnershipOnChain(SnarkjsToCardano.ProofCompressed c, byte[] pkh,
                                         byte[] recipientPkh, String recipientAddress,
                                         long refundLovelace, long maxFeeLovelace) throws Exception {
        initialize();
        byte[] funderPkh = new Address(adminAccount.baseAddress()).getPaymentCredentialHash()
                .orElseThrow(() -> new IllegalStateException("admin has no payment key credential"));
        String funderAddress = adminAccount.enterpriseAddress();
        long remainder = checkVoucherTerms(VOUCHER_LOVELACE, refundLovelace, maxFeeLovelace,
                tagOutputMinLovelace(funderAddress));

        // Datum = OwnershipDatum(pkh, refundAmount, funderPkh, maxFee): the pkh the proof must
        // attest, the minimum lovelace the recipient is owed, who gets the remainder back, and the
        // fee slack. ConstrData (alt 0), matching the on-chain record.
        var datum = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(new BytesPlutusData(pkh),
                        BigIntPlutusData.of(BigInteger.valueOf(refundLovelace)),
                        new BytesPlutusData(funderPkh),
                        BigIntPlutusData.of(BigInteger.valueOf(maxFeeLovelace))))
                .build();

        // 10 ADA locked: 2 to the recipient, up to maxFee (2) of fee slack, and the rest (6) back
        // to the admin in a tagged output.
        //
        // Also carve out a dedicated 5 ADA pure-ADA output back to the admin, used as explicit
        // collateral for the unlock below. On public backends (Blockfrost) the admin's UTxOs may
        // hold native tokens and the UTxO API lags after the lock spends its funding input — so
        // the default collateral selector can grab a token-bearing and/or already-spent UTxO
        // (CollateralContainsNonADA / BadInputsUTxO). A fresh, confirmed, ADA-only output from
        // this very lock tx sidesteps both. Yaci DevKit never hit this (no lag, ADA-only wallet).
        var lockTx = new Tx()
                .payToContract(scriptAddr, Amount.lovelace(BigInteger.valueOf(VOUCHER_LOVELACE)), datum)
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

        // Redeemer = OwnershipRedeemer(piA, piB, piC, recipient): the proof + the recipient it was
        // bound to (the second, packed public input). ConstrData (alt 0), matching the on-chain record.
        var redeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(new BytesPlutusData(c.piA()), new BytesPlutusData(c.piB()),
                        new BytesPlutusData(c.piC()), new BytesPlutusData(recipientPkh))).build();

        // Pay the bound recipient the refund and the admin the remainder, each tagged with the
        // voucher's outref — the validator counts only tagged outputs, so the tx submitter cannot
        // redirect or keep the funds. The remainder goes to the admin's enterprise address, never
        // the change address, so fee balancing can't take the fee out of a tagged output. Same key:
        // one combined output.
        var tag = outRefTag(scriptUtxo.getTxHash(), scriptUtxo.getOutputIndex());
        var unlockTx = new ScriptTx().collectFrom(scriptUtxo, redeemer);
        if (Arrays.equals(recipientPkh, funderPkh)) {
            unlockTx.payToContract(funderAddress, Amount.lovelace(BigInteger.valueOf(refundLovelace + remainder)), tag);
        } else {
            unlockTx.payToContract(recipientAddress, Amount.lovelace(BigInteger.valueOf(refundLovelace)), tag);
            if (remainder > 0)
                unlockTx.payToContract(funderAddress, Amount.lovelace(BigInteger.valueOf(remainder)), tag);
        }
        unlockTx.attachSpendingValidator(script);
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

    /**
     * Check a voucher's terms before locking it, returning the remainder owed to the funder. Refuses
     * terms the validator would reject ({@code refund ≥ 0}, {@code maxFee ≥ 0},
     * {@code refund + maxFee ≤ voucher}), and a remainder that is positive but below
     * {@code remainderMinLovelace}, the min-UTxO of its tagged output (ADR-0009 D6).
     */
    public static long checkVoucherTerms(long voucherLovelace, long refundLovelace, long maxFeeLovelace,
                                         long remainderMinLovelace) {
        if (refundLovelace < 0 || maxFeeLovelace < 0)
            throw new IllegalArgumentException("refund and maxFee must be non-negative");
        if (refundLovelace > voucherLovelace - maxFeeLovelace)
            throw new IllegalArgumentException("refund + maxFee exceeds the voucher's " + voucherLovelace + " lovelace");
        long remainder = voucherLovelace - refundLovelace - maxFeeLovelace;
        if (remainder > 0 && remainder < remainderMinLovelace)
            throw new IllegalArgumentException("remainder " + remainder + " lovelace is below the min-UTxO "
                    + remainderMinLovelace + " of its tagged output: lower maxFee or raise the refund");
        return remainder;
    }

    /** The voucher tag: the outref {@code Constr 0 [B txId, I index]}, as the validator compares it. */
    public static ConstrPlutusData outRefTag(String txHash, int index) {
        return ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(new BytesPlutusData(HexUtil.decodeHexString(txHash)),
                        BigIntPlutusData.of(BigInteger.valueOf(index))))
                .build();
    }

    /** Min-UTxO of an ADA-only output to {@code address} tagged with an outref (worst-case index). */
    private long tagOutputMinLovelace(String address) throws Exception {
        var pp = backendService.getEpochService().getProtocolParameters();
        if (!pp.isSuccessful()) throw new IllegalStateException("protocol parameters: " + pp.getResponse());
        var output = TransactionOutput.builder()
                .address(address)
                .value(new Value(MinAdaCalculator.DUMMY_COIN_VAL, List.of()))
                .inlineDatum(outRefTag("00".repeat(32), 65_535))
                .build();
        return new MinAdaCalculator(pp.getValue()).calculateMinAda(output).longValueExact();
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
