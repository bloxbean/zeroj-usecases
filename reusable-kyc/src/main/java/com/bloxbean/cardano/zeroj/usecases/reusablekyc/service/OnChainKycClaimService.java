package com.bloxbean.cardano.zeroj.usecases.reusablekyc.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.MinAdaCalculator;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.client.common.model.Network;
import com.bloxbean.cardano.client.function.helper.ScriptUtxoFinders;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.transaction.spec.TransactionInput;
import com.bloxbean.cardano.client.transaction.spec.TransactionOutput;
import com.bloxbean.cardano.client.transaction.spec.Value;
import com.bloxbean.cardano.client.util.HexUtil;
import org.julclang.clientlib.JulcScriptLoader;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.onchain.BbsKycClaimValidator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import static com.bloxbean.cardano.client.common.CardanoConstants.LOVELACE;

/**
 * Drives the reusable-KYC claim on-chain (ADR-0003): deploys {@link BbsKycClaimValidator} with the
 * issuer's BBS verification material, locks a <b>voucher</b> UTxO carrying the claim policy, then
 * spends it with a holder's BBS presentation as the redeemer. The ledger itself verifies the BBS
 * proof and enforces the payout — spending the voucher once is the nullifier.
 *
 * <p>The claim pays through outputs tagged with the voucher's outref (ADR-0009 D6): the refund to
 * the recipient, and the remainder ({@code voucher − refund − maxFee}) back to the funder's
 * enterprise address. Creation refuses terms the validator would reject, and a positive remainder
 * below the min-UTxO of its tagged output.</p>
 */
public class OnChainKycClaimService {

    /** Demo voucher size and refund (2 ADA to the recipient; the rest returns to the funder). */
    public static final long DEMO_REFUND_LOVELACE = 2_000_000L;
    /**
     * The fee slack the voucher allows (2 ADA). Whoever submits the claim may keep {@code maxFee}
     * minus the actual fee, so a funder sets it close to the expected fee; this covers the BBS
     * verification's script fee with some headroom.
     */
    public static final long DEMO_MAX_FEE_LOVELACE = 2_000_000L;
    public static final long VOUCHER_LOVELACE = 10_000_000L;
    private static final long COLLATERAL_ADA = 5L;

    /** The issuer's BBS verification material — deterministic for a given issuer/schema/header. */
    public record BbsParams(byte[] w, byte[] bp2, byte[] p1, byte[] q1, List<byte[]> h,
                            byte[] domainBytes, byte[] dstH2S, byte[] dstMap) {}

    /** One holder presentation, flattened for the redeemer (undisclosed indexes 0,1,4). */
    public record Claim(byte[] abar, byte[] bbar, byte[] d,
                        BigInteger eHat, BigInteger r1Hat, BigInteger r3Hat,
                        List<BigInteger> mHats, BigInteger challenge,
                        byte[] country, byte[] kycLevel, byte[] presentationHeader) {}

    private final BackendService backendService;
    private final Account funder;
    private final BbsParams params;
    private final Network network;
    private final boolean evaluateLocally;

    private PlutusScript script;
    private String scriptAddr;

    public OnChainKycClaimService(BackendService backendService, Account funder,
                                  BbsParams params, Network network) {
        this(backendService, funder, params, network, true);
    }

    /**
     * @param evaluateLocally {@code true} to evaluate script ExUnits with the local Julc VM and its
     *                        safety margin; {@code false} to delegate evaluation to the backend.
     */
    public OnChainKycClaimService(BackendService backendService, Account funder,
                                  BbsParams params, Network network, boolean evaluateLocally) {
        this.backendService = backendService;
        this.funder = funder;
        this.params = params;
        this.network = network;
        this.evaluateLocally = evaluateLocally;
    }

    public synchronized void initialize() {
        if (script != null) return;
        script = JulcScriptLoader.load(BbsKycClaimValidator.class,
                new BytesPlutusData(params.w()),
                new BytesPlutusData(params.bp2()),
                new BytesPlutusData(params.p1()),
                new BytesPlutusData(params.q1()),
                new BytesPlutusData(params.h().get(0)),
                new BytesPlutusData(params.h().get(1)),
                new BytesPlutusData(params.h().get(2)),
                new BytesPlutusData(params.h().get(3)),
                new BytesPlutusData(params.h().get(4)),
                new BytesPlutusData(params.domainBytes()),
                new BytesPlutusData(params.dstH2S()),
                new BytesPlutusData(params.dstMap()));
        scriptAddr = AddressProvider.getEntAddress(script, network).toBech32();
    }

    public String scriptAddress() { initialize(); return scriptAddr; }

    /**
     * The presentation header a claim on {@code (voucher, recipient)} must use:
     * {@code blake2b_256(voucherTxId ‖ I2OSP(index,8) ‖ recipientPkh)} — the exact value
     * {@link BbsKycClaimValidator} recomputes on-chain.
     *
     * <p>Deliberately <b>not</b> a random nonce: deriving it from the voucher being spent makes it
     * unique per claim by construction (a UTxO is spendable once), unguessable to pick wrongly, and
     * impossible to lift a presentation from one claim to another.</p>
     */
    public static byte[] claimHeader(String voucherTxHash, int voucherIndex, byte[] recipientPkh) {
        return claimHeader(HexUtil.decodeHexString(voucherTxHash), voucherIndex, recipientPkh);
    }

    /** As {@link #claimHeader(String, int, byte[])}, with the voucher's tx id as raw bytes. */
    public static byte[] claimHeader(byte[] voucherTxId, long voucherIndex, byte[] recipientPkh) {
        return Blake2bUtil.blake2bHash256(
                concat(concat(voucherTxId, i2osp8(voucherIndex)), recipientPkh));
    }

    /**
     * Lock a voucher for {@code (country, kycLevel)} payable to {@code recipient}, then claim it.
     *
     * @param claimFactory builds the claim once the voucher exists — it receives the
     *                     {@link #claimHeader} the presentation must be bound to (the voucher's ref
     *                     is only known after the lock lands).
     */
    public String lockAndClaim(Function<byte[], Claim> claimFactory,
                               String requiredCountry, String requiredKycLevel,
                               String recipientAddress, byte[] recipientPkh, long refundLovelace)
            throws Exception {
        return lockAndClaim(claimFactory, requiredCountry, requiredKycLevel, recipientAddress, recipientPkh,
                refundLovelace, DEMO_MAX_FEE_LOVELACE);
    }

    /** As {@link #lockAndClaim(Function, String, String, String, byte[], long)}, with an explicit {@code maxFee}. */
    public String lockAndClaim(Function<byte[], Claim> claimFactory,
                               String requiredCountry, String requiredKycLevel,
                               String recipientAddress, byte[] recipientPkh, long refundLovelace,
                               long maxFeeLovelace) throws Exception {
        initialize();
        byte[] funderPkh = funderPkh();
        String funderAddress = funderTagAddress();
        long remainder = checkVoucherTerms(VOUCHER_LOVELACE, refundLovelace, maxFeeLovelace,
                tagOutputMinLovelace(funderAddress));

        // Voucher datum = the claim policy: which disclosed values are required, who gets paid, how
        // much, who gets the remainder, and the fee slack.
        var datum = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(requiredCountry.getBytes(StandardCharsets.UTF_8)),
                        new BytesPlutusData(requiredKycLevel.getBytes(StandardCharsets.UTF_8)),
                        new BytesPlutusData(recipientPkh),
                        BigIntPlutusData.of(BigInteger.valueOf(refundLovelace)),
                        new BytesPlutusData(funderPkh),
                        BigIntPlutusData.of(BigInteger.valueOf(maxFeeLovelace))))
                .build();

        // Lock the voucher, and carve out a dedicated ADA-only output for collateral (same reasoning
        // as the account-ownership demo: avoids token-bearing/stale collateral selection).
        var lockTx = new Tx()
                .payToContract(scriptAddr, Amount.lovelace(BigInteger.valueOf(VOUCHER_LOVELACE)), datum)
                .payToAddress(funder.baseAddress(), Amount.ada(COLLATERAL_ADA))
                .from(funder.baseAddress());
        var lock = new QuickTxBuilder(backendService).compose(lockTx)
                .withSigner(SignerProviders.signerFrom(funder)).completeAndWait();
        if (!lock.isSuccessful()) throw new RuntimeException("voucher lock failed: " + lock.getResponse());
        waitForTx(lock.getValue());
        awaitUtxo(lock.getValue(), scriptAddr);

        var utxoSupplier = new DefaultUtxoSupplier(backendService.getUtxoService());
        List<Utxo> matches = ScriptUtxoFinders.findAllByInlineDatum(utxoSupplier, scriptAddr, datum);
        Utxo voucher = matches.stream()
                .filter(u -> u.getTxHash().equals(lock.getValue())).findFirst()
                .or(() -> matches.stream().findFirst())
                .orElseThrow(() -> new RuntimeException("No voucher UTxO with the expected datum at " + scriptAddr));

        Utxo collateralUtxo = findFreshAdaCollateral(funder.baseAddress(), lock.getValue());
        var collateralInput = new TransactionInput(collateralUtxo.getTxHash(), collateralUtxo.getOutputIndex());

        // The presentation must be bound to THIS voucher + recipient (the validator recomputes this).
        byte[] ph = claimHeader(voucher.getTxHash(), voucher.getOutputIndex(), recipientPkh);
        Claim claim = claimFactory.apply(ph);

        // Redeemer = the BBS presentation. The ledger verifies it natively.
        var redeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(claim.abar()),
                        new BytesPlutusData(claim.bbar()),
                        new BytesPlutusData(claim.d()),
                        BigIntPlutusData.of(claim.eHat()),
                        BigIntPlutusData.of(claim.r1Hat()),
                        BigIntPlutusData.of(claim.r3Hat()),
                        BigIntPlutusData.of(claim.mHats().get(0)),
                        BigIntPlutusData.of(claim.mHats().get(1)),
                        BigIntPlutusData.of(claim.mHats().get(2)),
                        BigIntPlutusData.of(claim.challenge()),
                        new BytesPlutusData(claim.country()),
                        new BytesPlutusData(claim.kycLevel()),
                        new BytesPlutusData(claim.presentationHeader())))
                .build();

        // Every payment carries the voucher's outref as its inline datum, the tag the validator
        // counts. The funder's remainder goes to its enterprise address, never the change address,
        // so fee balancing can't take the fee out of a tagged output. Same key: one combined output.
        var tag = outRefTag(voucher.getTxHash(), voucher.getOutputIndex());
        var claimTx = new ScriptTx().collectFrom(voucher, redeemer);
        if (Arrays.equals(recipientPkh, funderPkh)) {
            claimTx.payToContract(funderAddress, Amount.lovelace(BigInteger.valueOf(refundLovelace + remainder)), tag);
        } else {
            claimTx.payToContract(recipientAddress, Amount.lovelace(BigInteger.valueOf(refundLovelace)), tag);
            if (remainder > 0)
                claimTx.payToContract(funderAddress, Amount.lovelace(BigInteger.valueOf(remainder)), tag);
        }
        claimTx.attachSpendingValidator(script);
        // Local Julc evaluation is the default; its ExUnits match the ledger exactly.
        // Callers can pass evaluateLocally=false to use the backend/node evaluator instead.
        var builder = new QuickTxBuilder(backendService).compose(claimTx);
        if (evaluateLocally) {
            builder = builder.withTxEvaluator(LocalJulcEvaluator.create(backendService));
        }
        var result = builder
                .withSigner(SignerProviders.signerFrom(funder))
                .feePayer(funder.baseAddress())
                .collateralPayer(funder.baseAddress())
                .withCollateralInputs(collateralInput)
                .completeAndWait();
        if (!result.isSuccessful())
            throw new RuntimeException("on-chain KYC claim failed: " + result.getResponse());
        waitForTx(result.getValue());
        return result.getValue();
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

    private byte[] funderPkh() {
        return new Address(funder.baseAddress()).getPaymentCredentialHash()
                .orElseThrow(() -> new IllegalStateException("funder has no payment key credential"));
    }

    /** The funder's enterprise address: its payment key, apart from the change address. */
    private String funderTagAddress() {
        return funder.enterpriseAddress();
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

    private void awaitUtxo(String txHash, String address) throws Exception {
        var supplier = new DefaultUtxoSupplier(backendService.getUtxoService());
        for (int i = 0; i < 20; i++) {
            boolean seen = supplier.getAll(address).stream().anyMatch(u -> u.getTxHash().equals(txHash));
            if (seen) return;
            Thread.sleep(1000);
        }
    }

    private Utxo findFreshAdaCollateral(String address, String lockTxHash) throws Exception {
        var supplier = new DefaultUtxoSupplier(backendService.getUtxoService());
        for (int i = 0; i < 30; i++) {
            Optional<Utxo> collateral = supplier.getAll(address).stream()
                    .filter(u -> lockTxHash.equals(u.getTxHash()))
                    .filter(OnChainKycClaimService::isAdaOnly)
                    .filter(u -> lovelaceOf(u) >= COLLATERAL_ADA * 1_000_000L)
                    .findFirst();
            if (collateral.isPresent()) return collateral.get();
            Thread.sleep(1000);
        }
        throw new RuntimeException("No ADA-only collateral output from lock tx " + lockTxHash);
    }

    /** Big-endian 8-byte encoding — matches the validator's {@code integerToByteString(true, 8, i)}. */
    private static byte[] i2osp8(long value) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (value & 0xff);
            value >>>= 8;
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
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
}
