package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.function.TxSigner;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.transaction.spec.MultiAsset;
import com.bloxbean.cardano.client.transaction.spec.Transaction;
import com.bloxbean.cardano.client.transaction.spec.TransactionInput;
import com.bloxbean.cardano.client.transaction.spec.TransactionOutput;
import com.bloxbean.cardano.client.util.HexUtil;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * The passport transactions (ADR-0009 D1).
 * <ul>
 *   <li><b>Issue</b>: one transaction, built and paid by the manufacturer, that mints
 *       {@code {productId: 1}} into the passport address with the passport datum. The auditor
 *       co-signs it only after checking the transaction against its own report
 *       ({@link #check}) and reserving the product ({@link CoSignGuard}).</li>
 *   <li><b>Revoke</b>: built, signed and paid by the auditor alone; spends the passport and burns
 *       its token.</li>
 * </ul>
 */
public final class PassportTransactions {

    /** The passport output's lovelace: above min-UTxO for a four-claim datum (about 3.1 ADA). */
    public static final BigInteger PASSPORT_LOVELACE = BigInteger.valueOf(5_000_000);

    /**
     * The issue transaction's validity window in slots (one-second slots on DevKit). The
     * auditor's reservation of a product for an unconfirmed transaction is released only after
     * this TTL has passed ({@link CoSignGuard}).
     */
    public static final long ISSUE_TTL_SLOTS = 180;

    private PassportTransactions() {}

    /** {@code Issue(piA, piB, piC)}: the mint redeemer carries only the proof. */
    public static PlutusData issueRedeemer(Groth16ProofBLS381 proof) {
        var p = ProverToCardano.compressProof(proof);
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(p.piA()), new BytesPlutusData(p.piB()), new BytesPlutusData(p.piC()))).build();
    }

    /** {@code Burn(0)}: the mint redeemer of a revocation. */
    public static PlutusData burnRedeemer() {
        return ConstrPlutusData.builder().alternative(1).data(ListPlutusData.of(BigIntPlutusData.of(0))).build();
    }

    /** {@code Revoke(0)}: the only spend redeemer. */
    public static PlutusData revokeRedeemer() {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(BigIntPlutusData.of(0))).build();
    }

    /**
     * The passport transaction. The manufacturer builds, pays and signs; {@code auditorSigner}
     * adds the auditor's signature (normally {@link CoSignGuard#signer}, which refuses a transaction
     * that does not match the auditor's report, or a second passport for the product). The
     * transaction is valid for {@link #ISSUE_TTL_SLOTS} slots. Script evaluation runs locally
     * first: a transaction the script refuses is never submitted.
     */
    public static Result<String> issue(BackendService backend, PassportScript script, Account manufacturer,
                                       TxSigner auditorSigner, PassportDatum datum, Groth16ProofBLS381 proof) {
        return issue(backend, script, manufacturer, auditorSigner, datum, proof,
                RoleKeys.pkh(manufacturer), script.auditorPkh());
    }

    /** As {@link #issue}, with explicit required signers (the negative tests leave the auditor out). */
    public static Result<String> issue(BackendService backend, PassportScript script, Account manufacturer,
                                       TxSigner auditorSigner, PassportDatum datum, Groth16ProofBLS381 proof,
                                       byte[]... requiredSigners) {
        String nameHex = HexUtil.encodeHexString(datum.productId());
        var tx = new ScriptTx()
                .mintAsset(script.script(), List.of(new Asset("0x" + nameHex, BigInteger.ONE)), issueRedeemer(proof))
                .payToContract(script.address(),
                        List.of(new Amount("lovelace", PASSPORT_LOVELACE), new Amount(script.unit(datum.productId()), BigInteger.ONE)),
                        datum.toPlutusData());
        try {
            long ttl = LocalJulcEvaluator.latestSlot(backend) + ISSUE_TTL_SLOTS;
            return new QuickTxBuilder(backend).compose(tx)
                    .withTxEvaluator(LocalJulcEvaluator.create(backend))
                    .validTo(ttl)
                    .withSigner(SignerProviders.signerFrom(manufacturer).andThen(auditorSigner))
                    .withRequiredSigners(requiredSigners)
                    .feePayer(manufacturer.baseAddress())
                    .collateralPayer(manufacturer.baseAddress())
                    .complete();
        } catch (RuntimeException e) {
            return Result.error(e.getMessage());
        }
    }

    /** The auditor revokes a passport on its own: spend with {@code Revoke}, burn {@code {productId: −1}}. */
    public static Result<String> revoke(BackendService backend, PassportScript script, Account auditor,
                                        Utxo passport, byte[] productId) {
        return revoke(backend, script, auditor, passport, productId, script.auditorPkh());
    }

    /** As {@link #revoke}, signed and paid by {@code signer} (the negative tests use someone else). */
    public static Result<String> revoke(BackendService backend, PassportScript script, Account signer,
                                        Utxo passport, byte[] productId, byte[] requiredSigner) {
        var tx = new ScriptTx()
                .collectFrom(passport, revokeRedeemer())
                .mintAsset(script.script(), List.of(new Asset("0x" + HexUtil.encodeHexString(productId), BigInteger.ONE.negate())),
                        burnRedeemer())
                .attachSpendingValidator(script.script())
                .withChangeAddress(signer.baseAddress());
        try {
            return new QuickTxBuilder(backend).compose(tx)
                    .withTxEvaluator(LocalJulcEvaluator.create(backend))
                    .withSigner(SignerProviders.signerFrom(signer))
                    .withRequiredSigners(requiredSigner)
                    .feePayer(signer.baseAddress())
                    .collateralPayer(signer.baseAddress())
                    .complete();
        } catch (RuntimeException e) {
            return Result.error(e.getMessage());
        }
    }

    /**
     * The auditor's check of a finished passport transaction against its report, before it
     * signs ({@link CoSignGuard} adds the once-per-product rule):
     * <ul>
     *   <li>the mint under the passport policy is exactly {@code {productId: 1}};</li>
     *   <li>exactly one output holds the token, at the passport address, with exactly the expected
     *       datum (the auditor's own commitments, this product, this manufacturer);</li>
     *   <li>the auditor is a required signer;</li>
     *   <li>the auditor's signature authorises nothing else: no input or collateral input at an
     *       address whose payment or stake credential is the auditor's key hash, and no withdrawal,
     *       certificate, vote or proposal. Inputs {@code addressOf} cannot resolve are refused.</li>
     * </ul>
     * Anything else throws, and the transaction stays unsigned.
     */
    public static void check(Transaction transaction, PassportScript script, PassportDatum expected,
                             Function<TransactionInput, Optional<String>> addressOf) {
        var body = transaction.getBody();
        String nameHex = HexUtil.encodeHexString(expected.productId());
        List<MultiAsset> mint = body.getMint() == null ? List.of() : body.getMint();
        List<MultiAsset> ours = mint.stream().filter(ma -> ma.getPolicyId().equals(script.policyId())).toList();
        if (ours.size() != 1 || ours.get(0).getAssets().size() != 1
                || !ours.get(0).getAssets().get(0).getNameAsHex().replace("0x", "").equalsIgnoreCase(nameHex)
                || ours.get(0).getAssets().get(0).getValue().compareTo(BigInteger.ONE) != 0) {
            throw new IllegalStateException("auditor refuses to co-sign: the mint is not exactly {" + nameHex + ": 1}");
        }
        List<TransactionOutput> holders = body.getOutputs().stream()
                .filter(o -> o.getValue().getMultiAssets() != null && o.getValue().getMultiAssets().stream()
                        .anyMatch(ma -> ma.getPolicyId().equals(script.policyId())))
                .toList();
        if (holders.size() != 1 || !holders.get(0).getAddress().equals(script.address())) {
            throw new IllegalStateException("auditor refuses to co-sign: the passport is not at the passport address");
        }
        PlutusData datum = holders.get(0).getInlineDatum();
        if (datum == null || !datum.serializeToHex().equals(expected.toPlutusData().serializeToHex())) {
            throw new IllegalStateException("auditor refuses to co-sign: the datum does not match its report");
        }
        boolean required = body.getRequiredSigners() != null
                && body.getRequiredSigners().stream().anyMatch(s -> Arrays.equals(s, script.auditorPkh()));
        if (!required) throw new IllegalStateException("auditor refuses to co-sign: not a required signer");
        if ((body.getWithdrawals() != null && !body.getWithdrawals().isEmpty())
                || (body.getCerts() != null && !body.getCerts().isEmpty())
                || body.getVotingProcedures() != null
                || (body.getProposalProcedures() != null && !body.getProposalProcedures().isEmpty())) {
            throw new IllegalStateException("auditor refuses to co-sign: withdrawals, certificates, votes or proposals");
        }
        List<TransactionInput> spent = new ArrayList<>();
        if (body.getInputs() != null) spent.addAll(body.getInputs());
        if (body.getCollateral() != null) spent.addAll(body.getCollateral());
        for (TransactionInput input : spent) {
            String at = addressOf.apply(input).orElseThrow(() -> new IllegalStateException(
                    "auditor refuses to co-sign: cannot resolve input " + input.getTransactionId() + "#" + input.getIndex()));
            Address address = new Address(at);
            boolean auditors = address.getPaymentCredentialHash().map(h -> Arrays.equals(h, script.auditorPkh())).orElse(false)
                    || address.getDelegationCredentialHash().map(h -> Arrays.equals(h, script.auditorPkh())).orElse(false);
            if (auditors) {
                throw new IllegalStateException("auditor refuses to co-sign: the transaction spends the auditor's own funds (" + at + ")");
            }
        }
    }
}
