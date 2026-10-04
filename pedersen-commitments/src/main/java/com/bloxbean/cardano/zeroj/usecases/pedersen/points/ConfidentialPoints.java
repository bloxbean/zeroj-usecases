package com.bloxbean.cardano.zeroj.usecases.pedersen.points;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
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
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.KeyedCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.circuit.PointsRedeemProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.circuit.PointsTransferProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.points.onchain.PointsLedger;
import org.julclang.clientlib.JulcScriptLoader;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Confidential loyalty points (ADR-0006 demo A): the wallet side and the transactions.
 *
 * <p>A {@link Note}'s amount and blinding are its <b>opening</b>; only the owner (and whoever
 * created the note) knows it. On-chain there is only the commitment.
 */
public final class ConfidentialPoints {

    /** The note token's name under the points policy. */
    public static final byte[] NOTE_TOKEN = "PTS".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    /** A note as its owner sees it: owner key hash, hidden amount, blinding and commitment. */
    public record Note(byte[] owner, long amount, BigInteger blinding, JubjubPoint commitment) {
        public static Note of(byte[] owner, long amount) {
            BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
            return new Note(owner, amount, r, PedersenCommitment.commit(BigInteger.valueOf(amount), r).normalized());
        }
    }

    private final KeyedCircuit transfer;
    private final KeyedCircuit redeem;

    public ConfidentialPoints() {
        transfer = KeyedCircuit.compile("points-transfer", PointsTransferProofCircuit.build());
        redeem = KeyedCircuit.compile("points-redeem", PointsRedeemProofCircuit.build());
    }

    public KeyedCircuit transferCircuit() { return transfer; }

    public KeyedCircuit redeemCircuit() { return redeem; }

    // ------------------------------------------------------------------
    //  Proofs
    // ------------------------------------------------------------------

    public static PointsTransferProofCircuit.Inputs transferInputs(Note in, Note out1, Note out2) {
        return PointsTransferProofCircuit.inputs()
                .inU(in.commitment().affineU()).inV(in.commitment().affineV())
                .out1U(out1.commitment().affineU()).out1V(out1.commitment().affineV())
                .out2U(out2.commitment().affineU()).out2V(out2.commitment().affineV())
                .inAmount(in.amount()).inBlinding(in.blinding())
                .out1Amount(out1.amount()).out1Blinding(out1.blinding())
                .out2Amount(out2.amount()).out2Blinding(out2.blinding());
    }

    public static PointsRedeemProofCircuit.Inputs redeemInputs(Note in, Note change, long price) {
        return PointsRedeemProofCircuit.inputs()
                .inU(in.commitment().affineU()).inV(in.commitment().affineV())
                .changeU(change.commitment().affineU()).changeV(change.commitment().affineV())
                .price(price)
                .inAmount(in.amount()).inBlinding(in.blinding())
                .changeAmount(change.amount()).changeBlinding(change.blinding());
    }

    /** Proves {@code in = out1 + out2}; throws if the amounts do not balance. */
    public Groth16ProofBLS381 proveTransfer(Note in, Note out1, Note out2) {
        return transfer.prove(transferInputs(in, out1, out2).toWitnessMap());
    }

    /** Proves {@code in = change + price}; throws if the amounts do not balance. */
    public Groth16ProofBLS381 proveRedeem(Note in, Note change, long price) {
        return redeem.prove(redeemInputs(in, change, price).toWitnessMap());
    }

    // ------------------------------------------------------------------
    //  Script and encodings
    // ------------------------------------------------------------------

    /** The points ledger for one issuer: policy id and note address share its hash. */
    public PlutusScript script(byte[] issuerPkh) {
        var t = transfer.compressedVk();
        var r = redeem.compressedVk();
        return JulcScriptLoader.load(PointsLedger.class,
                new BytesPlutusData(issuerPkh),
                new BytesPlutusData(NOTE_TOKEN),
                new BytesPlutusData(t.alpha()), new BytesPlutusData(t.beta()),
                new BytesPlutusData(t.gamma()), new BytesPlutusData(t.delta()), Plutus.icData(t.ic()),
                new BytesPlutusData(r.alpha()), new BytesPlutusData(r.beta()),
                new BytesPlutusData(r.gamma()), new BytesPlutusData(r.delta()), Plutus.icData(r.ic()));
    }

    /** {@code Note(owner, u, v)}. */
    public static ConstrPlutusData noteDatum(Note n) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(n.owner()),
                BigIntPlutusData.of(n.commitment().affineU()),
                BigIntPlutusData.of(n.commitment().affineV()))).build();
    }

    /** {@code Receipt(owner, price)}. */
    public static ConstrPlutusData receiptDatum(byte[] owner, long price) {
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(owner), BigIntPlutusData.of(price))).build();
    }

    /** The receipt token's name: {@code blake2b_256(txId ‖ I2OSP2(index))} of the redeemed note. */
    public static byte[] receiptName(Utxo note) {
        return Blake2bUtil.blake2bHash256(Fields.concat(HexUtil.decodeHexString(note.getTxHash()),
                Fields.i2osp(BigInteger.valueOf(note.getOutputIndex()), 2)));
    }

    // ------------------------------------------------------------------
    //  Transactions
    // ------------------------------------------------------------------

    /** The issuer creates new notes. */
    public static Result<String> issue(BackendService backend, PlutusScript script, Account issuer,
                                       List<Note> notes) {
        String policyId = Plutus.policyId(script);
        String address = address(script);
        var tx = new ScriptTx()
                .mintAsset(script, List.of(new Asset("0x" + HexUtil.encodeHexString(NOTE_TOKEN),
                        BigInteger.valueOf(notes.size()))), action(0));
        for (Note n : notes) {
            tx = tx.payToContract(address, noteAmounts(policyId), noteDatum(n));
        }
        return new QuickTxBuilder(backend).compose(tx)
                .withTxEvaluator(DevKit.evaluator(backend))
                .withSigner(SignerProviders.signerFrom(issuer))
                .withRequiredSigners(issuer.hdKeyPair().getPublicKey().getKeyHash())
                .feePayer(issuer.baseAddress())
                .collateralPayer(issuer.baseAddress())
                .complete();
    }

    /** The owner splits {@code noteUtxo} into two notes, with a proof that the amounts balance. */
    public static Result<String> transfer(BackendService backend, PlutusScript script, Account owner,
                                          Utxo noteUtxo, Note out1, Note out2, Groth16ProofBLS381 proof) {
        String policyId = Plutus.policyId(script);
        String address = address(script);
        var p = ProverToCardano.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(p.piA()), new BytesPlutusData(p.piB()), new BytesPlutusData(p.piC()))).build();
        var tx = new ScriptTx()
                .collectFrom(noteUtxo, redeemer)
                .mintAsset(script, List.of(new Asset("0x" + HexUtil.encodeHexString(NOTE_TOKEN), BigInteger.ONE)),
                        action(1))
                .payToContract(address, noteAmounts(policyId), noteDatum(out1))
                .payToContract(address, noteAmounts(policyId), noteDatum(out2))
                .attachSpendingValidator(script);
        return submit(backend, tx, owner);
    }

    /**
     * The owner spends {@code price} points at the issuer and keeps {@code change} as a new note
     * (which may belong to someone else). A receipt token goes to the issuer with datum
     * {@code Receipt(owner, price)}, naming the spender.
     */
    public static Result<String> redeem(BackendService backend, PlutusScript script, Account owner,
                                        String issuerAddress, Utxo noteUtxo, Note change, long price,
                                        Groth16ProofBLS381 proof) {
        String policyId = Plutus.policyId(script);
        String address = address(script);
        byte[] receipt = receiptName(noteUtxo);
        var p = ProverToCardano.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(1).data(ListPlutusData.of(
                BigIntPlutusData.of(price),
                new BytesPlutusData(p.piA()), new BytesPlutusData(p.piB()), new BytesPlutusData(p.piC()))).build();
        var tx = new ScriptTx()
                .collectFrom(noteUtxo, redeemer)
                .mintAsset(script, List.of(new Asset("0x" + HexUtil.encodeHexString(receipt), BigInteger.ONE)),
                        action(2))
                .payToContract(address, noteAmounts(policyId), noteDatum(change))
                .payToContract(issuerAddress,
                        List.of(Amount.ada(2), new Amount(policyId + HexUtil.encodeHexString(receipt), BigInteger.ONE)),
                        receiptDatum(owner.hdKeyPair().getPublicKey().getKeyHash(), price))
                .attachSpendingValidator(script);
        return submit(backend, tx, owner);
    }

    public static String address(PlutusScript script) {
        try {
            return AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<Amount> noteAmounts(String policyId) {
        List<Amount> amounts = new ArrayList<>();
        amounts.add(Amount.ada(2));
        amounts.add(new Amount(policyId + HexUtil.encodeHexString(NOTE_TOKEN), BigInteger.ONE));
        return amounts;
    }

    /** {@code Issue} / {@code Split} / {@code Receipt}: {@code Constr tag [I 0]}. */
    private static PlutusData action(int tag) {
        return ConstrPlutusData.builder().alternative(tag).data(ListPlutusData.of(BigIntPlutusData.of(0))).build();
    }

    private static Result<String> submit(BackendService backend, ScriptTx tx, Account owner) {
        try {
            return new QuickTxBuilder(backend).compose(tx)
                    .withTxEvaluator(DevKit.evaluator(backend))
                    .withSigner(SignerProviders.signerFrom(owner))
                    .withRequiredSigners(owner.hdKeyPair().getPublicKey().getKeyHash())
                    .feePayer(owner.baseAddress())
                    .collateralPayer(owner.baseAddress())
                    .complete();
        } catch (RuntimeException e) {
            return Result.error(e.getMessage());
        }
    }
}
