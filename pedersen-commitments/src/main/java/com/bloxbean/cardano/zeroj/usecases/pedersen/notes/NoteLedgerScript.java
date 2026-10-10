package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

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
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.KeyedCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain.NoteLedger;
import org.julclang.clientlib.JulcScriptLoader;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * One {@code NoteLedger} instance (ADR-0007 N2–N4) and its transactions: deploying it as a
 * reference script, issuing (trusted or proved), transferring and redeeming.
 *
 * <p>The ledger is too large to attach to a spending transaction, so it is deployed once into an
 * output at its own address. That output holds no note token, so no transaction can ever spend
 * it, and wallets ignore it (it is not a note).
 */
public final class NoteLedgerScript {

    private final byte[] token;
    private final byte[] issuerPkh;
    private final boolean provedIssuance;
    private final NoteProofs proofs;
    private final Registry registry;
    private final PlutusScript script;
    private final String policyId;
    private final String address;
    private Utxo reference;

    public NoteLedgerScript(byte[] issuerPkh, byte[] token, NoteProofs proofs, Registry registry) {
        this.issuerPkh = issuerPkh.clone();
        this.token = token.clone();
        this.provedIssuance = proofs.provesIssuance();
        this.proofs = proofs;
        this.registry = registry;
        byte[] none = new byte[32];
        this.script = JulcScriptLoader.load(NoteLedger.class,
                new BytesPlutusData(issuerPkh),
                new BytesPlutusData(token),
                BigIntPlutusData.of(provedIssuance ? 1 : 0),
                new BytesPlutusData(registry.policy()),
                new BytesPlutusData(Registry.TOKEN),
                new BytesPlutusData(VerificationKeys.hash(proofs.transfer().compressedVk())),
                new BytesPlutusData(VerificationKeys.hash(proofs.redeem().compressedVk())),
                new BytesPlutusData(provedIssuance ? VerificationKeys.hash(proofs.issue(1).compressedVk()) : none),
                new BytesPlutusData(provedIssuance ? VerificationKeys.hash(proofs.issue(2).compressedVk()) : none));
        this.policyId = Plutus.policyId(script);
        try {
            this.address = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public PlutusScript script() { return script; }

    public String policyId() { return policyId; }

    public String address() { return address; }

    public byte[] token() { return token.clone(); }

    public String unit() { return policyId + HexUtil.encodeHexString(token); }

    public Registry registry() { return registry; }

    public NoteProofs proofs() { return proofs; }

    public boolean provedIssuance() { return provedIssuance; }

    public Utxo reference() {
        if (reference == null) throw new IllegalStateException("deploy the ledger's reference script first");
        return reference;
    }

    /** Deploys the script as a reference script at the ledger's own address (never spendable). */
    public Result<String> deploy(BackendService backend, Account payer) {
        try {
            var tx = new Tx()
                    .payToContract(address, List.of(Amount.ada(40)), PlutusData.unit(), script)
                    .from(payer.baseAddress());
            var result = new QuickTxBuilder(backend).compose(tx)
                    .withSigner(SignerProviders.signerFrom(payer))
                    .complete();
            if (result.isSuccessful()) {
                DevKit.waitForTx(backend, result.getValue());
                reference = DevKit.utxosOf(backend, address, result.getValue()).getFirst();
            }
            return result;
        } catch (Exception e) {
            return Result.error(e.getMessage());
        }
    }

    /** Uses an already deployed reference script. */
    public void useReference(Utxo deployed) {
        this.reference = deployed;
    }

    // ------------------------------------------------------------------ issuance

    /** Trusted issuance (points): the issuer supplies the notes' audit data and is trusted for it. */
    public Result<String> issue(BackendService backend, Account issuer, List<AuditedNote> notes) {
        if (provedIssuance) throw new IllegalStateException("this ledger issues with a proof");
        var tx = new ScriptTx()
                .mintAsset(policyId, List.of(new Asset(tokenHex(), BigInteger.valueOf(notes.size()))),
                        ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(BigIntPlutusData.of(0))).build())
                .readFrom(registry.currentUtxo(backend));
        for (AuditedNote n : notes) tx = tx.payToContract(address, noteValue(backend, n), n.datum());
        return submit(backend, tx, issuer);
    }

    /** Proved issuance (payroll): one or two notes and the proof that their limbs encrypt their amounts. */
    public Result<String> provedIssue(BackendService backend, Account issuer, List<AuditedNote> notes,
                                      Groth16ProofBLS381 proof) {
        if (!provedIssuance) throw new IllegalStateException("this ledger issues without a proof");
        KeyedCircuit circuit = proofs.issue(notes.size());
        var tx = new ScriptTx()
                .mintAsset(policyId, List.of(new Asset(tokenHex(), BigInteger.valueOf(notes.size()))),
                        proofRedeemer(3, null, proof, circuit))
                .readFrom(registry.currentUtxo(backend));
        for (AuditedNote n : notes) tx = tx.payToContract(address, noteValue(backend, n), n.datum());
        return submit(backend, tx, issuer);
    }

    // ------------------------------------------------------------------ spending

    /** The owner splits {@code note} into {@code out1} and {@code out2}. */
    public Result<String> transfer(BackendService backend, Account owner, Utxo note, AuditedNote out1,
                                   AuditedNote out2, Groth16ProofBLS381 proof) {
        var tx = new ScriptTx()
                .collectFrom(note, proofRedeemer(0, null, proof, proofs.transfer()))
                .mintAsset(policyId, List.of(new Asset(tokenHex(), BigInteger.ONE)),
                        ConstrPlutusData.builder().alternative(1).data(ListPlutusData.of(BigIntPlutusData.of(0))).build())
                .readFrom(registry.currentUtxo(backend))
                .payToContract(address, noteValue(backend, out1), out1.datum())
                .payToContract(address, noteValue(backend, out2), out2.datum());
        return submit(backend, tx, owner);
    }

    /**
     * The address-policy cheat (ADR-0007 N2; ZeroJ ADR-0055 M3 criterion (a)): an honest transfer
     * plus a copy of {@code out1} paid under the ledger's payment credential with another stake
     * credential. The ledger refuses the whole transaction.
     */
    public Result<String> transferWithStakeVariantCopy(BackendService backend, Account owner, Utxo note, AuditedNote out1,
                                                       AuditedNote out2, Groth16ProofBLS381 proof) {
        String staked;
        try {
            staked = AddressProvider.getBaseAddress(script, owner.hdKeyPair().getPublicKey(), Networks.testnet()).toBech32();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        var tx = new ScriptTx()
                .collectFrom(note, proofRedeemer(0, null, proof, proofs.transfer()))
                .mintAsset(policyId, List.of(new Asset(tokenHex(), BigInteger.ONE)),
                        ConstrPlutusData.builder().alternative(1).data(ListPlutusData.of(BigIntPlutusData.of(0))).build())
                .readFrom(registry.currentUtxo(backend))
                .payToContract(address, noteValue(backend, out1), out1.datum())
                .payToContract(address, noteValue(backend, out2), out2.datum())
                .payToContract(staked, List.of(Amount.ada(4)), out1.datum());
        return submit(backend, tx, owner);
    }

    /** The owner pays {@code price} at the issuer and keeps {@code change}; a receipt goes to the issuer. */
    public Result<String> redeem(BackendService backend, Account owner, String issuerAddress, Utxo note,
                                 AuditedNote change, long price, Groth16ProofBLS381 proof) {
        byte[] receipt = receiptName(note);
        var tx = new ScriptTx()
                .collectFrom(note, proofRedeemer(1, BigInteger.valueOf(price), proof, proofs.redeem()))
                .mintAsset(policyId, List.of(new Asset("0x" + HexUtil.encodeHexString(receipt), BigInteger.ONE)),
                        ConstrPlutusData.builder().alternative(2).data(ListPlutusData.of(BigIntPlutusData.of(0))).build())
                .readFrom(registry.currentUtxo(backend))
                .payToContract(address, noteValue(backend, change), change.datum())
                .payToContract(issuerAddress,
                        List.of(Amount.ada(2), new Amount(policyId + HexUtil.encodeHexString(receipt), BigInteger.ONE)),
                        receiptDatum(owner.hdKeyPair().getPublicKey().getKeyHash(), price));
        return submit(backend, tx, owner);
    }

    // ------------------------------------------------------------------ encodings

    /** {@code Constr tag [price?, piA, piB, piC, vk]}. */
    private static ConstrPlutusData proofRedeemer(int tag, BigInteger price, Groth16ProofBLS381 proof, KeyedCircuit circuit) {
        var p = ProverToCardano.compressProof(proof);
        List<PlutusData> fields = new ArrayList<>();
        if (price != null) fields.add(BigIntPlutusData.of(price));
        fields.add(new BytesPlutusData(p.piA()));
        fields.add(new BytesPlutusData(p.piB()));
        fields.add(new BytesPlutusData(p.piC()));
        fields.add(VerificationKeys.data(circuit.compressedVk()));
        return ConstrPlutusData.builder().alternative(tag).data(ListPlutusData.of(fields.toArray(new PlutusData[0]))).build();
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

    /** Exactly lovelace (the computed minimum) and one note token. */
    private List<Amount> noteValue(BackendService backend, AuditedNote note) {
        List<Amount> token = List.of(new Amount(unit(), BigInteger.ONE));
        List<Amount> value = new ArrayList<>();
        value.add(new Amount("lovelace", Plutus.minAda(backend, address, token, note.datum())));
        value.addAll(token);
        return value;
    }

    private String tokenHex() {
        return "0x" + HexUtil.encodeHexString(token);
    }

    private Result<String> submit(BackendService backend, ScriptTx tx, Account signer) {
        try {
            return new QuickTxBuilder(backend).compose(tx.readFrom(reference()))
                    .withReferenceScripts(script)
                    .withTxEvaluator(DevKit.evaluator(backend))
                    .withSigner(SignerProviders.signerFrom(signer))
                    .withRequiredSigners(signer.hdKeyPair().getPublicKey().getKeyHash())
                    .feePayer(signer.baseAddress())
                    .collateralPayer(signer.baseAddress())
                    .complete();
        } catch (RuntimeException e) {
            return Result.error(e.getMessage());
        }
    }

    byte[] issuerPkh() {
        return issuerPkh.clone();
    }
}
