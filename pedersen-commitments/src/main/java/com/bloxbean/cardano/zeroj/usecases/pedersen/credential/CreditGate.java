package com.bloxbean.cardano.zeroj.usecases.pedersen.credential;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.client.crypto.VerificationKey;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.transaction.spec.script.ScriptPubkey;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.KeyedCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.circuit.CreditProfileProof;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.circuit.CreditProfileProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.onchain.CreditGatePolicy;
import org.julclang.clientlib.JulcScriptLoader;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

/**
 * Committed credentials (ADR-0006 demo B): the bureau issues one vector commitment to a holder's
 * credit profile; the holder later proves predicates over it to a lender's gate.
 */
public final class CreditGate {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** A credit profile and the blinding of its commitment: the holder's opening. */
    public record Profile(long income, int creditScore, int birthYear, int country, BigInteger blinding) {
        public static Profile of(long income, int creditScore, int birthYear, int country) {
            return new Profile(income, creditScore, birthYear, country, PedersenCommitment.randomBlinding(RANDOM));
        }

        public List<BigInteger> values() {
            return List.of(BigInteger.valueOf(income), BigInteger.valueOf(creditScore),
                    BigInteger.valueOf(birthYear), BigInteger.valueOf(country));
        }

        public PedersenVectorCommitment commitment() {
            return PedersenVectorCommitment.commit(CreditProfileProof.SCHEMA, values(), blinding);
        }
    }

    private final KeyedCircuit circuit;

    public CreditGate() {
        circuit = KeyedCircuit.compile("credit-profile-check", CreditProfileProofCircuit.build());
    }

    public KeyedCircuit circuit() { return circuit; }

    public static CreditProfileProofCircuit.Inputs inputs(Profile p, long minIncome, int minScore) {
        var c = p.commitment().point().normalized();
        return CreditProfileProofCircuit.inputs()
                .schemaDigest(CreditProfileProof.SCHEMA.digest())
                .u(c.affineU()).v(c.affineV())
                .minIncome(minIncome).minScore(minScore)
                .income(p.income()).creditScore(p.creditScore())
                .birthYear(p.birthYear()).country(p.country())
                .blinding(p.blinding());
    }

    /** Proves the profile meets the thresholds; throws if it does not. */
    public Groth16ProofBLS381 prove(Profile p, long minIncome, int minScore) {
        return circuit.prove(inputs(p, minIncome, minScore).toWitnessMap());
    }

    /** The lender's gate for one bureau and one pair of thresholds. */
    public PlutusScript gate(byte[] issuerPolicyId, long minIncome, int minScore) {
        var vk = circuit.compressedVk();
        return JulcScriptLoader.load(CreditGatePolicy.class,
                new BytesPlutusData(Fields.i2osp(CreditProfileProof.SCHEMA.digest(), 32)),
                new BytesPlutusData(issuerPolicyId),
                BigIntPlutusData.of(minIncome),
                BigIntPlutusData.of(minScore),
                new BytesPlutusData(vk.alpha()), new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()), new BytesPlutusData(vk.delta()), Plutus.icData(vk.ic()));
    }

    /** The bureau's issuing policy: a native script that only its key can satisfy. */
    public static ScriptPubkey bureauPolicy(Account bureau) throws Exception {
        return ScriptPubkey.create(VerificationKey.create(bureau.publicKeyBytes()));
    }

    /** {@code blake2b_256(I2OSP32(u) ‖ I2OSP32(v) ‖ I2OSP32(σ) ‖ holder)}. */
    public static byte[] recordTokenName(PedersenVectorCommitment c, byte[] holder) {
        var p = c.point().normalized();
        return Blake2bUtil.blake2bHash256(Fields.concat(Fields.i2osp(p.affineU(), 32), Fields.i2osp(p.affineV(), 32),
                Fields.i2osp(c.schema().digest(), 32), holder));
    }

    /** {@code Record(u, v, σ, holder)}. */
    public static ConstrPlutusData recordDatum(PedersenVectorCommitment c, byte[] holder) {
        var p = c.point().normalized();
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                BigIntPlutusData.of(p.affineU()), BigIntPlutusData.of(p.affineV()),
                BigIntPlutusData.of(c.schema().digest()), new BytesPlutusData(holder))).build();
    }

    /** The bureau records the issuance on-chain, at the holder's address. */
    public static Result<String> issueRecord(BackendService backend, Account bureau, String holderAddress,
                                             byte[] holder, PedersenVectorCommitment c) throws Exception {
        ScriptPubkey policy = bureauPolicy(bureau);
        byte[] name = recordTokenName(c, holder);
        String unit = policy.getPolicyId() + HexUtil.encodeHexString(name);
        var tx = new Tx()
                .mintAssets(policy, new Asset("0x" + HexUtil.encodeHexString(name), BigInteger.ONE))
                .payToContract(holderAddress, List.of(Amount.ada(2), new Amount(unit, BigInteger.ONE)),
                        recordDatum(c, holder))
                .from(bureau.baseAddress());
        return new QuickTxBuilder(backend).compose(tx).withSigner(SignerProviders.signerFrom(bureau)).complete();
    }

    /** The holder claims a badge from the gate, referencing the issuance record. */
    public static Result<String> claim(BackendService backend, PlutusScript gate, Account holder,
                                       PedersenVectorCommitment c, Utxo record, Groth16ProofBLS381 proof) {
        byte[] holderPkh = holder.hdKeyPair().getPublicKey().getKeyHash();
        String policyId = Plutus.policyId(gate);
        var p = c.point().normalized();
        var pc = ProverToCardano.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(holderPkh),
                BigIntPlutusData.of(p.affineU()), BigIntPlutusData.of(p.affineV()),
                new BytesPlutusData(pc.piA()), new BytesPlutusData(pc.piB()), new BytesPlutusData(pc.piC()))).build();
        var tx = new ScriptTx()
                .mintAsset(gate, List.of(new Asset("0x" + HexUtil.encodeHexString(holderPkh), BigInteger.ONE)), redeemer)
                .payToAddress(holder.baseAddress(),
                        List.of(Amount.ada(2), new Amount(policyId + HexUtil.encodeHexString(holderPkh), BigInteger.ONE)));
        if (record != null) tx = tx.readFrom(record);
        try {
            return new QuickTxBuilder(backend).compose(tx)
                    .withTxEvaluator(DevKit.evaluator(backend))
                    .withSigner(SignerProviders.signerFrom(holder))
                    .withRequiredSigners(holderPkh)
                    .feePayer(holder.baseAddress())
                    .collateralPayer(holder.baseAddress())
                    .complete();
        } catch (RuntimeException e) {
            return Result.error(e.getMessage());
        }
    }
}
