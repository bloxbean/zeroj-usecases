package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Result;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusScript;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain.AuditorRegistry;
import org.julclang.clientlib.JulcScriptLoader;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * One auditor registry instance (ADR-0007 N1): its script, address and policy, the Init and
 * Rotate transactions, and the current entry read from the chain.
 *
 * <p>The instance is fixed by its seed output, which Init must spend. Its policy id is what a
 * ledger (or an auction) pins as {@code registryPolicy}.
 */
public final class Registry {

    public static final byte[] TOKEN = "REG".getBytes(StandardCharsets.UTF_8);
    private final PlutusScript script;
    private final KeyPossession possession;
    private final String seedTxHash;
    private final int seedIndex;
    private final byte[] policy;
    private final String address;

    private Registry(PlutusScript script, KeyPossession possession, String seedTxHash, int seedIndex) {
        this.script = script;
        this.possession = possession;
        this.seedTxHash = seedTxHash;
        this.seedIndex = seedIndex;
        this.policy = HexUtil.decodeHexString(Plutus.policyId(script));
        try {
            this.address = AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The registry whose Init must spend {@code seedTxHash#seedIndex}. */
    public static Registry forSeed(String seedTxHash, int seedIndex, KeyPossession possession) {
        var vk = possession.circuit().compressedVk();
        // The base X = G of every possession statement (elgamal-jubjub-v1 §3.3).
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR.normalized();
        PlutusScript script = JulcScriptLoader.load(AuditorRegistry.class,
                new BytesPlutusData(seedRef(seedTxHash, seedIndex)),
                new BytesPlutusData(TOKEN),
                new BytesPlutusData(KeyPossession.ctxPrefix(KeyPossession.KeyType.ELGAMAL)),
                new BytesPlutusData(KeyPossession.ctxPrefix(KeyPossession.KeyType.VIEWING)),
                BigIntPlutusData.of(g.affineU()), BigIntPlutusData.of(g.affineV()),
                new BytesPlutusData(vk.alpha()), new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()), new BytesPlutusData(vk.delta()), Plutus.icData(vk.ic()));
        return new Registry(script, possession, seedTxHash, seedIndex);
    }

    /** {@code txId ‖ I2OSP2(index)}, as {@code ValuesLib.refBytes}. */
    public static byte[] seedRef(String txHash, int index) {
        return Fields.concat(HexUtil.decodeHexString(txHash), Fields.i2osp(BigInteger.valueOf(index), 2));
    }

    public PlutusScript script() { return script; }

    public byte[] policy() { return policy.clone(); }

    public String policyHex() { return HexUtil.encodeHexString(policy); }

    public String address() { return address; }

    public String unit() { return policyHex() + HexUtil.encodeHexString(TOKEN); }

    public KeyPossession possession() { return possession; }

    // ------------------------------------------------------------------ transactions

    /** Creates the registry with generation 0, spending {@code seed} and signed by the auditor. */
    public Result<String> init(BackendService backend, Account auditor, Utxo seed, RegistryEntry entry) {
        if (entry.generation() != 0) throw new IllegalArgumentException("Init creates generation 0");
        if (!seed.getTxHash().equals(seedTxHash) || seed.getOutputIndex() != seedIndex) {
            throw new IllegalArgumentException("this registry's Init must spend " + seedTxHash + "#" + seedIndex);
        }
        requireKey(auditor, entry.auditor(), "the auditor");
        AdmittedAuditor.admit(policy, entry, possession); // fail before submitting what the script would refuse
        List<Amount> held = entryValue(backend, entry);
        var tx = new ScriptTx()
                .collectFrom(seed)
                .mintAsset(script, List.of(new Asset("0x" + HexUtil.encodeHexString(TOKEN), BigInteger.ONE)),
                        PlutusData.unit())
                .payToContract(address, held, entry.toPlutusData());
        return submit(backend, tx, List.of(auditor), auditor);
    }

    /** Moves the entry forward one generation, signed by the old and the new auditor. */
    public Result<String> rotate(BackendService backend, Account oldAuditor, Account newAuditor, RegistryEntry next) {
        RegistryEntry old = current(backend);
        requireKey(oldAuditor, old.auditor(), "the current auditor");
        requireKey(newAuditor, next.auditor(), "the new auditor");
        if (next.generation() != old.generation() + 1) {
            throw new IllegalArgumentException("a rotation moves to generation " + (old.generation() + 1));
        }
        AdmittedAuditor.admit(policy, next, possession);
        Utxo current = currentUtxo(backend);
        var tx = new ScriptTx()
                .collectFrom(current, PlutusData.unit())
                .payToContract(address, entryValue(backend, next), next.toPlutusData())
                .attachSpendingValidator(script);
        List<Account> signers = Arrays.equals(keyHash(oldAuditor), keyHash(newAuditor))
                ? List.of(oldAuditor) : List.of(oldAuditor, newAuditor);
        return submit(backend, tx, signers, oldAuditor);
    }

    private static byte[] keyHash(Account account) {
        return account.hdKeyPair().getPublicKey().getKeyHash();
    }

    private static void requireKey(Account account, byte[] expected, String who) {
        if (!Arrays.equals(keyHash(account), expected)) {
            throw new IllegalArgumentException(who + "'s key hash is not the entry's auditor");
        }
    }

    private List<Amount> entryValue(BackendService backend, RegistryEntry entry) {
        List<Amount> token = List.of(new Amount(unit(), BigInteger.ONE));
        List<Amount> held = new ArrayList<>();
        held.add(new Amount("lovelace", Plutus.minAda(backend, address, token, entry.toPlutusData())));
        held.addAll(token);
        return held;
    }

    private static Result<String> submit(BackendService backend, ScriptTx tx, List<Account> signers, Account payer) {
        try {
            var builder = new QuickTxBuilder(backend).compose(tx)
                    .withTxEvaluator(DevKit.evaluator(backend))
                    .feePayer(payer.baseAddress())
                    .collateralPayer(payer.baseAddress());
            var signer = SignerProviders.signerFrom(signers.getFirst());
            List<byte[]> required = new ArrayList<>();
            for (Account a : signers) required.add(a.hdKeyPair().getPublicKey().getKeyHash());
            for (int i = 1; i < signers.size(); i++) signer = signer.andThen(SignerProviders.signerFrom(signers.get(i)));
            return builder.withSigner(signer).withRequiredSigners(required.toArray(new byte[0][])).complete();
        } catch (RuntimeException e) {
            return Result.error(e.getMessage());
        }
    }

    // ------------------------------------------------------------------ reading

    /** The one UTxO holding the registry token, at the exact registry address. */
    public Utxo currentUtxo(BackendService backend) {
        try {
            for (int page = 1; ; page++) {
                var r = backend.getUtxoService().getUtxos(address, 100, page);
                if (!r.isSuccessful() || r.getValue() == null || r.getValue().isEmpty()) break;
                for (Utxo u : r.getValue()) {
                    if (u.getAmount().stream().anyMatch(a -> a.getUnit().equals(unit())
                            && a.getQuantity().equals(BigInteger.ONE))) {
                        return u;
                    }
                }
                if (r.getValue().size() < 100) break;
            }
        } catch (Exception e) {
            throw new IllegalStateException("could not read the registry: " + e.getMessage(), e);
        }
        throw new IllegalStateException("no registry entry at " + address);
    }

    /** The current entry, parsed strictly (shape only; admission is {@link AdmittedAuditor#admit}). */
    public RegistryEntry current(BackendService backend) {
        Utxo u = currentUtxo(backend);
        try {
            return RegistryEntry.fromPlutusData(PlutusData.deserialize(HexUtil.decodeHexString(u.getInlineDatum())));
        } catch (Exception e) {
            throw new IllegalStateException("registry datum unreadable: " + e.getMessage(), e);
        }
    }

    /** The current entry, admitted: possession proofs verified under this registry (ADR-0007 N5). */
    public AdmittedAuditor admitted(BackendService backend) {
        return AdmittedAuditor.admit(policy, current(backend), possession);
    }
}
