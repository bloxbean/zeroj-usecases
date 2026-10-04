package com.bloxbean.cardano.zeroj.usecases.pedersen.solvency;

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
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.circuit.HiddenLiabilitySolvencyProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.solvency.onchain.SolvencyVault;
import org.julclang.clientlib.JulcScriptLoader;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Hidden-liability solvency (ADR-0006 demo C): one Pedersen commitment per customer balance,
 * a proof that the hidden total is at most the reserve locked in the vault, a check each customer
 * runs on their own entry, and an aggregate opening for an auditor.
 */
public final class SolvencyAttestation {

    public static final byte[] ATTEST_TOKEN = "ATTEST".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * A customer as the exchange sees them: id, a fresh 32-byte salt for this period, the
     * balance and its blinding. The customer receives everything but the other customers' data.
     */
    public record Customer(String id, byte[] salt, long balance, BigInteger blinding) {
        public static Customer of(String id, long balance) {
            byte[] salt = new byte[32];
            RANDOM.nextBytes(salt);
            return new Customer(id, salt, balance, PedersenCommitment.randomBlinding(RANDOM));
        }

        /** {@code blake2b_256(I2OSP2(len(id)) ‖ UTF-8(id) ‖ salt)}: unambiguous for any id. */
        public byte[] idHash() {
            byte[] utf8 = id.getBytes(StandardCharsets.UTF_8);
            return Blake2bUtil.blake2bHash256(Fields.concat(
                    Fields.i2osp(BigInteger.valueOf(utf8.length), 2), utf8, salt));
        }

        public JubjubPoint commitment() {
            return PedersenCommitment.commit(BigInteger.valueOf(balance), blinding).normalized();
        }
    }

    /** A published entry: the customer's id hash and balance commitment. */
    public record Entry(byte[] idHash, JubjubPoint commitment) {}

    /**
     * An attestation period {@code [start, end]} (POSIX ms), from the exchange's public schedule.
     * Attestations must be made before {@code start} and stay locked until after {@code end}.
     */
    public record Period(long start, long end) {
        public Period {
            if (end <= start) throw new IllegalArgumentException("period must end after it starts");
        }
    }

    private final int customers;
    private final KeyedCircuit circuit;

    public SolvencyAttestation(int customers) {
        this.customers = customers;
        this.circuit = KeyedCircuit.compile("hidden-liability-solvency-n" + customers,
                HiddenLiabilitySolvencyProofCircuit.build(customers));
    }

    public KeyedCircuit circuit() { return circuit; }

    public int customers() { return customers; }

    public static List<Entry> entries(List<Customer> book) {
        return book.stream().map(c -> new Entry(c.idHash(), c.commitment())).toList();
    }

    public static HiddenLiabilitySolvencyProofCircuit.Inputs inputs(long reserves, List<Customer> book) {
        return HiddenLiabilitySolvencyProofCircuit.inputs(book.size())
                .reserves(reserves)
                .liabilityU(book.stream().map(c -> c.commitment().affineU()).toList())
                .liabilityV(book.stream().map(c -> c.commitment().affineV()).toList())
                .balances(book.stream().map(c -> BigInteger.valueOf(c.balance())).toList())
                .blindings(book.stream().map(Customer::blinding).toList());
    }

    /** Proves {@code Σ balances ≤ reserves}; throws if the exchange is not solvent. */
    public Groth16ProofBLS381 prove(long reserves, List<Customer> book) {
        if (book.size() != customers) throw new IllegalArgumentException("expected " + customers + " customers");
        return circuit.prove(inputs(reserves, book).toWitnessMap());
    }

    // ------------------------------------------------------------------
    //  Checks anyone can run
    // ------------------------------------------------------------------

    /**
     * The customer's check over a set of entries: their id hash appears exactly once, and that
     * entry opens to their balance. Pass every entry of the period ({@link #liveEntries}).
     */
    public static boolean customerCheck(List<Entry> entries, Customer me) {
        byte[] mine = me.idHash();
        List<Entry> matches = entries.stream().filter(e -> Arrays.equals(e.idHash(), mine)).toList();
        return matches.size() == 1
                && PedersenCommitment.verify(matches.getFirst().commitment(), BigInteger.valueOf(me.balance()), me.blinding());
    }

    /** What the exchange hands an auditor: total liabilities and the sum of the blindings mod l. */
    public record AuditOpening(BigInteger liabilities, BigInteger blinding) {}

    public static AuditOpening auditOpening(List<Customer> book) {
        BigInteger total = BigInteger.ZERO;
        BigInteger r = BigInteger.ZERO;
        for (Customer c : book) {
            total = total.add(BigInteger.valueOf(c.balance()));
            r = r.add(c.blinding()).mod(JubjubCurve.SUBGROUP_ORDER);
        }
        return new AuditOpening(total, r);
    }

    /**
     * The auditor's check, by homomorphism: {@code Σ C_i = Commit(L, Σ r_i)} over the published
     * entries. Reveals {@code L} to the auditor and nothing about any single balance.
     */
    public static boolean auditorCheck(List<Entry> entries, AuditOpening opening) {
        JubjubPoint sum = JubjubPoint.IDENTITY;
        for (Entry e : entries) sum = sum.add(e.commitment());
        return PedersenCommitment.verify(sum.normalized(), opening.liabilities(), opening.blinding());
    }

    // ------------------------------------------------------------------
    //  Script, datums and transactions
    // ------------------------------------------------------------------

    /**
     * The vault for one exchange and one period. Customers derive it themselves from the published
     * parameters and verification key, and never take a script the exchange merely points to.
     */
    public PlutusScript vault(byte[] exchangePkh, Period period) {
        var vk = circuit.compressedVk();
        return JulcScriptLoader.load(SolvencyVault.class,
                new BytesPlutusData(exchangePkh),
                new BytesPlutusData(ATTEST_TOKEN),
                BigIntPlutusData.of(customers),
                BigIntPlutusData.of(period.start()),
                BigIntPlutusData.of(period.end()),
                new BytesPlutusData(vk.alpha()), new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()), new BytesPlutusData(vk.delta()), Plutus.icData(vk.ic()));
    }

    public static String address(PlutusScript script) {
        try {
            return AddressProvider.getEntAddress(script, Networks.testnet()).toBech32();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code Attestation([Entry(idHash, u, v)])}. */
    public static ConstrPlutusData attestationDatum(List<Entry> entries) {
        List<PlutusData> items = new ArrayList<>();
        for (Entry e : entries) {
            items.add(ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                    new BytesPlutusData(e.idHash()),
                    BigIntPlutusData.of(e.commitment().affineU()),
                    BigIntPlutusData.of(e.commitment().affineV()))).build());
        }
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                ListPlutusData.of(items.toArray(new PlutusData[0])))).build();
    }

    /**
     * The entries of a live attestation, read from the vault output's inline datum, as a customer
     * or auditor would read them from the chain.
     */
    public static List<Entry> readEntries(Utxo vaultUtxo) {
        try {
            var datum = (ConstrPlutusData) PlutusData.deserialize(HexUtil.decodeHexString(vaultUtxo.getInlineDatum()));
            var entries = (ListPlutusData) datum.getData().getPlutusDataList().get(0);
            List<Entry> out = new ArrayList<>();
            for (PlutusData item : entries.getPlutusDataList()) {
                var f = ((ConstrPlutusData) item).getData().getPlutusDataList();
                out.add(new Entry(((BytesPlutusData) f.get(0)).getValue(), JubjubPoint.fromAffine(
                        ((BigIntPlutusData) f.get(1)).getValue(), ((BigIntPlutusData) f.get(2)).getValue())));
            }
            return out;
        } catch (Exception e) {
            throw new IllegalArgumentException("not an attestation datum", e);
        }
    }

    /**
     * Every entry of every live attestation of {@code vault}'s period: all UTxOs at the vault's
     * address that hold its attestation token. This is the set a customer checks.
     */
    public static List<Entry> liveEntries(BackendService backend, PlutusScript vault) throws Exception {
        String unit = Plutus.policyId(vault) + HexUtil.encodeHexString(ATTEST_TOKEN);
        List<Entry> all = new ArrayList<>();
        for (int page = 1; ; page++) {
            var result = backend.getUtxoService().getUtxos(address(vault), 100, page);
            if (!result.isSuccessful() || result.getValue() == null || result.getValue().isEmpty()) break;
            for (Utxo u : result.getValue()) {
                if (u.getAmount().stream().anyMatch(a -> a.getUnit().equals(unit))) all.addAll(readEntries(u));
            }
            if (result.getValue().size() < 100) break;
        }
        return all;
    }

    /** Locks {@code reservesLovelace} in the vault with the attestation, minting its token. */
    public static Result<String> attest(BackendService backend, PlutusScript vault, Account exchange,
                                        long reservesLovelace, List<Entry> entries,
                                        Groth16ProofBLS381 proof, long validToSlot) {
        String policyId = Plutus.policyId(vault);
        var p = ProverToCardano.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                new BytesPlutusData(p.piA()), new BytesPlutusData(p.piB()), new BytesPlutusData(p.piC()))).build();
        var tx = new ScriptTx()
                .mintAsset(vault, List.of(new Asset("0x" + HexUtil.encodeHexString(ATTEST_TOKEN), BigInteger.ONE)), redeemer)
                .payToContract(address(vault),
                        List.of(new Amount("lovelace", BigInteger.valueOf(reservesLovelace)),
                                new Amount(policyId + HexUtil.encodeHexString(ATTEST_TOKEN), BigInteger.ONE)),
                        attestationDatum(entries));
        return submit(backend, tx, exchange, null, validToSlot);
    }

    /** Releases the reserve once the period has ended, burning the attestation token. */
    public static Result<String> release(BackendService backend, PlutusScript vault, Account exchange,
                                         Utxo vaultUtxo, Long validFromSlot) {
        var burn = ConstrPlutusData.builder().alternative(1).data(ListPlutusData.of(BigIntPlutusData.of(0))).build();
        var tx = new ScriptTx()
                .collectFrom(vaultUtxo, ConstrPlutusData.of(0))
                .mintAsset(vault, List.of(new Asset("0x" + HexUtil.encodeHexString(ATTEST_TOKEN), BigInteger.ONE.negate())), burn)
                .payToAddress(exchange.baseAddress(), Amount.ada(2))
                .attachSpendingValidator(vault);
        return submit(backend, tx, exchange, validFromSlot, null);
    }

    private static Result<String> submit(BackendService backend, ScriptTx tx, Account exchange,
                                         Long validFrom, Long validTo) {
        try {
            var ctx = new QuickTxBuilder(backend).compose(tx)
                    .withTxEvaluator(DevKit.evaluator(backend))
                    .withSigner(SignerProviders.signerFrom(exchange))
                    .withRequiredSigners(exchange.hdKeyPair().getPublicKey().getKeyHash())
                    .feePayer(exchange.baseAddress())
                    .collateralPayer(exchange.baseAddress());
            if (validFrom != null) ctx = ctx.validFrom(validFrom);
            if (validTo != null) ctx = ctx.validTo(validTo);
            return ctx.complete();
        } catch (RuntimeException e) {
            return Result.error(e.getMessage());
        }
    }
}
