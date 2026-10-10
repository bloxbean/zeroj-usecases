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
import org.zeroj.circuit.lib.jubjub.ConfidentialNotes;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteReaderKey;
import org.zeroj.circuit.lib.jubjub.NoteScanner;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Hidden-liability solvency (ADR-0006 demo C, ADR-0007 N6): one Pedersen commitment per customer
 * balance, a proof that the hidden total is at most the reserve locked in the vault, a check each
 * customer runs on their own entry, and an aggregate opening for an auditor.
 *
 * <p>Openings are delivered <b>on-chain</b> ({@code confidential-note-jubjub-v1}): each entry
 * carries its customer's opening encrypted to the customer's viewing key, and the attestation
 * carries the aggregate opening {@code (L, Σ r_i mod l)} encrypted to the auditor's viewing key.
 * Customers and the auditor recover them from the chain, not from the exchange's say-so.
 */
public final class SolvencyAttestation {

    public static final byte[] ATTEST_TOKEN = "ATTEST".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * A customer as the exchange sees them: id, a fresh 32-byte salt for this period, the
     * balance, its blinding, and the customer's reader key (given when the account was opened).
     * The salt still reaches the customer off-chain, with the account statement.
     */
    public record Customer(String id, byte[] salt, long balance, BigInteger blinding, NoteReaderKey readerKey) {
        public static Customer of(String id, long balance, NoteReaderKey readerKey) {
            byte[] salt = new byte[32];
            RANDOM.nextBytes(salt);
            return new Customer(id, salt, balance, PedersenCommitment.randomBlinding(RANDOM), readerKey);
        }

        public NoteOpening opening() {
            return NoteOpening.of(BigInteger.valueOf(balance), blinding);
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

    /** A published entry: the customer's id hash, balance commitment and delivered opening. */
    public record Entry(byte[] idHash, JubjubPoint commitment, byte[] delivery) {}

    /** One attestation as read from the chain: its entries and the auditor's delivery. */
    public record Attestation(List<Entry> entries, byte[] auditorDelivery) {}

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

    /** Each customer's entry, with its opening sealed to the customer's reader key. */
    public static List<Entry> entries(List<Customer> book) {
        return book.stream().map(c -> new Entry(c.idHash(), c.commitment(),
                ConfidentialNotes.seal(c.opening(), List.of(c.readerKey()), RANDOM).getFirst())).toList();
    }

    /** {@code entries} with customer {@code id}'s delivery replaced by random bytes (the cheat). */
    public static List<Entry> withGarbageFor(List<Entry> entries, List<Customer> book, String id) {
        List<Entry> out = new ArrayList<>();
        for (int i = 0; i < entries.size(); i++) {
            Entry e = entries.get(i);
            if (book.get(i).id().equals(id)) {
                byte[] garbage = new byte[ConfidentialNotes.DELIVERY_LENGTH];
                RANDOM.nextBytes(garbage);
                out.add(new Entry(e.idHash(), e.commitment(), garbage));
            } else {
                out.add(e);
            }
        }
        return out;
    }

    /** The aggregate opening {@code (L, Σ r_i mod l)} sealed to the auditor's reader key. Requires {@code L < 2^64}. */
    public static byte[] auditorDelivery(List<Customer> book, NoteReaderKey auditor) {
        AuditOpening a = auditOpening(book);
        return ConfidentialNotes.seal(NoteOpening.of(a.liabilities(), a.blinding()), List.of(auditor), RANDOM).getFirst();
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

    /** The outcome of a customer's check. */
    public enum Check { LISTED_ONCE_CORRECT, MISSING, LISTED_TWICE, UNOPENABLE, WRONG_BALANCE }

    /**
     * The customer's check over every entry of the period ({@link #liveEntries}): their id hash
     * (from their salt) appears exactly once, and that entry's delivery opens, with their own
     * viewing key, to the balance their account shows.
     */
    public static Check customerCheck(List<Entry> entries, Customer me, NoteViewingKey key) {
        byte[] mine = me.idHash();
        List<Entry> matches = entries.stream().filter(e -> Arrays.equals(e.idHash(), mine)).toList();
        if (matches.isEmpty()) return Check.MISSING;
        if (matches.size() > 1) return Check.LISTED_TWICE;
        JubjubPoint c = matches.getFirst().commitment().normalized();
        var opened = NoteScanner.of(key).open(matches.getFirst().delivery(), c.affineU(), c.affineV());
        if (opened.isEmpty()) return Check.UNOPENABLE;
        return opened.get().value().longValueExact() == me.balance() ? Check.LISTED_ONCE_CORRECT : Check.WRONG_BALANCE;
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
     * The auditor's check from the chain alone: it computes {@code Σ C_i} over the attestation's
     * entries and opens its own delivery against it, learning {@code L} and nothing about any
     * single balance. Empty if the delivery does not open (evidence against the exchange).
     */
    public static Optional<BigInteger> auditorCheck(Attestation attestation, NoteViewingKey auditor) {
        JubjubPoint sum = JubjubPoint.IDENTITY;
        for (Entry e : attestation.entries()) sum = sum.add(e.commitment());
        JubjubPoint s = sum.normalized();
        return NoteScanner.of(auditor).open(attestation.auditorDelivery(), s.affineU(), s.affineV()).map(NoteOpening::value);
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

    /** {@code Attestation([Entry(idHash, u, v, delivery)], auditorDelivery)}. */
    public static ConstrPlutusData attestationDatum(List<Entry> entries, byte[] auditorDelivery) {
        List<PlutusData> items = new ArrayList<>();
        for (Entry e : entries) {
            items.add(ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                    new BytesPlutusData(e.idHash()),
                    BigIntPlutusData.of(e.commitment().affineU()),
                    BigIntPlutusData.of(e.commitment().affineV()),
                    new BytesPlutusData(e.delivery()))).build());
        }
        return ConstrPlutusData.builder().alternative(0).data(ListPlutusData.of(
                ListPlutusData.of(items.toArray(new PlutusData[0])), new BytesPlutusData(auditorDelivery))).build();
    }

    /**
     * The entries of a live attestation, read from the vault output's inline datum, as a customer
     * or auditor would read them from the chain.
     */
    public static Attestation readAttestation(Utxo vaultUtxo) {
        try {
            var datum = (ConstrPlutusData) PlutusData.deserialize(HexUtil.decodeHexString(vaultUtxo.getInlineDatum()));
            var fields = datum.getData().getPlutusDataList();
            var entries = (ListPlutusData) fields.get(0);
            List<Entry> out = new ArrayList<>();
            for (PlutusData item : entries.getPlutusDataList()) {
                var f = ((ConstrPlutusData) item).getData().getPlutusDataList();
                out.add(new Entry(((BytesPlutusData) f.get(0)).getValue(), JubjubPoint.fromAffine(
                        ((BigIntPlutusData) f.get(1)).getValue(), ((BigIntPlutusData) f.get(2)).getValue()),
                        ((BytesPlutusData) f.get(3)).getValue()));
            }
            return new Attestation(out, ((BytesPlutusData) fields.get(1)).getValue());
        } catch (Exception e) {
            throw new IllegalArgumentException("not an attestation datum", e);
        }
    }

    public static List<Entry> readEntries(Utxo vaultUtxo) {
        return readAttestation(vaultUtxo).entries();
    }

    /**
     * Every entry of every live attestation of {@code vault}'s period: all UTxOs at the vault's
     * address that hold its attestation token. This is the set a customer checks.
     */
    public static List<Entry> liveEntries(BackendService backend, PlutusScript vault) throws Exception {
        List<Entry> all = new ArrayList<>();
        for (Attestation a : liveAttestations(backend, vault)) all.addAll(a.entries());
        return all;
    }

    /** Every live attestation of {@code vault}'s period. */
    public static List<Attestation> liveAttestations(BackendService backend, PlutusScript vault) throws Exception {
        String unit = Plutus.policyId(vault) + HexUtil.encodeHexString(ATTEST_TOKEN);
        List<Attestation> all = new ArrayList<>();
        for (int page = 1; ; page++) {
            var result = backend.getUtxoService().getUtxos(address(vault), 100, page);
            if (!result.isSuccessful() || result.getValue() == null || result.getValue().isEmpty()) break;
            for (Utxo u : result.getValue()) {
                if (u.getAmount().stream().anyMatch(a -> a.getUnit().equals(unit))) all.add(readAttestation(u));
            }
            if (result.getValue().size() < 100) break;
        }
        return all;
    }

    /** Locks {@code reservesLovelace} in the vault with the attestation, minting its token. */
    public static Result<String> attest(BackendService backend, PlutusScript vault, Account exchange,
                                        long reservesLovelace, List<Entry> entries, byte[] auditorDelivery,
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
                        attestationDatum(entries, auditorDelivery));
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
