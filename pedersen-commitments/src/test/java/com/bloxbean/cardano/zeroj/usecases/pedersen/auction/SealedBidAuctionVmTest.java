package com.bloxbean.cardano.zeroj.usecases.pedersen.auction;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.circuit.BidProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.onchain.SealedBidAuction;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AdmittedAuditor;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.AuditorKeys;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.KeyPossession;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.RegistryEntry;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.RegistryTestData;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.VerificationKeys;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.Interval;
import org.julclang.ledger.IntervalBound;
import org.julclang.ledger.IntervalBoundType;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PolicyId;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.StakingCredential;
import org.julclang.ledger.TokenName;
import org.julclang.ledger.TxId;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.TxOutRef;
import org.julclang.ledger.Value;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.ScriptContextTestBuilder;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code SealedBidAuction} in the Plutus VM (ADR-0008): Open, Bid, Settle (n = 1, 2, 3), NoBids and
 * Refund are accepted, with their complete-transaction cost checked against the 80% gate, and every
 * mutation of ADR-0008's verification list is rejected.
 */
class SealedBidAuctionVmTest extends ContractTest {

    static final long STEP_LIMIT = 10_000_000_000L;
    static final long MEMORY_LIMIT = 16_500_000L;
    static final SecureRandom RANDOM = new SecureRandom();
    static final byte[] POLICY = filled(28, (byte) 0xac);
    static final byte[] REGISTRY_POLICY = filled(28, (byte) 0x3e);
    static final byte[] ITEM_POLICY = filled(28, (byte) 0x17);
    static final byte[] ITEM_NAME = "Painting#1".getBytes();
    static final byte[] SELLER = filled(28, (byte) 0x5e);
    static final byte[] AUCTIONEER = filled(28, (byte) 0xa1);
    static final byte[] ALICE = filled(28, (byte) 0x0a);
    static final byte[] BOB = filled(28, (byte) 0x0b);
    static final byte[] CAROL = filled(28, (byte) 0x0c);
    static final byte[] DAVE = filled(28, (byte) 0x0d);
    static final TxOutRef SEED = new TxOutRef(TxId.of(filled(32, (byte) 0x51)), BigInteger.TWO);
    static final byte[] T = tokenOf(SEED);
    static final long LOT_ADA = 3_000_000;
    static final long DEPOSIT = 100;
    static final long RESERVE = 10;
    static final long BIDDING_ENDS = 1_000_000;
    static final long SETTLE_BY = 1_200_000;
    static final long MIN_WINDOW = 60_000;
    static final BigInteger ADA = BigInteger.valueOf(1_000_000);
    static final Address LOT_ADDRESS = new Address(new Credential.ScriptCredential(ScriptHash.of(POLICY)), Optional.empty());
    static final Address STAKED_LOT = new Address(LOT_ADDRESS.credential(), Optional.of(new StakingCredential.StakingHash(
            new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x5a))))));

    static AuctionProofs proofs;
    static Program program;
    static AuditorKeys auctioneerKeys;
    static RegistryEntry entry;
    static AdmittedAuditor auctioneer;
    static List<ElGamalEncryption> encs = new ArrayList<>();
    static List<SnarkjsToCardano.ProofCompressed> bidProofs = new ArrayList<>();
    static final List<Long> AMOUNTS = List.of(40L, 70L, 70L);
    static final List<byte[]> BIDDERS = List.of(ALICE, BOB, CAROL);

    @BeforeAll
    static void setup() {
        proofs = new AuctionProofs();
        KeyPossession possession = new KeyPossession();
        auctioneerKeys = AuditorKeys.generate(RANDOM);
        entry = auctioneerKeys.entry(REGISTRY_POLICY, AUCTIONEER, 0, possession);
        auctioneer = AdmittedAuditor.admit(REGISTRY_POLICY, entry, possession);
        program = new SealedBidAuctionVmTest().compileValidator(SealedBidAuction.class, Path.of("src/main/java")).program()
                .applyParams(PlutusData.bytes(REGISTRY_POLICY), PlutusData.bytes("REG".getBytes()),
                        PlutusData.integer(BigInteger.valueOf(MIN_WINDOW)), PlutusData.integer(BigInteger.valueOf(2_000_000)),
                        PlutusData.bytes(VerificationKeys.hash(proofs.bid().compressedVk())),
                        PlutusData.bytes(VerificationKeys.hash(proofs.settle(1).compressedVk())),
                        PlutusData.bytes(VerificationKeys.hash(proofs.settle(2).compressedVk())),
                        PlutusData.bytes(VerificationKeys.hash(proofs.settle(3).compressedVk())));
        for (int i = 0; i < 3; i++) {
            ElGamalEncryption e = ElGamal.encryptWithOpening(auctioneer.context(), BigInteger.valueOf(AMOUNTS.get(i)), 32, RANDOM);
            encs.add(e);
            bidProofs.add(ProverToCardano.compressProof(proofs.proveBid(BIDDERS.get(i), DEPOSIT, RESERVE,
                    auctioneer.pkU(), auctioneer.pkV(), e)));
        }
        specials();
    }

    /** A bid with a valid proof for exactly its bidder and ciphertext. */
    record Special(byte[] bidder, List<BigInteger> ct, SnarkjsToCardano.ProofCompressed proof) {}

    static final Map<BidMutation, Special> SPECIAL = new EnumMap<>(BidMutation.class);

    /** Proves {@code inputs} and checks the proof off-chain (the positive control), then compresses it. */
    static Special special(byte[] bidder, BidProofCircuit.Inputs inputs) {
        var proof = proofs.bid().prove(inputs.toWitnessMap());
        var pub = BidProofCircuit.publicInputs(inputs);
        assertTrue(proofs.bid().verify(proof, pub), "positive control: the mutation's own proof is valid");
        return new Special(bidder, pub.subList(5, 9), ProverToCardano.compressProof(proof));
    }

    static Special fresh(byte[] bidder, long amount) {
        ElGamalEncryption e = ElGamal.encryptWithOpening(auctioneer.context(), BigInteger.valueOf(amount), 32, RANDOM);
        return special(bidder, AuctionProofs.bidInputs(bidder, DEPOSIT, RESERVE, auctioneer.pkU(), auctioneer.pkV(), e));
    }

    static void specials() {
        SPECIAL.put(BidMutation.NONE, new Special(CAROL, List.of(encs.get(2).ciphertext().handle().affineU(),
                encs.get(2).ciphertext().handle().affineV(), encs.get(2).ciphertext().blinded().affineU(),
                encs.get(2).ciphertext().blinded().affineV()), bidProofs.get(2)));
        SPECIAL.put(BidMutation.BY_SELLER, fresh(SELLER, 50));
        SPECIAL.put(BidMutation.BY_AUCTIONEER, fresh(AUCTIONEER, 50));
        SPECIAL.put(BidMutation.REPEATED_BIDDER, fresh(ALICE, 50));
        SPECIAL.put(BidMutation.FOURTH_BID, fresh(DAVE, 50));
        // Carol re-uses Alice's ciphertext (same handle A), proving its opening under her own key hash.
        SPECIAL.put(BidMutation.COPIED_HANDLE, special(CAROL,
                AuctionProofs.bidInputs(CAROL, DEPOSIT, RESERVE, auctioneer.pkU(), auctioneer.pkV(), encs.get(0))));
        // k = l: A = [l]·G is the identity, B = [m]·G. A valid R_enc proof, but a lot that could never settle.
        BigInteger l = JubjubCurve.SUBGROUP_ORDER;
        var b = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(50)).normalized();
        BigInteger carol = AuctionProofs.bidderInt(CAROL);
        var identity = BidProofCircuit.inputs()
                .bidderInt(carol).deposit(DEPOSIT).reserve(RESERVE).pkU(auctioneer.pkU()).pkV(auctioneer.pkV())
                .aU(BigInteger.ZERO).aV(BigInteger.ONE).bU(b.affineU()).bV(b.affineV())
                .bid(50).k(l).bidderSquared(carol.multiply(carol).mod(Fields.FR));
        SPECIAL.put(BidMutation.IDENTITY_HANDLE, special(CAROL, identity));
    }

    // ------------------------------------------------------------------ data

    static PlutusData bid(int i) {
        var ct = encs.get(i).ciphertext();
        return PlutusData.constr(0, PlutusData.bytes(BIDDERS.get(i)), PlutusData.integer(ct.handle().affineU()),
                PlutusData.integer(ct.handle().affineV()), PlutusData.integer(ct.blinded().affineU()),
                PlutusData.integer(ct.blinded().affineV()));
    }

    static List<PlutusData> lotFields(List<PlutusData> bids) {
        return new ArrayList<>(List.of(PlutusData.bytes(SELLER), PlutusData.bytes(AUCTIONEER), PlutusData.bytes(ITEM_POLICY),
                PlutusData.bytes(ITEM_NAME), PlutusData.integer(BigInteger.valueOf(LOT_ADA)),
                PlutusData.integer(BigInteger.valueOf(DEPOSIT)), PlutusData.integer(BigInteger.valueOf(RESERVE)),
                PlutusData.integer(BigInteger.valueOf(BIDDING_ENDS)), PlutusData.integer(BigInteger.valueOf(SETTLE_BY)),
                PlutusData.integer(auctioneer.pkU()), PlutusData.integer(auctioneer.pkV()), PlutusData.integer(BigInteger.ZERO),
                PlutusData.list(bids.toArray(new PlutusData[0]))));
    }

    static PlutusData lot(List<PlutusData> bids) {
        return PlutusData.constr(0, lotFields(bids).toArray(new PlutusData[0]));
    }

    static List<PlutusData> bids(int n) {
        List<PlutusData> out = new ArrayList<>();
        for (int i = 0; i < n; i++) out.add(bid(i));
        return out;
    }

    static Value lotValue(int bids) {
        return Value.lovelace(BigInteger.valueOf(LOT_ADA).add(BigInteger.valueOf(DEPOSIT * bids).multiply(ADA)))
                .merge(Value.singleton(PolicyId.of(ITEM_POLICY), TokenName.of(ITEM_NAME), BigInteger.ONE))
                .merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.ONE));
    }

    static TxInInfo registryInput(PlutusData entryDatum) {
        Value v = Value.lovelace(BigInteger.valueOf(8_000_000))
                .merge(Value.singleton(PolicyId.of(REGISTRY_POLICY), TokenName.of("REG".getBytes()), BigInteger.ONE));
        return new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(
                new Address(new Credential.ScriptCredential(ScriptHash.of(REGISTRY_POLICY)), Optional.empty()), v,
                new OutputDatum.OutputDatumInline(entryDatum), Optional.empty()));
    }

    static Interval upTo(long t) {
        return new Interval(new IntervalBound(new IntervalBoundType.NegInf(), true),
                new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(t)), false));
    }

    static Interval between(long from, long to) {
        return new Interval(new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(from)), true),
                new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(to)), false));
    }

    static Interval from(long t) {
        return new Interval(new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(t)), true),
                new IntervalBound(new IntervalBoundType.PosInf(), true));
    }

    static Interval always() {
        return new Interval(new IntervalBound(new IntervalBoundType.NegInf(), true), new IntervalBound(new IntervalBoundType.PosInf(), true));
    }

    static TxOut payout(byte[] pkh, long lovelace, boolean withItem, boolean tagged, boolean staked) {
        return payout(pkh, lovelace, withItem, tagged ? POLICY : filled(28, (byte) 0x99), tagged, staked);
    }

    /** A payout tagged {@code Payout(policy, T)} (or with another token name when not {@code tagged}). */
    static TxOut payout(byte[] pkh, long lovelace, boolean withItem, byte[] policy, boolean tagged, boolean staked) {
        Address to = new Address(new Credential.PubKeyCredential(PubKeyHash.of(pkh)), staked
                ? Optional.of(new StakingCredential.StakingHash(new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x66)))))
                : Optional.empty());
        Value v = Value.lovelace(BigInteger.valueOf(lovelace));
        if (withItem) v = v.merge(Value.singleton(PolicyId.of(ITEM_POLICY), TokenName.of(ITEM_NAME), BigInteger.ONE));
        PlutusData tag = PlutusData.constr(0, PlutusData.bytes(policy), PlutusData.bytes(tagged ? T : filled(32, (byte) 1)));
        return new TxOut(to, v, new OutputDatum.OutputDatumInline(tag), Optional.empty());
    }

    // ------------------------------------------------------------------ Open

    enum OpenMutation {
        NONE, TOKEN_NOT_DERIVED, SCRIPT_INPUT_SPENT, TWO_TOKENS, ITEM_MISSING, LOT_ADA_MISMATCH, LOT_ADA_BELOW_MIN,
        KEY_NOT_REGISTRY, GENERATION_WRONG, AUCTIONEER_NOT_ENTRY, WINDOW_TOO_SHORT, AFTER_BIDDING_ENDS, NO_UPPER_BOUND,
        RESERVE_ABOVE_DEPOSIT, RESERVE_ONE, NOT_SIGNED, BIDS_NOT_EMPTY, STAKED_OUTPUT, EXTRA_ASSET, REGISTRY_MISSING,
        TWO_TOKEN_NAMES, DEPOSIT_2_POW_32, ITEM_NAME_33_BYTES, ITEM_UNDER_OWN_POLICY
    }

    @Test
    @DisplayName("Open: a seller mints a one-shot lot token and locks the item; every mutation is rejected")
    void open() {
        var honest = evaluate(program, openContext(OpenMutation.NONE));
        assertInstanceOf(EvalResult.Success.class, honest);
        report("open (mint)", honest, null);
        for (OpenMutation m : OpenMutation.values()) {
            if (m != OpenMutation.NONE && evaluate(program, openContext(m)) instanceof EvalResult.Success) fail("Open accepted " + m);
        }
    }

    private PlutusData openContext(OpenMutation m) {
        Value mint = Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.valueOf(m == OpenMutation.TWO_TOKENS ? 2 : 1));
        if (m == OpenMutation.TWO_TOKEN_NAMES) mint = mint.merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(filled(32, (byte) 3)), BigInteger.ONE));
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).mint(mint).redeemer(PlutusData.constr(0, PlutusData.integer(0)));
        b.validRange(switch (m) {
            case AFTER_BIDDING_ENDS -> upTo(BIDDING_ENDS + 1000);
            case NO_UPPER_BOUND -> always();
            default -> upTo(BIDDING_ENDS - 10_000);
        });
        if (m != OpenMutation.NOT_SIGNED) b.signer(SELLER);
        TxOutRef seed = m == OpenMutation.TOKEN_NOT_DERIVED ? TestDataBuilder.randomTxOutRef_typed() : SEED;
        b.input(new TxInInfo(seed, new TxOut(new Address(new Credential.PubKeyCredential(PubKeyHash.of(SELLER)), Optional.empty()),
                Value.lovelace(BigInteger.valueOf(50_000_000)), new OutputDatum.NoOutputDatum(), Optional.empty())));
        if (m == OpenMutation.SCRIPT_INPUT_SPENT) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LOT_ADDRESS, Value.lovelace(BigInteger.valueOf(5_000_000)),
                    new OutputDatum.OutputDatumInline(PlutusData.integer(0)), Optional.empty())));
        }
        List<PlutusData> f = lotFields(List.of());
        switch (m) {
            case LOT_ADA_BELOW_MIN -> f.set(4, PlutusData.integer(BigInteger.valueOf(1_000_000)));
            case KEY_NOT_REGISTRY -> f.set(9, PlutusData.integer(auctioneer.pkU().add(BigInteger.ONE)));
            case GENERATION_WRONG -> f.set(11, PlutusData.integer(BigInteger.ONE));
            case AUCTIONEER_NOT_ENTRY -> f.set(1, PlutusData.bytes(DAVE));
            case WINDOW_TOO_SHORT -> f.set(8, PlutusData.integer(BigInteger.valueOf(BIDDING_ENDS + MIN_WINDOW - 1)));
            case RESERVE_ABOVE_DEPOSIT -> f.set(6, PlutusData.integer(BigInteger.valueOf(DEPOSIT + 1)));
            case RESERVE_ONE -> f.set(6, PlutusData.integer(BigInteger.ONE));
            case BIDS_NOT_EMPTY -> f.set(12, PlutusData.list(bid(0)));
            case DEPOSIT_2_POW_32 -> f.set(5, PlutusData.integer(BigInteger.ONE.shiftLeft(32)));
            case ITEM_NAME_33_BYTES -> f.set(3, PlutusData.bytes(filled(33, (byte) 'x')));
            case ITEM_UNDER_OWN_POLICY -> f.set(2, PlutusData.bytes(POLICY));
            default -> { }
        }
        Value v = Value.lovelace(BigInteger.valueOf(m == OpenMutation.LOT_ADA_BELOW_MIN ? 1_000_000
                        : m == OpenMutation.LOT_ADA_MISMATCH ? LOT_ADA + 1 : LOT_ADA))
                .merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.valueOf(m == OpenMutation.TWO_TOKENS ? 2 : 1)));
        if (m != OpenMutation.ITEM_MISSING) v = v.merge(Value.singleton(PolicyId.of(ITEM_POLICY), TokenName.of(ITEM_NAME), BigInteger.ONE));
        if (m == OpenMutation.EXTRA_ASSET) v = v.merge(Value.singleton(PolicyId.of(filled(28, (byte) 0x77)), TokenName.of("Z".getBytes()), BigInteger.ONE));
        b.output(new TxOut(m == OpenMutation.STAKED_OUTPUT ? STAKED_LOT : LOT_ADDRESS, v,
                new OutputDatum.OutputDatumInline(PlutusData.constr(0, f.toArray(new PlutusData[0]))), Optional.empty()));
        if (m != OpenMutation.REGISTRY_MISSING) b.referenceInput(registryInput(RegistryTestData.datum(entry)));
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------ Bid

    enum BidMutation {
        NONE, LATE, NO_UPPER_BOUND, UNSIGNED, BY_SELLER, BY_AUCTIONEER, REPEATED_BIDDER, FOURTH_BID, DEPOSIT_OFF_BY_ONE,
        EARLIER_BID_CHANGED, COPIED_HANDLE, IDENTITY_HANDLE, STAKED_OUTPUT, TOKENLESS_INPUT, EXTRA_ASSET, MINT_DURING_BID,
        PROOF_FOR_OTHER_BIDDER, WRONG_VK, TWO_LOTS, DEPOSIT_TOO_MUCH, REFERENCE_SCRIPT_ON_LOT,
        // boundary cases, checked separately (AT_DEADLINE is accepted)
        AT_DEADLINE, JUST_LATE
    }

    @Test
    @DisplayName("Bid: the third bid is appended with its deposit and proof; every mutation is rejected")
    void placeBid() {
        var honest = evaluate(program, bidContext(BidMutation.NONE));
        assertInstanceOf(EvalResult.Success.class, honest);
        report("bid (spend, third bid)", honest, null);
        for (BidMutation m : BidMutation.values()) {
            if (m != BidMutation.NONE && m != BidMutation.AT_DEADLINE
                    && evaluate(program, bidContext(m)) instanceof EvalResult.Success) fail("Bid accepted " + m);
        }
        // Boundaries: an (exclusive) upper bound at exactly biddingEnds is in time; one millisecond later is not.
        assertInstanceOf(EvalResult.Success.class, evaluate(program, bidContext(BidMutation.AT_DEADLINE)));
        assertTrue(evaluate(program, bidContext(BidMutation.JUST_LATE)) instanceof EvalResult.Failure);
    }

    /** Bid #3 (Carol) onto a lot holding Alice's and Bob's bids. */
    private PlutusData bidContext(BidMutation m) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x61)), BigInteger.ZERO);
        int already = m == BidMutation.FOURTH_BID ? 3 : 2;
        PlutusData before = lot(bids(already));
        // Each guarded mutation carries its own valid proof (checked off-chain in setup), so only the
        // targeted rule can refuse it; PROOF_FOR_OTHER_BIDDER alone reuses Carol's proof on purpose.
        Special sp = SPECIAL.getOrDefault(m, SPECIAL.get(BidMutation.NONE));
        byte[] bidder = m == BidMutation.PROOF_FOR_OTHER_BIDDER ? DAVE : sp.bidder();
        BigInteger aU = sp.ct().get(0);
        BigInteger aV = sp.ct().get(1);
        BigInteger bU = sp.ct().get(2);
        BigInteger bV = sp.ct().get(3);
        SnarkjsToCardano.ProofCompressed p = sp.proof();
        PlutusData newBid = PlutusData.constr(0, PlutusData.bytes(bidder), PlutusData.integer(aU), PlutusData.integer(aV),
                PlutusData.integer(bU), PlutusData.integer(bV));
        PlutusData vk = m == BidMutation.WRONG_VK ? VerificationKeys.julcData(proofs.settle(1).compressedVk())
                : VerificationKeys.julcData(proofs.bid().compressedVk());
        PlutusData redeemer = PlutusData.constr(0, PlutusData.bytes(bidder), PlutusData.integer(aU), PlutusData.integer(aV),
                PlutusData.integer(bU), PlutusData.integer(bV),
                PlutusData.bytes(p.piA()), PlutusData.bytes(p.piB()), PlutusData.bytes(p.piC()), vk);
        var b = ScriptContextTestBuilder.spending(ownRef, before).redeemer(redeemer);
        b.validRange(switch (m) {
            case LATE -> upTo(BIDDING_ENDS + 1000);
            case NO_UPPER_BOUND -> always();
            case AT_DEADLINE -> upTo(BIDDING_ENDS);
            case JUST_LATE -> upTo(BIDDING_ENDS + 1);
            default -> upTo(BIDDING_ENDS - 1000);
        });
        if (m != BidMutation.UNSIGNED) b.signer(bidder);
        Value in = lotValue(already);
        if (m == BidMutation.TOKENLESS_INPUT) {
            in = Value.lovelace(BigInteger.valueOf(LOT_ADA).add(BigInteger.valueOf(DEPOSIT * already).multiply(ADA)))
                    .merge(Value.singleton(PolicyId.of(ITEM_POLICY), TokenName.of(ITEM_NAME), BigInteger.ONE));
        }
        b.input(new TxInInfo(ownRef, new TxOut(LOT_ADDRESS, in, new OutputDatum.OutputDatumInline(before), Optional.empty())));
        if (m == BidMutation.TWO_LOTS) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LOT_ADDRESS, lotValue(0),
                    new OutputDatum.OutputDatumInline(lot(List.of())), Optional.empty())));
        }
        if (m == BidMutation.MINT_DURING_BID) b.mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(filled(32, (byte) 9)), BigInteger.ONE));
        List<PlutusData> after = bids(already);
        if (m == BidMutation.EARLIER_BID_CHANGED) after.set(0, bid(1));
        after.add(newBid);
        BigInteger lovelace = BigInteger.valueOf(LOT_ADA).add(BigInteger.valueOf(DEPOSIT * (already + 1)).multiply(ADA));
        if (m == BidMutation.DEPOSIT_OFF_BY_ONE) lovelace = lovelace.subtract(BigInteger.ONE);
        if (m == BidMutation.DEPOSIT_TOO_MUCH) lovelace = lovelace.add(BigInteger.ONE);
        Value out = Value.lovelace(lovelace)
                .merge(Value.singleton(PolicyId.of(ITEM_POLICY), TokenName.of(ITEM_NAME), BigInteger.ONE))
                .merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.ONE));
        if (m == BidMutation.EXTRA_ASSET) out = out.merge(Value.singleton(PolicyId.of(filled(28, (byte) 0x77)), TokenName.of("Z".getBytes()), BigInteger.ONE));
        b.output(new TxOut(m == BidMutation.STAKED_OUTPUT ? STAKED_LOT : LOT_ADDRESS, out,
                new OutputDatum.OutputDatumInline(lot(after)),
                m == BidMutation.REFERENCE_SCRIPT_ON_LOT ? Optional.of(ScriptHash.of(filled(28, (byte) 0x42))) : Optional.empty()));
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------ Settle

    enum SettleMutation {
        NONE, EARLY, LATE, NO_UPPER_BOUND, UNDERPAID_SELLER, UNDERPAID_WINNER, UNDERPAID_LOSER, UNTAGGED_PAYOUT, STAKED_PAYOUT,
        NOT_BURNED, W_OUT_OF_RANGE, P_BELOW_RESERVE, PROOF_OVER_SUBSET, SCRIPT_OUTPUT_REMAINS, ITEM_TO_ANOTHER, WRONG_VK,
        OTHER_POLICY_TAG, TWO_LOTS
    }

    @Test
    @DisplayName("Settle: n = 1, 2, 3 accepted with cost measured; every mutation is rejected")
    void settle() {
        for (int n = 1; n <= 3; n++) {
            var spend = evaluate(program, settleContext(SettleMutation.NONE, n, true));
            assertInstanceOf(EvalResult.Success.class, spend);
            var burn = evaluate(program, settleContext(SettleMutation.NONE, n, false));
            assertInstanceOf(EvalResult.Success.class, burn);
            report("settle n=" + n + " (spend + burn)", spend, burn);
        }
        for (SettleMutation m : SettleMutation.values()) {
            if (m != SettleMutation.NONE && evaluate(program, settleContext(m, 3, true)) instanceof EvalResult.Success) {
                fail("Settle accepted " + m);
            }
        }
    }

    /** Settles a lot of {@code n} bids (40, 70, 70): the winner is bid #min(n, 2) at its amount. */
    private PlutusData settleContext(SettleMutation m, int n, boolean spending) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x62)), BigInteger.ZERO);
        PlutusData datum = lot(bids(n));
        int w = Math.min(n, 2);
        long p = AMOUNTS.get(w - 1);
        List<Lot.Bid> lotBids = new ArrayList<>();
        int proofBids = m == SettleMutation.PROOF_OVER_SUBSET ? n - 1 : n;
        for (int i = 0; i < proofBids; i++) {
            var ct = encs.get(i).ciphertext();
            lotBids.add(new Lot.Bid(BIDDERS.get(i), ct.handle().affineU(), ct.handle().affineV(), ct.blinded().affineU(), ct.blinded().affineV()));
        }
        Lot hostLot = new Lot(null, "", SELLER, AUCTIONEER, ITEM_POLICY, ITEM_NAME, LOT_ADA, DEPOSIT, RESERVE, BIDDING_ENDS,
                SETTLE_BY, auctioneer.pkU(), auctioneer.pkV(), 0, lotBids);
        var proof = ProverToCardano.compressProof(proofs.proveSettle(hostLot, w, p,
                auctioneerKeys.elgamal().secretScalar(), AMOUNTS.subList(0, proofBids)));
        long claimedW = m == SettleMutation.W_OUT_OF_RANGE ? n + 1 : w;
        long claimedP = m == SettleMutation.P_BELOW_RESERVE ? RESERVE - 1 : p;
        PlutusData vk = VerificationKeys.julcData(proofs.settle(m == SettleMutation.WRONG_VK ? (n == 1 ? 2 : 1) : proofBids).compressedVk());
        PlutusData redeemer = PlutusData.constr(1, PlutusData.integer(BigInteger.valueOf(claimedW)),
                PlutusData.integer(BigInteger.valueOf(claimedP)), PlutusData.bytes(proof.piA()), PlutusData.bytes(proof.piB()),
                PlutusData.bytes(proof.piC()), vk);
        var b = spending
                ? ScriptContextTestBuilder.spending(ownRef, datum).redeemer(redeemer)
                : ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).redeemer(PlutusData.constr(1, PlutusData.integer(0)));
        b.validRange(switch (m) {
            case EARLY -> between(BIDDING_ENDS - 1000, SETTLE_BY - 1000);
            case LATE -> between(BIDDING_ENDS + 1000, SETTLE_BY + 1000);
            case NO_UPPER_BOUND -> from(BIDDING_ENDS + 1000);
            default -> between(BIDDING_ENDS + 1000, SETTLE_BY - 1000);
        });
        b.input(new TxInInfo(ownRef, new TxOut(LOT_ADDRESS, lotValue(n), new OutputDatum.OutputDatumInline(datum), Optional.empty())));
        if (m == SettleMutation.TWO_LOTS) {
            // A second authentic lot of the same policy in the same transaction (one burn shown).
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LOT_ADDRESS, lotValue(n),
                    new OutputDatum.OutputDatumInline(datum), Optional.empty())));
        }
        if (m != SettleMutation.NOT_BURNED) b.mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.valueOf(-1)));
        long deposit = DEPOSIT * 1_000_000;
        b.output(payout(SELLER, p * 1_000_000 - (m == SettleMutation.UNDERPAID_SELLER ? 1 : 0), false, true, false));
        for (int i = 0; i < n; i++) {
            if (i + 1 == w) {
                long amount = LOT_ADA + deposit - p * 1_000_000 - (m == SettleMutation.UNDERPAID_WINNER ? 1 : 0);
                byte[] to = m == SettleMutation.ITEM_TO_ANOTHER ? DAVE : BIDDERS.get(i);
                b.output(payout(to, amount, true, m != SettleMutation.UNTAGGED_PAYOUT, m == SettleMutation.STAKED_PAYOUT));
            } else {
                // OTHER_POLICY_TAG: a loser's refund tagged with the same T under another auction's policy.
                byte[] tagPolicy = m == SettleMutation.OTHER_POLICY_TAG ? filled(28, (byte) 0xad) : POLICY;
                b.output(payout(BIDDERS.get(i), deposit - (m == SettleMutation.UNDERPAID_LOSER ? 1 : 0), false, tagPolicy, true, false));
            }
        }
        if (m == SettleMutation.SCRIPT_OUTPUT_REMAINS) {
            b.output(new TxOut(LOT_ADDRESS, Value.lovelace(BigInteger.valueOf(2_000_000)), new OutputDatum.OutputDatumInline(datum), Optional.empty()));
        }
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------ Burn

    @Test
    @DisplayName("Burn: refused with no lot spent, with a positive mint, or with two token names")
    void burnNegatives() {
        var noLot = ScriptContextTestBuilder.minting(PolicyId.of(POLICY))
                .mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.valueOf(-1)))
                .redeemer(PlutusData.constr(1, PlutusData.integer(0)));
        assertTrue(evaluate(program, noLot.buildPlutusData()) instanceof EvalResult.Failure, "no lot spent");
        var positive = ScriptContextTestBuilder.minting(PolicyId.of(POLICY))
                .mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.ONE))
                .redeemer(PlutusData.constr(1, PlutusData.integer(0)));
        positive.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LOT_ADDRESS, lotValue(0),
                new OutputDatum.OutputDatumInline(lot(List.of())), Optional.empty())));
        assertTrue(evaluate(program, positive.buildPlutusData()) instanceof EvalResult.Failure, "a positive mint under Burn");
        var two = ScriptContextTestBuilder.minting(PolicyId.of(POLICY))
                .mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.valueOf(-1))
                        .merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(filled(32, (byte) 4)), BigInteger.valueOf(-1))))
                .redeemer(PlutusData.constr(1, PlutusData.integer(0)));
        two.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LOT_ADDRESS, lotValue(0),
                new OutputDatum.OutputDatumInline(lot(List.of())), Optional.empty())));
        assertTrue(evaluate(program, two.buildPlutusData()) instanceof EvalResult.Failure, "two token names burned");
    }

    // ------------------------------------------------------------------ Refund and NoBids

    enum CloseMutation { NONE, EARLY, UNDERPAID_BIDDER, ITEM_NOT_RETURNED, UNTAGGED, OTHER_POLICY_TAG }

    @Test
    @DisplayName("Refund after settleBy and NoBids after the window are accepted; their mutations are rejected")
    void refundAndNoBids() {
        var refund = evaluate(program, refundContext(CloseMutation.NONE));
        assertInstanceOf(EvalResult.Success.class, refund);
        report("refund (spend, 3 bids)", refund, null);
        for (CloseMutation m : CloseMutation.values()) {
            if (m != CloseMutation.NONE && evaluate(program, refundContext(m)) instanceof EvalResult.Success) fail("Refund accepted " + m);
        }
        assertInstanceOf(EvalResult.Success.class, evaluate(program, noBidsContext(0, true, BIDDING_ENDS + 1000)));
        assertTrue(evaluate(program, noBidsContext(1, true, BIDDING_ENDS + 1000)) instanceof EvalResult.Failure, "NoBids with a bid");
        assertTrue(evaluate(program, noBidsContext(0, false, BIDDING_ENDS + 1000)) instanceof EvalResult.Failure, "NoBids unsigned");
        assertTrue(evaluate(program, noBidsContext(0, true, BIDDING_ENDS - 1000)) instanceof EvalResult.Failure, "NoBids early");
    }

    private PlutusData refundContext(CloseMutation m) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x63)), BigInteger.ZERO);
        PlutusData datum = lot(bids(3));
        var b = ScriptContextTestBuilder.spending(ownRef, datum).redeemer(PlutusData.constr(3, PlutusData.integer(0)));
        b.validRange(from(m == CloseMutation.EARLY ? SETTLE_BY - 1000 : SETTLE_BY + 1000));
        b.input(new TxInInfo(ownRef, new TxOut(LOT_ADDRESS, lotValue(3), new OutputDatum.OutputDatumInline(datum), Optional.empty())));
        b.mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.valueOf(-1)));
        b.output(payout(SELLER, LOT_ADA, m != CloseMutation.ITEM_NOT_RETURNED, m != CloseMutation.UNTAGGED, false));
        for (int i = 0; i < 3; i++) {
            byte[] tagPolicy = m == CloseMutation.OTHER_POLICY_TAG && i == 0 ? filled(28, (byte) 0xad) : POLICY;
            b.output(payout(BIDDERS.get(i), DEPOSIT * 1_000_000 - (m == CloseMutation.UNDERPAID_BIDDER && i == 1 ? 1 : 0), false,
                    tagPolicy, true, false));
        }
        return b.buildPlutusData();
    }

    private PlutusData noBidsContext(int bids, boolean signed, long from) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x64)), BigInteger.ZERO);
        PlutusData datum = lot(bids(bids));
        var b = ScriptContextTestBuilder.spending(ownRef, datum).redeemer(PlutusData.constr(2, PlutusData.integer(0)));
        b.validRange(from(from));
        if (signed) b.signer(SELLER);
        b.input(new TxInInfo(ownRef, new TxOut(LOT_ADDRESS, lotValue(bids), new OutputDatum.OutputDatumInline(datum), Optional.empty())));
        b.mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(T), BigInteger.valueOf(-1)));
        b.output(payout(SELLER, LOT_ADA, true, true, false));
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------

    /** Prints the complete transaction's cost and asserts ADR-0055's 80% gate on both limits. */
    private void report(String what, EvalResult a, EvalResult b) {
        long cpu = a.budgetConsumed().cpuSteps() + (b == null ? 0 : b.budgetConsumed().cpuSteps());
        long mem = a.budgetConsumed().memoryUnits() + (b == null ? 0 : b.budgetConsumed().memoryUnits());
        System.out.printf("[SealedBidAuction %s] cpu=%d (%.1f%% of steps) mem=%d (%.1f%% of memory)%n",
                what, cpu, 100.0 * cpu / STEP_LIMIT, mem, 100.0 * mem / MEMORY_LIMIT);
        assertTrue(cpu <= STEP_LIMIT * 8 / 10 && mem <= MEMORY_LIMIT * 8 / 10, what + " exceeds the 80% gate");
    }

    static byte[] tokenOf(TxOutRef ref) {
        byte[] bytes = Arrays.copyOf(ref.txId().hash(), 34);
        int index = ref.index().intValueExact();
        bytes[32] = (byte) (index >>> 8);
        bytes[33] = (byte) index;
        return Blake2bUtil.blake2bHash256(bytes);
    }

    static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
