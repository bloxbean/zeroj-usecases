package com.bloxbean.cardano.zeroj.usecases.voting.onchain;

import com.bloxbean.cardano.zeroj.usecases.voting.VotingFixture;
import com.bloxbean.cardano.zeroj.usecases.voting.crypto.JubjubElGamal;
import com.bloxbean.cardano.zeroj.usecases.voting.service.VoteCircuitService;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.DatumHash;
import org.julclang.ledger.Interval;
import org.julclang.ledger.IntervalBound;
import org.julclang.ledger.IntervalBoundType;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PolicyId;
import org.julclang.ledger.ScriptHash;
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
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * The vote scripts in the Plutus VM (ADR-0005 B2): an honest ballot transaction is accepted, and
 * every binding mutation the ADR lists is rejected — by the ballot policy (V1, V3, V6, V10, the
 * pre-minted copy) or by the vote list (G2, G3, G5, exact values).
 */
class VoteScriptsVmTest extends ContractTest {

    private static final byte[] ZK_POLICY = filled(28, (byte) 0x7a);
    private static final byte[] LIST_POLICY = filled(28, (byte) 0x1c);
    private static final Address LIST_ADDRESS = new Address(
            new Credential.ScriptCredential(ScriptHash.of(LIST_POLICY)), Optional.empty());
    private static final Address WALLET = TestDataBuilder.pubKeyAddress(TestDataBuilder.randomPubKeyHash_typed());
    private static final byte[] ROOT_KEY = "VROOT".getBytes();
    private static final byte[] PREFIX = "V".getBytes();
    private static final long DEADLINE = 1_800_000_000_000L;
    private static final TxOutRef SEED = new TxOutRef(TxId.of(filled(32, (byte) 0x5e)), BigInteger.valueOf(3));

    private static VotingFixture fx;
    private static VoteCircuitService.BallotProof honest;
    private static VoteCircuitService.BallotProof foreignRoot;
    private static SnarkjsToCardano.ProofCompressed honestProof;
    private static Program zkPolicy;
    private static Program listPolicy;

    @BeforeAll
    static void setup() {
        fx = VotingFixture.get();
        honest = fx.prove(0, 1);
        honestProof = ProverToCardano.compressProof(honest.proof());

        // G1: an attacker's own voter tree containing a fresh key, proved honestly against it.
        BigInteger attacker = BigInteger.valueOf(424242);
        BigInteger[][] attackerTree = VotingFixture.buildTree(fx.circuits,
                List.of(fx.circuits.computePublicKey(attacker)));
        BigInteger[][] p = VotingFixture.path(attackerTree, 0);
        foreignRoot = fx.circuits.proveBallot(new VoteCircuitService.BallotWitness(
                VotingFixture.ELECTION_ID, attackerTree[VotingFixture.DEPTH][0], fx.electionKey, attacker,
                1, JubjubElGamal.randomScalar(VotingFixture.RANDOM), p[0], p[1]));

        var t = new VoteScriptsVmTest();
        var vk = ProverToCardano.compressVk(fx.circuits.ballotSetup());
        JubjubPoint key = fx.electionKey.normalized();
        zkPolicy = t.compileValidator(VoteZkMintingPolicy.class, Path.of("src/main/java")).program().applyParams(
                PlutusData.integer(VotingFixture.ELECTION_ID),
                PlutusData.integer(fx.root()),
                PlutusData.integer(key.affineU()),
                PlutusData.integer(key.affineV()),
                PlutusData.integer(BigInteger.valueOf(DEADLINE)),
                PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()),
                icData(vk.ic()));
        listPolicy = t.compileValidator(VoteListValidator.class, Path.of("src/main/java")).program().applyParams(
                PlutusData.bytes(ROOT_KEY),
                PlutusData.bytes(PREFIX),
                PlutusData.integer(BigInteger.ONE),
                PlutusData.bytes(ZK_POLICY),
                PlutusData.bytes(seedRef(SEED)));
    }

    // ------------------------------------------------------------------
    //  Ballot policy
    // ------------------------------------------------------------------

    enum ZkMutation {
        NONE, FOREIGN_ROOT, TAMPERED_PROOF, DATUM_BALLOT_CHANGED, PRE_MINTED_COPY, TWO_UNITS,
        EXTRA_ENTRY, AFTER_DEADLINE, NO_UPPER_BOUND, NON_CANONICAL_COORDINATE, SHORT_NAME, HASHED_DATUM
    }

    @Test
    @DisplayName("Ballot policy: an honest ballot is accepted; every binding mutation is rejected")
    void ballotPolicy() {
        var ok = evaluate(zkPolicy, zkContext(ZkMutation.NONE));
        assertSuccess(ok);
        System.out.println("[VoteZkMintingPolicy] budget consumed: " + ok.budgetConsumed());
        for (ZkMutation m : ZkMutation.values()) {
            if (m == ZkMutation.NONE) continue;
            if (evaluate(zkPolicy, zkContext(m)) instanceof EvalResult.Success) {
                fail("ballot policy accepted mutation " + m);
            }
        }
    }

    private PlutusData zkContext(ZkMutation m) {
        var ballot = m == ZkMutation.FOREIGN_ROOT ? foreignRoot : honest;
        byte[] name = nullifierName(ballot.nullifier());
        if (m == ZkMutation.SHORT_NAME) name = Arrays.copyOfRange(name, 1, 32);
        var proof = m == ZkMutation.FOREIGN_ROOT ? ProverToCardano.compressProof(foreignRoot.proof()) : honestProof;
        byte[] piA = m == ZkMutation.TAMPERED_PROOF ? flipped(proof.piA()) : proof.piA();

        JubjubElGamal.Ciphertext stored = ballot.ciphertext();
        if (m == ZkMutation.DATUM_BALLOT_CHANGED || m == ZkMutation.PRE_MINTED_COPY) {
            // An unproved ballot: here, the honest ballot plus an encryption of 1 (a double vote).
            stored = stored.add(JubjubElGamal.encrypt(1, BigInteger.TWO, fx.electionKey));
        }
        PlutusData nodeDatum = m == ZkMutation.NON_CANONICAL_COORDINATE
                ? listElement(ballotData(stored, true), new byte[0])
                : listElement(ballotData(stored, false), new byte[0]);

        BigInteger units = m == ZkMutation.TWO_UNITS ? BigInteger.TWO : BigInteger.ONE;
        Value mint = Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(name), units);
        if (m == ZkMutation.EXTRA_ENTRY) {
            mint = mint.merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(filled(32, (byte) 1)), BigInteger.ONE));
        }
        var builder = ScriptContextTestBuilder.minting(PolicyId.of(ZK_POLICY))
                .mint(mint)
                .redeemer(PlutusData.constr(0, PlutusData.bytes(piA), PlutusData.bytes(proof.piB()),
                        PlutusData.bytes(proof.piC())))
                .validRange(range(m));
        if (m == ZkMutation.PRE_MINTED_COPY) {
            // An earlier copy of N, minted outside the list, placed first with the proved datum.
            builder.output(new TxOut(WALLET,
                    Value.lovelace(BigInteger.valueOf(2_000_000)).merge(
                            Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(name), BigInteger.ONE)),
                    new OutputDatum.OutputDatumInline(listElement(ballotData(ballot.ciphertext(), false), new byte[0])),
                    Optional.empty()));
        }
        OutputDatum datum = m == ZkMutation.HASHED_DATUM
                ? new OutputDatum.OutputDatumHash(DatumHash.of(filled(32, (byte) 9)))
                : new OutputDatum.OutputDatumInline(nodeDatum);
        builder.output(new TxOut(LIST_ADDRESS, nodeValue(name, units), datum, Optional.empty()));
        return builder.buildPlutusData();
    }

    private static Interval range(ZkMutation m) {
        IntervalBound from = new IntervalBound(new IntervalBoundType.NegInf(), true);
        return switch (m) {
            case AFTER_DEADLINE -> new Interval(from,
                    new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(DEADLINE + 1000)), false));
            case NO_UPPER_BOUND -> new Interval(from, new IntervalBound(new IntervalBoundType.PosInf(), true));
            default -> new Interval(from,
                    new IntervalBound(new IntervalBoundType.Finite(BigInteger.valueOf(DEADLINE)), false));
        };
    }

    // ------------------------------------------------------------------
    //  Vote list
    // ------------------------------------------------------------------

    enum ListMutation {
        NONE, KEY_NOT_NULLIFIER, SECOND_LIST_INPUT, STRAY_TOKEN_IN_NODE, STRAY_TOKEN_IN_ANCHOR,
        EXTRA_LIST_MINT, NODE_WITHOUT_NULLIFIER, NO_NULLIFIER_MINTED, TWO_NULLIFIERS_MINTED, ANCHOR_DATA_CHANGED
    }

    @Test
    @DisplayName("Vote list: an honest insert is accepted; every binding mutation is rejected")
    void listInsert() {
        assertSuccess(evaluate(listPolicy, insertContext(ListMutation.NONE)));
        for (ListMutation m : ListMutation.values()) {
            if (m == ListMutation.NONE) continue;
            if (evaluate(listPolicy, insertContext(m)) instanceof EvalResult.Success) {
                fail("vote list accepted mutation " + m);
            }
        }
    }

    @Test
    @DisplayName("Vote list: the root is created only by consuming the seed, and alone")
    void listInit() {
        assertSuccess(evaluate(listPolicy, initContext(true, false)));
        if (evaluate(listPolicy, initContext(false, false)) instanceof EvalResult.Success) {
            fail("InitList accepted without consuming the seed (a second root)");
        }
        if (evaluate(listPolicy, initContext(true, true)) instanceof EvalResult.Success) {
            fail("InitList accepted an extra list token");
        }
    }

    private PlutusData insertContext(ListMutation m) {
        byte[] name = nullifierName(honest.nullifier());
        byte[] key = Arrays.copyOfRange(name, 1, 32);
        if (m == ListMutation.KEY_NOT_NULLIFIER) {
            key = key.clone();
            key[30] ^= 1;
        }
        byte[] nodeToken = concat(PREFIX, key);

        Value mint = Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(nodeToken), BigInteger.ONE);
        if (m == ListMutation.EXTRA_LIST_MINT) {
            mint = mint.merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(concat(PREFIX, filled(31, (byte) 0))), BigInteger.ONE));
        }
        if (m != ListMutation.NO_NULLIFIER_MINTED) {
            mint = mint.merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(name), BigInteger.ONE));
        }
        if (m == ListMutation.TWO_NULLIFIERS_MINTED) {
            mint = mint.merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(filled(32, (byte) 2)), BigInteger.ONE));
        }

        TxOutRef anchorRef = TestDataBuilder.randomTxOutRef_typed();
        Value rootValue = Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(ROOT_KEY), BigInteger.ONE));
        PlutusData rootData = PlutusData.constr(0);
        TxOut anchor = new TxOut(LIST_ADDRESS, rootValue,
                new OutputDatum.OutputDatumInline(listElement(rootData, new byte[0])), Optional.empty());

        var builder = ScriptContextTestBuilder.minting(PolicyId.of(LIST_POLICY))
                .mint(mint)
                .input(new TxInInfo(anchorRef, anchor))
                .redeemer(PlutusData.constr(1, PlutusData.bytes(ROOT_KEY), PlutusData.integer(0), PlutusData.integer(1)));
        if (m == ListMutation.SECOND_LIST_INPUT) {
            // Another voter's node, spent alongside the anchor (its ballot would be dropped).
            byte[] otherName = filled(32, (byte) 3);
            Value otherValue = nodeValueFor(concat(PREFIX, Arrays.copyOfRange(otherName, 1, 32)), otherName);
            builder.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LIST_ADDRESS, otherValue,
                    new OutputDatum.OutputDatumInline(listElement(ballotData(honest.ciphertext(), false), new byte[0])),
                    Optional.empty())));
        }

        Value contValue = rootValue;
        if (m == ListMutation.STRAY_TOKEN_IN_ANCHOR) {
            contValue = contValue.merge(Value.singleton(PolicyId.of(filled(28, (byte) 0x33)), TokenName.of(new byte[] {1}), BigInteger.ONE));
        }
        PlutusData contData = m == ListMutation.ANCHOR_DATA_CHANGED
                ? ballotData(honest.ciphertext(), false) : rootData;
        builder.output(new TxOut(LIST_ADDRESS, contValue,
                new OutputDatum.OutputDatumInline(listElement(contData, key)), Optional.empty()));

        Value newValue = m == ListMutation.NODE_WITHOUT_NULLIFIER
                ? Value.lovelace(BigInteger.valueOf(2_000_000))
                        .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(nodeToken), BigInteger.ONE))
                : nodeValueFor(nodeToken, name);
        if (m == ListMutation.STRAY_TOKEN_IN_NODE) {
            newValue = newValue.merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(filled(32, (byte) 4)), BigInteger.ONE));
        }
        builder.output(new TxOut(LIST_ADDRESS, newValue,
                new OutputDatum.OutputDatumInline(listElement(ballotData(honest.ciphertext(), false), new byte[0])),
                Optional.empty()));
        if (m == ListMutation.NODE_WITHOUT_NULLIFIER) {
            builder.output(new TxOut(WALLET, Value.lovelace(BigInteger.valueOf(2_000_000))
                    .merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(name), BigInteger.ONE)),
                    new OutputDatum.NoOutputDatum(), Optional.empty()));
        }
        return builder.buildPlutusData();
    }

    private PlutusData initContext(boolean withSeed, boolean extraToken) {
        Value mint = Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(ROOT_KEY), BigInteger.ONE);
        if (extraToken) {
            mint = mint.merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(concat(PREFIX, filled(31, (byte) 0))), BigInteger.ONE));
        }
        var builder = ScriptContextTestBuilder.minting(PolicyId.of(LIST_POLICY))
                .mint(mint)
                .redeemer(PlutusData.constr(0, PlutusData.integer(0)));
        TxOutRef ref = withSeed ? SEED : new TxOutRef(TxId.of(filled(32, (byte) 0x5e)), BigInteger.valueOf(4));
        builder.input(new TxInInfo(ref, new TxOut(WALLET, Value.lovelace(BigInteger.valueOf(10_000_000)),
                new OutputDatum.NoOutputDatum(), Optional.empty())));
        builder.output(new TxOut(LIST_ADDRESS, Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(ROOT_KEY), BigInteger.ONE)),
                new OutputDatum.OutputDatumInline(listElement(PlutusData.constr(0), new byte[0])), Optional.empty()));
        return builder.buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  Encodings
    // ------------------------------------------------------------------

    private static Value nodeValue(byte[] nullifierName, BigInteger units) {
        byte[] token = concat(PREFIX, Arrays.copyOfRange(nullifierName, Math.max(0, nullifierName.length - 31), nullifierName.length));
        return Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(token), BigInteger.ONE))
                .merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(nullifierName), units));
    }

    private static Value nodeValueFor(byte[] listToken, byte[] nullifierName) {
        return Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(listToken), BigInteger.ONE))
                .merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(nullifierName), BigInteger.ONE));
    }

    private static PlutusData ballotData(JubjubElGamal.Ciphertext c, boolean nonCanonical) {
        BigInteger au = c.handle().affineU();
        if (nonCanonical) au = au.add(JubjubCurve.BASE_FIELD_PRIME);
        return PlutusData.constr(0,
                PlutusData.integer(au), PlutusData.integer(c.handle().affineV()),
                PlutusData.integer(c.ballot().affineU()), PlutusData.integer(c.ballot().affineV()));
    }

    private static PlutusData listElement(PlutusData userData, byte[] nextKey) {
        return PlutusData.constr(0, userData, PlutusData.bytes(nextKey));
    }

    private static byte[] nullifierName(BigInteger n) {
        byte[] raw = n.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }

    private static byte[] seedRef(TxOutRef ref) {
        int index = ref.index().intValueExact();
        return concat(ref.txId().hash(), new byte[] {(byte) (index >>> 8), (byte) index});
    }

    private static PlutusData icData(List<byte[]> ic) {
        PlutusData[] points = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) points[i] = PlutusData.bytes(ic.get(i));
        return PlutusData.list(points);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] flipped(byte[] bytes) {
        byte[] copy = bytes.clone();
        copy[copy.length - 1] ^= 1;
        return copy;
    }

    private static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
