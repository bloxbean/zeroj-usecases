package com.bloxbean.cardano.zeroj.usecases.nft.onchain;

import com.bloxbean.cardano.zeroj.usecases.nft.NftFixture;
import com.bloxbean.cardano.zeroj.usecases.nft.service.NftScheme;
import com.bloxbean.cardano.zeroj.usecases.nft.service.ProverService;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
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
import org.zeroj.circuit.FieldConfig;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * The NFT gate's scripts in the Plutus VM (ADR-0009 D2, M5): an honest insert and an honest root
 * are accepted, and every rule the ADR lists is checked by a mutation that must be rejected.
 * <ul>
 *   <li>ZK policy: the event (root, context) is a script parameter; the mint is exactly
 *       {@code {n: 1}} with {@code n} the canonical 32-byte nullifier.</li>
 *   <li>List, InitList: one-shot root (seed), no list input, the root token in its datum output.</li>
 *   <li>List, InsertNode: one list input (the anchor), one list mint, no burns, the key is
 *       {@code slice(1, 31, n)} of the single 32-byte ZK token, both tokens in the new node.</li>
 *   <li>List, spend: only with exactly one list mint (an insert's anchor).</li>
 * </ul>
 */
class NullifierScriptsVmTest extends ContractTest {

    private static final BigInteger R = FieldConfig.BLS12_381.prime();
    private static final byte[] ZK_POLICY = filled(28, (byte) 0x7a);
    private static final byte[] LIST_POLICY = filled(28, (byte) 0x1c);
    private static final Address LIST_ADDRESS = new Address(
            new Credential.ScriptCredential(ScriptHash.of(LIST_POLICY)), Optional.empty());
    private static final Address WALLET = TestDataBuilder.pubKeyAddress(TestDataBuilder.randomPubKeyHash_typed());
    private static final byte[] ROOT_KEY = "NROOT".getBytes();
    private static final byte[] PREFIX = "N".getBytes();
    /** A reference script on a list output (its later spenders would pay the per-byte fee). */
    private static final Optional<ScriptHash> REF_SCRIPT = Optional.of(ScriptHash.of(filled(28, (byte) 0x99)));
    private static final TxOutRef SEED = new TxOutRef(TxId.of(filled(32, (byte) 0x5e)), BigInteger.valueOf(3));

    private static NftFixture fx;
    private static ProverService.ProofResult honest;
    private static SnarkjsToCardano.ProofCompressed honestProof;
    private static Program zkPolicy;
    private static Program listPolicy;

    @BeforeAll
    static void setup() {
        fx = NftFixture.get();
        honest = fx.prove(0);
        honestProof = ProverToCardano.compressProof(honest.proof());
        var t = new NullifierScriptsVmTest();
        zkPolicy = t.zkPolicy(fx.root(), NftFixture.CONTEXT);
        listPolicy = t.compileValidator(NullifierListValidator.class, Path.of("src/main/java")).program().applyParams(
                PlutusData.bytes(ROOT_KEY),
                PlutusData.bytes(PREFIX),
                PlutusData.integer(BigInteger.ONE),
                PlutusData.bytes(ZK_POLICY),
                PlutusData.bytes(seedRef(SEED)));
    }

    private Program zkPolicy(BigInteger root, BigInteger context) {
        var vk = ProverToCardano.compressVk(fx.prover.getSetupResult());
        return compileValidator(ZkProofMintingPolicy.class, Path.of("src/main/java")).program().applyParams(
                PlutusData.integer(root),
                PlutusData.integer(context),
                PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()),
                icData(vk.ic()));
    }

    // ------------------------------------------------------------------
    //  ZK policy
    // ------------------------------------------------------------------

    enum ZkMutation {
        NONE, TAMPERED_PROOF, NAME_NOT_NULLIFIER, REDEEMER_NULLIFIER_CHANGED, SHORT_NAME,
        NON_CANONICAL_NULLIFIER, TWO_UNITS, EXTRA_ENTRY, BURN
    }

    @Test
    @DisplayName("ZK policy: an honest mint is accepted; every binding mutation is rejected")
    void zkPolicyMutations() {
        var ok = evaluate(zkPolicy, zkContext(ZkMutation.NONE));
        assertSuccess(ok);
        System.out.println("[ZkProofMintingPolicy] budget consumed: " + ok.budgetConsumed());
        for (ZkMutation m : ZkMutation.values()) {
            if (m == ZkMutation.NONE) continue;
            if (evaluate(zkPolicy, zkContext(m)) instanceof EvalResult.Success) {
                fail("ZK policy accepted mutation " + m);
            }
        }
    }

    @Test
    @DisplayName("ZK policy: a valid proof is rejected by the policy of another snapshot or another event (I5)")
    void foreignEvent() {
        Program otherRoot = zkPolicy(fx.root().add(BigInteger.ONE), NftFixture.CONTEXT);
        Program otherContext = zkPolicy(fx.root(), NftScheme.contextId("another-event"));
        if (evaluate(otherRoot, zkContext(ZkMutation.NONE)) instanceof EvalResult.Success) {
            fail("ZK policy accepted a proof under another snapshot root");
        }
        if (evaluate(otherContext, zkContext(ZkMutation.NONE)) instanceof EvalResult.Success) {
            fail("ZK policy accepted a proof under another context");
        }
    }

    private PlutusData zkContext(ZkMutation m) {
        BigInteger nullifier = honest.nullifier();
        byte[] name = NftScheme.i2osp32(nullifier);
        BigInteger redeemerNullifier = nullifier;
        switch (m) {
            case NAME_NOT_NULLIFIER -> {
                name = name.clone();
                name[31] ^= 1;
            }
            case REDEEMER_NULLIFIER_CHANGED -> {
                redeemerNullifier = nullifier.add(BigInteger.ONE);
                name = NftScheme.i2osp32(redeemerNullifier);
            }
            case SHORT_NAME -> name = Arrays.copyOfRange(name, 1, 32);
            case NON_CANONICAL_NULLIFIER -> {
                // n + r: the same field element as n, a different 32-byte name and list key.
                redeemerNullifier = nullifier.add(R);
                name = fixed32(redeemerNullifier);
            }
            default -> { }
        }
        byte[] piA = m == ZkMutation.TAMPERED_PROOF ? flipped(honestProof.piA()) : honestProof.piA();

        BigInteger units = switch (m) {
            case TWO_UNITS -> BigInteger.TWO;
            case BURN -> BigInteger.ONE.negate();
            default -> BigInteger.ONE;
        };
        Value mint = Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(name), units);
        if (m == ZkMutation.EXTRA_ENTRY) {
            mint = mint.merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(filled(32, (byte) 1)), BigInteger.ONE));
        }
        return ScriptContextTestBuilder.minting(PolicyId.of(ZK_POLICY))
                .mint(mint)
                .redeemer(PlutusData.constr(0, PlutusData.bytes(piA), PlutusData.bytes(honestProof.piB()),
                        PlutusData.bytes(honestProof.piC()), PlutusData.integer(redeemerNullifier)))
                .output(new TxOut(LIST_ADDRESS, nodeValue(name), inline(listElement(new byte[0])), Optional.empty()))
                .buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  List: InitList
    // ------------------------------------------------------------------

    enum InitMutation {
        NONE, SECOND_ROOT_WITHOUT_SEED, LIST_INPUT_SPENT, EXTRA_TOKEN, TWO_ROOT_UNITS,
        ROOT_TOKEN_OUTSIDE_DATUM_OUTPUT, ROOT_DATUM_EXTRA_FIELD, ROOT_NOT_EMPTY, ROOT_REFERENCE_SCRIPT
    }

    @Test
    @DisplayName("List: the root is created once (seed), with no list input, its token in its datum output")
    void listInit() {
        assertSuccess(evaluate(listPolicy, initContext(InitMutation.NONE)));
        for (InitMutation m : InitMutation.values()) {
            if (m != InitMutation.NONE && evaluate(listPolicy, initContext(m)) instanceof EvalResult.Success) {
                fail("InitList accepted " + m);
            }
        }
    }

    private PlutusData initContext(InitMutation m) {
        BigInteger rootUnits = m == InitMutation.TWO_ROOT_UNITS ? BigInteger.TWO : BigInteger.ONE;
        Value mint = Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(ROOT_KEY), rootUnits);
        if (m == InitMutation.EXTRA_TOKEN) {
            mint = mint.merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(concat(PREFIX, filled(31, (byte) 0))), BigInteger.ONE));
        }
        var builder = ScriptContextTestBuilder.minting(PolicyId.of(LIST_POLICY))
                .mint(mint)
                .redeemer(PlutusData.constr(0, PlutusData.integer(0)));
        // A second root: the seed is gone (spent by the first InitList), so any other wallet input.
        TxOutRef ref = m != InitMutation.SECOND_ROOT_WITHOUT_SEED ? SEED
                : new TxOutRef(TxId.of(filled(32, (byte) 0x5e)), BigInteger.valueOf(4));
        builder.input(new TxInInfo(ref, new TxOut(WALLET, Value.lovelace(BigInteger.valueOf(10_000_000)),
                new OutputDatum.NoOutputDatum(), Optional.empty())));
        if (m == InitMutation.LIST_INPUT_SPENT) {
            // An existing node spent alongside the root's creation (it would be dropped).
            byte[] otherName = filled(32, (byte) 3);
            builder.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LIST_ADDRESS,
                    nodeValue(otherName), inline(listElement(new byte[0])), Optional.empty())));
        }
        PlutusData rootDatum = switch (m) {
            case ROOT_DATUM_EXTRA_FIELD -> PlutusData.constr(0, PlutusData.constr(0), PlutusData.bytes(new byte[0]), PlutusData.integer(0));
            case ROOT_NOT_EMPTY -> listElement(filled(31, (byte) 0x10));
            default -> listElement(new byte[0]);
        };
        Value rootValue = Value.lovelace(BigInteger.valueOf(2_000_000));
        if (m != InitMutation.ROOT_TOKEN_OUTSIDE_DATUM_OUTPUT) {
            rootValue = rootValue.merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(ROOT_KEY), rootUnits));
        }
        builder.output(new TxOut(LIST_ADDRESS, rootValue, inline(rootDatum),
                m == InitMutation.ROOT_REFERENCE_SCRIPT ? REF_SCRIPT : Optional.empty()));
        if (m == InitMutation.ROOT_TOKEN_OUTSIDE_DATUM_OUTPUT) {
            builder.output(new TxOut(WALLET, Value.lovelace(BigInteger.valueOf(2_000_000))
                    .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(ROOT_KEY), BigInteger.ONE)),
                    new OutputDatum.NoOutputDatum(), Optional.empty()));
        }
        return builder.buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  List: InsertNode after the root
    // ------------------------------------------------------------------

    enum InsertMutation {
        NONE, FRESH_KEY_WITHOUT_ZK_MINT, KEY_NOT_NULLIFIER, ZK_NAME_31_BYTES, TWO_ZK_TOKENS, TWO_ZK_UNITS,
        ZK_TOKEN_OUTSIDE_NEW_NODE, LIST_TOKEN_OUTSIDE_NEW_NODE, TWO_LIST_INPUTS, EXTRA_LIST_MINT,
        BURN_WITH_INSERT, ANCHOR_DATUM_CHANGED, NEW_NODE_DATUM_CHANGED, STRAY_TOKEN_IN_NEW_NODE,
        STRAY_TOKEN_IN_ANCHOR, ANCHOR_REFERENCE_SCRIPT, NEW_NODE_REFERENCE_SCRIPT, ANCHOR_LOVELACE_TAKEN
    }

    @Test
    @DisplayName("List: an honest insert is accepted; every binding mutation is rejected")
    void listInsert() {
        var ok = evaluate(listPolicy, insertContext(InsertMutation.NONE));
        assertSuccess(ok);
        System.out.println("[NullifierListValidator insert] budget consumed: " + ok.budgetConsumed());
        for (InsertMutation m : InsertMutation.values()) {
            if (m == InsertMutation.NONE) continue;
            if (evaluate(listPolicy, insertContext(m)) instanceof EvalResult.Success) {
                fail("nullifier list accepted mutation " + m);
            }
        }
    }

    private PlutusData insertContext(InsertMutation m) {
        byte[] name = NftScheme.i2osp32(honest.nullifier());
        byte[] zkName = m == InsertMutation.ZK_NAME_31_BYTES ? Arrays.copyOfRange(name, 1, 32) : name;
        byte[] key = Arrays.copyOfRange(name, 1, 32);
        if (m == InsertMutation.KEY_NOT_NULLIFIER || m == InsertMutation.FRESH_KEY_WITHOUT_ZK_MINT) {
            key = key.clone();
            key[30] ^= 1;
        }
        byte[] nodeToken = concat(PREFIX, key);

        Value mint = Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(nodeToken), BigInteger.ONE);
        if (m == InsertMutation.EXTRA_LIST_MINT) {
            mint = mint.merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(concat(PREFIX, filled(31, (byte) 0))), BigInteger.ONE));
        }
        if (m == InsertMutation.BURN_WITH_INSERT) {
            // Burn another node's token in the same transaction (removing it from the list).
            mint = mint.merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(concat(PREFIX, filled(31, (byte) 0x44))),
                    BigInteger.ONE.negate()));
        }
        BigInteger zkUnits = m == InsertMutation.TWO_ZK_UNITS ? BigInteger.TWO : BigInteger.ONE;
        if (m != InsertMutation.FRESH_KEY_WITHOUT_ZK_MINT) {
            mint = mint.merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(zkName), zkUnits));
        }
        if (m == InsertMutation.TWO_ZK_TOKENS) {
            mint = mint.merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(filled(32, (byte) 2)), BigInteger.ONE));
        }

        Value rootValue = Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(ROOT_KEY), BigInteger.ONE));
        // ANCHOR_LOVELACE_TAKEN: the anchor holds 5 ADA, the continuing anchor only 2 ADA.
        Value anchorValue = m == InsertMutation.ANCHOR_LOVELACE_TAKEN
                ? Value.lovelace(BigInteger.valueOf(5_000_000))
                        .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(ROOT_KEY), BigInteger.ONE))
                : rootValue;
        TxOut anchor = new TxOut(LIST_ADDRESS, anchorValue, inline(listElement(new byte[0])), Optional.empty());

        var builder = ScriptContextTestBuilder.minting(PolicyId.of(LIST_POLICY))
                .mint(mint)
                .input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), anchor))
                .redeemer(PlutusData.constr(1, PlutusData.bytes(ROOT_KEY), PlutusData.integer(0), PlutusData.integer(1)));
        if (m == InsertMutation.TWO_LIST_INPUTS) {
            // Another holder's node, spent alongside the anchor (its nullifier would be dropped).
            byte[] otherName = filled(32, (byte) 3);
            builder.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LIST_ADDRESS,
                    nodeValue(otherName), inline(listElement(new byte[0])), Optional.empty())));
        }

        Value contValue = rootValue;
        if (m == InsertMutation.STRAY_TOKEN_IN_ANCHOR) {
            contValue = contValue.merge(Value.singleton(PolicyId.of(filled(28, (byte) 0x33)), TokenName.of(new byte[] {1}), BigInteger.ONE));
        }
        PlutusData contDatum = m == InsertMutation.ANCHOR_DATUM_CHANGED
                ? PlutusData.constr(0, PlutusData.integer(7), PlutusData.bytes(key))
                : listElement(key);
        builder.output(new TxOut(LIST_ADDRESS, contValue, inline(contDatum),
                m == InsertMutation.ANCHOR_REFERENCE_SCRIPT ? REF_SCRIPT : Optional.empty()));

        Value newValue = Value.lovelace(BigInteger.valueOf(2_000_000));
        if (m != InsertMutation.LIST_TOKEN_OUTSIDE_NEW_NODE) {
            newValue = newValue.merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(nodeToken), BigInteger.ONE));
        }
        if (m != InsertMutation.ZK_TOKEN_OUTSIDE_NEW_NODE && m != InsertMutation.FRESH_KEY_WITHOUT_ZK_MINT) {
            newValue = newValue.merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(zkName), zkUnits));
        }
        if (m == InsertMutation.STRAY_TOKEN_IN_NEW_NODE) {
            newValue = newValue.merge(Value.singleton(PolicyId.of(filled(28, (byte) 0x33)), TokenName.of(new byte[] {1}), BigInteger.ONE));
        }
        PlutusData newDatum = m == InsertMutation.NEW_NODE_DATUM_CHANGED
                ? PlutusData.constr(0, PlutusData.integer(7), PlutusData.bytes(new byte[0]))
                : listElement(new byte[0]);
        builder.output(new TxOut(LIST_ADDRESS, newValue, inline(newDatum),
                m == InsertMutation.NEW_NODE_REFERENCE_SCRIPT ? REF_SCRIPT : Optional.empty()));
        if (m == InsertMutation.ZK_TOKEN_OUTSIDE_NEW_NODE) {
            builder.output(new TxOut(WALLET, Value.lovelace(BigInteger.valueOf(2_000_000))
                    .merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(zkName), BigInteger.ONE)),
                    new OutputDatum.NoOutputDatum(), Optional.empty()));
        }
        if (m == InsertMutation.LIST_TOKEN_OUTSIDE_NEW_NODE) {
            builder.output(new TxOut(WALLET, Value.lovelace(BigInteger.valueOf(2_000_000))
                    .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(nodeToken), BigInteger.ONE)),
                    new OutputDatum.NoOutputDatum(), Optional.empty()));
        }
        return builder.buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  List: InsertNode after a node
    // ------------------------------------------------------------------

    enum NodeMutation { NONE, ORDER_VIOLATION, DUPLICATE_KEY, ANCHOR_DROPS_ZK_TOKEN }

    @Test
    @DisplayName("List: inserts after a node keep order, refuse a re-inserted key and keep the anchor's ZK token")
    void listInsertAfterNode() {
        assertSuccess(evaluate(listPolicy, afterNodeContext(NodeMutation.NONE)));
        for (NodeMutation m : NodeMutation.values()) {
            if (m != NodeMutation.NONE && evaluate(listPolicy, afterNodeContext(m)) instanceof EvalResult.Success) {
                fail("nullifier list accepted " + m);
            }
        }
    }

    /**
     * Inserts the honest nullifier's key after a node. {@code ORDER_VIOLATION} uses an anchor whose
     * key is above the new key; {@code DUPLICATE_KEY} an anchor that already points at the new key
     * (the nullifier's earlier node); {@code ANCHOR_DROPS_ZK_TOKEN} moves the anchor's ZK token out.
     */
    private PlutusData afterNodeContext(NodeMutation m) {
        byte[] name = NftScheme.i2osp32(honest.nullifier());
        byte[] key = Arrays.copyOfRange(name, 1, 32);
        byte[] anchorKey = filled(31, m == NodeMutation.ORDER_VIOLATION ? (byte) 0xff : (byte) 0x00);
        byte[] anchorName = concat(new byte[] {0}, anchorKey);
        byte[] anchorToken = concat(PREFIX, anchorKey);
        byte[] anchorNext = m == NodeMutation.DUPLICATE_KEY ? key : new byte[0];
        byte[] nodeToken = concat(PREFIX, key);

        Value anchorValue = nodeValueFor(anchorToken, anchorName);
        var builder = ScriptContextTestBuilder.minting(PolicyId.of(LIST_POLICY))
                .mint(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(nodeToken), BigInteger.ONE)
                        .merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(name), BigInteger.ONE)))
                .input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(LIST_ADDRESS, anchorValue,
                        inline(listElement(anchorNext)), Optional.empty())))
                .redeemer(PlutusData.constr(1, PlutusData.bytes(anchorToken), PlutusData.integer(0), PlutusData.integer(1)));
        Value contValue = m == NodeMutation.ANCHOR_DROPS_ZK_TOKEN
                ? Value.lovelace(BigInteger.valueOf(2_000_000))
                        .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(anchorToken), BigInteger.ONE))
                : anchorValue;
        builder.output(new TxOut(LIST_ADDRESS, contValue, inline(listElement(key)), Optional.empty()));
        builder.output(new TxOut(LIST_ADDRESS, nodeValueFor(nodeToken, name), inline(listElement(anchorNext)),
                Optional.empty()));
        if (m == NodeMutation.ANCHOR_DROPS_ZK_TOKEN) {
            builder.output(new TxOut(WALLET, Value.lovelace(BigInteger.valueOf(2_000_000))
                    .merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(anchorName), BigInteger.ONE)),
                    new OutputDatum.NoOutputDatum(), Optional.empty()));
        }
        return builder.buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  List: spend
    // ------------------------------------------------------------------

    enum SpendMutation { NONE, NO_LIST_MINT, BURN_ONLY, TWO_LIST_MINTS, ONLY_ZK_MINT }

    @Test
    @DisplayName("List: a node is spent only alongside exactly one list mint (as an insert's anchor)")
    void listSpend() {
        assertSuccess(evaluate(listPolicy, spendContext(SpendMutation.NONE)));
        for (SpendMutation m : SpendMutation.values()) {
            if (m != SpendMutation.NONE && evaluate(listPolicy, spendContext(m)) instanceof EvalResult.Success) {
                fail("list spend accepted " + m);
            }
        }
    }

    /**
     * Spends a node. With exactly one list mint the spend defers to the minting purpose, which
     * then admits only the insert whose single list input is this anchor ({@link #listInsert}).
     */
    private PlutusData spendContext(SpendMutation m) {
        byte[] nodeName = filled(32, (byte) 0x44);
        byte[] nodeToken = concat(PREFIX, Arrays.copyOfRange(nodeName, 1, 32));
        PlutusData datum = listElement(new byte[0]);
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x61)), BigInteger.ZERO);
        Value newToken = Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(concat(PREFIX, filled(31, (byte) 0x55))), BigInteger.ONE);
        Value mint = switch (m) {
            case NONE -> newToken;
            case NO_LIST_MINT -> Value.zero();
            case BURN_ONLY -> Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(nodeToken), BigInteger.ONE.negate());
            case TWO_LIST_MINTS -> newToken.merge(Value.singleton(PolicyId.of(LIST_POLICY),
                    TokenName.of(concat(PREFIX, filled(31, (byte) 0x66))), BigInteger.ONE));
            case ONLY_ZK_MINT -> Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(filled(32, (byte) 0x55)), BigInteger.ONE);
        };
        var b = ScriptContextTestBuilder.spending(ownRef, datum)
                .redeemer(PlutusData.constr(0))
                .mint(mint);
        b.input(new TxInInfo(ownRef, new TxOut(LIST_ADDRESS, nodeValue(nodeName), inline(datum), Optional.empty())));
        b.output(new TxOut(WALLET, nodeValue(nodeName), new OutputDatum.NoOutputDatum(), Optional.empty()));
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------
    //  Encodings
    // ------------------------------------------------------------------

    private static Value nodeValue(byte[] nullifierName) {
        byte[] token = concat(PREFIX, Arrays.copyOfRange(nullifierName, Math.max(0, nullifierName.length - 31), nullifierName.length));
        return nodeValueFor(token, nullifierName);
    }

    private static Value nodeValueFor(byte[] listToken, byte[] nullifierName) {
        return Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(LIST_POLICY), TokenName.of(listToken), BigInteger.ONE))
                .merge(Value.singleton(PolicyId.of(ZK_POLICY), TokenName.of(nullifierName), BigInteger.ONE));
    }

    /** {@code ListElement((), nextKey)} = {@code Constr 0 [Constr 0 [], B nextKey]}. */
    private static PlutusData listElement(byte[] nextKey) {
        return PlutusData.constr(0, PlutusData.constr(0), PlutusData.bytes(nextKey));
    }

    private static OutputDatum inline(PlutusData d) {
        return new OutputDatum.OutputDatumInline(d);
    }

    private static byte[] fixed32(BigInteger n) {
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
