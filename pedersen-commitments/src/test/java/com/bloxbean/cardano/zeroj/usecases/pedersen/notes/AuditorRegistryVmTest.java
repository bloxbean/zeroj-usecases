package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import com.bloxbean.cardano.zeroj.usecases.pedersen.common.CostProfiler;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.ProofBytes;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.circuit.KeyPossessionProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain.AuditorRegistry;
import org.julclang.compiler.CompileResult;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.DatumHash;
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
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code AuditorRegistry} in the Plutus VM (ADR-0007 N1): the one-shot Init and the rotation are
 * accepted; every mutation that would duplicate the token, let it leave the exact address, skip a
 * signature, break the generation count, change the entry's shape, register an encoding other than
 * its coordinates' or register a key without a possession proof bound to this registry, this
 * registrant and its key type is rejected. That includes the identity key, for which a possession
 * proof with secret 0 does verify.
 */
class AuditorRegistryVmTest extends ContractTest {

    static final byte[] POLICY = filled(28, (byte) 0x3e);
    static final byte[] OTHER_REGISTRY = filled(28, (byte) 0x3f);
    static final byte[] TOKEN = "REG".getBytes(StandardCharsets.UTF_8);
    static final byte[] AUDITOR = filled(28, (byte) 0xa1);
    static final byte[] NEW_AUDITOR = filled(28, (byte) 0xa2);
    static final TxOutRef SEED = new TxOutRef(TxId.of(filled(32, (byte) 0x5e)), BigInteger.valueOf(3));
    static final Address REGISTRY = new Address(new Credential.ScriptCredential(ScriptHash.of(POLICY)), Optional.empty());
    static final Address WALLET = new Address(new Credential.PubKeyCredential(PubKeyHash.of(AUDITOR)), Optional.empty());
    static final SecureRandom RANDOM = new SecureRandom();

    private static Program program;
    private static CompileResult compiled;
    private static KeyPossession possession;
    private static AuditorKeys keys0;
    private static RegistryEntry gen0;
    private static RegistryEntry gen5;
    private static RegistryEntry otherRegistrant;
    private static RegistryEntry otherRegistry;
    private static RegistryEntry otherKey;

    @BeforeAll
    static void setup() {
        possession = new KeyPossession();
        byte[] seedRef = Arrays.copyOf(SEED.txId().hash(), 34);
        seedRef[33] = 3;
        var vk = possession.circuit().compressedVk();
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR.normalized();
        PlutusData[] ic = vk.ic().stream().map(PlutusData::bytes).toArray(PlutusData[]::new);
        compiled = new AuditorRegistryVmTest().compileValidatorWithSourceMap(AuditorRegistry.class, Path.of("src/main/java"));
        program = compiled.program().applyParams(PlutusData.bytes(seedRef), PlutusData.bytes(TOKEN),
                        PlutusData.bytes(KeyPossession.ctxPrefix(KeyPossession.KeyType.ELGAMAL)),
                        PlutusData.bytes(KeyPossession.ctxPrefix(KeyPossession.KeyType.VIEWING)),
                        PlutusData.integer(g.affineU()), PlutusData.integer(g.affineV()),
                        PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()), PlutusData.bytes(vk.gamma()),
                        PlutusData.bytes(vk.delta()), PlutusData.list(ic));
        keys0 = AuditorKeys.generate(RANDOM);
        gen0 = keys0.entry(POLICY, AUDITOR, 0, possession);
        gen5 = AuditorKeys.generate(RANDOM).entry(POLICY, NEW_AUDITOR, 5, possession);
        otherRegistrant = AuditorKeys.generate(RANDOM).entry(POLICY, NEW_AUDITOR, 0, possession);
        otherRegistry = AuditorKeys.generate(RANDOM).entry(OTHER_REGISTRY, AUDITOR, 0, possession);
        otherKey = AuditorKeys.generate(RANDOM).entry(POLICY, AUDITOR, 0, possession);
    }

    // ------------------------------------------------------------------ entries

    /** The 10 fields of an entry, to mutate one at a time. */
    static List<PlutusData> fields(RegistryEntry e) {
        return new ArrayList<>(List.of(PlutusData.bytes(e.auditor()), PlutusData.integer(BigInteger.valueOf(e.generation())),
                PlutusData.integer(e.pkU()), PlutusData.integer(e.pkV()), PlutusData.bytes(e.pkEnc()),
                PlutusData.integer(e.viewU()), PlutusData.integer(e.viewV()), PlutusData.bytes(e.viewKey()),
                PlutusData.bytes(e.pkProof()), PlutusData.bytes(e.viewProof())));
    }

    static PlutusData constr(List<PlutusData> fields) {
        return PlutusData.constr(0, fields.toArray(new PlutusData[0]));
    }

    static PlutusData datum(RegistryEntry e) {
        return constr(fields(e));
    }

    static RegistryEntry atGeneration(RegistryEntry e, long generation) {
        return new RegistryEntry(e.auditor(), generation, e.pkU(), e.pkV(), e.pkEnc(), e.viewU(), e.viewV(),
                e.viewKey(), e.pkProof(), e.viewProof());
    }

    /** A valid possession proof for the identity key bound to {@code auditor}: secret 0, P = D = O = (0, 1). */
    static byte[] identityProof(byte[] auditor) {
        BigInteger ctx = KeyPossession.ctx(KeyPossession.KeyType.ELGAMAL, POLICY, auditor);
        JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR.normalized();
        var identity = KeyPossessionProofCircuit.inputs().ctx(ctx).ctxSquared(ctx.multiply(ctx).mod(Fields.FR))
                .baseU(g.affineU()).baseV(g.affineV()).keyU(BigInteger.ZERO).keyV(BigInteger.ONE)
                .shareU(BigInteger.ZERO).shareV(BigInteger.ONE).secret(BigInteger.ZERO);
        byte[] proof = ProofBytes.encode(possession.circuit().prove(identity.toWitnessMap()));
        // Positive control: the proof really verifies, so only the u ≠ 0 rule can refuse the entry.
        assertTrue(possession.circuit().verify(ProofBytes.decode(proof), List.of(ctx, g.affineU(), g.affineV(),
                BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO, BigInteger.ONE)), "the identity's possession proof verifies");
        return proof;
    }

    enum EntryMutation {
        NONE,
        // shape
        WRONG_TAG, NINE_FIELDS, ELEVEN_FIELDS, AUDITOR_27, AUDITOR_29, NEGATIVE_GENERATION,
        NON_CANONICAL_PK_U, NON_CANONICAL_PK_V, NON_CANONICAL_VIEW_V, SHORT_PROOF, SAME_KEYS,
        // encodings
        PK_ENC_OF_OTHER_KEY, VIEW_KEY_OF_OTHER_KEY,
        // possession
        PROOF_OF_OTHER_REGISTRANT, PROOF_FROM_OTHER_REGISTRY, PK_PROOF_OF_OTHER_KEY, GARBAGE_VIEW_PROOF,
        PK_PROOF_UNDER_VIEW_TYPE, VIEW_PROOF_UNDER_ELGAMAL_TYPE, IDENTITY_KEY_WITH_VALID_PROOF
    }

    /** Entry {@code e} with mutation {@code m}. Type-swap mutations need the secrets, so they apply to gen0 only. */
    static PlutusData entry(RegistryEntry e, EntryMutation m) {
        List<PlutusData> f = fields(e);
        switch (m) {
            case WRONG_TAG -> { return PlutusData.constr(1, f.toArray(new PlutusData[0])); }
            case NINE_FIELDS -> f.remove(9);
            case ELEVEN_FIELDS -> f.add(PlutusData.integer(BigInteger.ONE));
            case AUDITOR_27 -> f.set(0, PlutusData.bytes(Arrays.copyOf(e.auditor(), 27)));
            case AUDITOR_29 -> f.set(0, PlutusData.bytes(Arrays.copyOf(e.auditor(), 29)));
            case NEGATIVE_GENERATION -> f.set(1, PlutusData.integer(BigInteger.valueOf(-1)));
            case NON_CANONICAL_PK_U -> f.set(2, PlutusData.integer(e.pkU().add(JubjubCurve.BASE_FIELD_PRIME)));
            case NON_CANONICAL_PK_V -> f.set(3, PlutusData.integer(e.pkV().add(JubjubCurve.BASE_FIELD_PRIME)));
            case NON_CANONICAL_VIEW_V -> f.set(6, PlutusData.integer(e.viewV().add(JubjubCurve.BASE_FIELD_PRIME)));
            case SHORT_PROOF -> f.set(8, PlutusData.bytes(Arrays.copyOf(e.pkProof(), 191)));
            case SAME_KEYS -> {
                f.set(5, PlutusData.integer(e.pkU()));
                f.set(6, PlutusData.integer(e.pkV()));
                f.set(7, PlutusData.bytes(e.pkEnc()));
                f.set(9, PlutusData.bytes(e.pkProof()));
            }
            case PK_ENC_OF_OTHER_KEY -> f.set(4, PlutusData.bytes(otherKey.pkEnc()));
            case VIEW_KEY_OF_OTHER_KEY -> f.set(7, PlutusData.bytes(otherKey.viewKey()));
            // Another registrant's keys and proofs (bound to NEW_AUDITOR), claimed by e's auditor.
            case PROOF_OF_OTHER_REGISTRANT -> {
                List<PlutusData> o = fields(otherRegistrant);
                o.set(0, PlutusData.bytes(e.auditor()));
                o.set(1, PlutusData.integer(BigInteger.valueOf(e.generation())));
                return constr(o);
            }
            // Keys and proofs copied from another registry's entry by the same auditor key hash.
            case PROOF_FROM_OTHER_REGISTRY -> {
                List<PlutusData> o = fields(otherRegistry);
                o.set(1, PlutusData.integer(BigInteger.valueOf(e.generation())));
                return constr(o);
            }
            case PK_PROOF_OF_OTHER_KEY -> f.set(8, PlutusData.bytes(otherKey.pkProof()));
            case GARBAGE_VIEW_PROOF -> f.set(9, PlutusData.bytes(new byte[192]));
            // The same key's own statement, proved under the other key type's context.
            case PK_PROOF_UNDER_VIEW_TYPE -> f.set(8, PlutusData.bytes(possession.prove(
                    KeyPossession.ctx(KeyPossession.KeyType.VIEWING, POLICY, e.auditor()),
                    keys0.elgamal().possessionStatement(), keys0.elgamal().secretScalar())));
            case VIEW_PROOF_UNDER_ELGAMAL_TYPE -> f.set(9, PlutusData.bytes(keys0.viewing().provePossession(
                    (s, x) -> possession.prove(KeyPossession.ctx(KeyPossession.KeyType.ELGAMAL, POLICY, e.auditor()), s, x))));
            case IDENTITY_KEY_WITH_VALID_PROOF -> {
                f.set(2, PlutusData.integer(BigInteger.ZERO));
                f.set(3, PlutusData.integer(BigInteger.ONE));
                f.set(4, PlutusData.bytes(JubjubPoint.IDENTITY.toBytes()));
                f.set(8, PlutusData.bytes(identityProof(e.auditor())));
            }
            default -> { }
        }
        return constr(f);
    }

    // ------------------------------------------------------------------ Init

    enum InitMutation {
        NONE, NO_SEED, MINT_TWO, EXTRA_MINT_NAME, OTHER_NAME_ONLY, NO_SIGNER, GENERATION_ONE, STAKED_OUTPUT,
        TWO_OUTPUTS, EXTRA_ASSET, REGISTRY_INPUT_SPENT, NO_OUTPUT, HASHED_DATUM, NO_DATUM
    }

    @Test
    @DisplayName("Init: the seed-bound singleton is minted once into a well-formed, possession-verified entry; every mutation is rejected")
    void init() {
        var initCtx = initContext(InitMutation.NONE, EntryMutation.NONE);
        var honest = evaluate(program, initCtx);
        CostProfiler.profile("registry init", program, compiled, initCtx);
        assertInstanceOf(EvalResult.Success.class, honest);
        System.out.println("[AuditorRegistry init] budget: " + honest.budgetConsumed());
        for (InitMutation m : InitMutation.values()) {
            if (m != InitMutation.NONE && evaluate(program, initContext(m, EntryMutation.NONE)) instanceof EvalResult.Success) {
                fail("Init accepted " + m);
            }
        }
        for (EntryMutation m : EntryMutation.values()) {
            if (m != EntryMutation.NONE && evaluate(program, initContext(InitMutation.NONE, m)) instanceof EvalResult.Success) {
                fail("Init accepted entry " + m);
            }
        }
    }

    private PlutusData initContext(InitMutation m, EntryMutation e) {
        Value mint = switch (m) {
            case MINT_TWO -> token(2);
            case EXTRA_MINT_NAME -> token(1).merge(Value.singleton(PolicyId.of(POLICY), TokenName.of("X".getBytes()), BigInteger.ONE));
            case OTHER_NAME_ONLY -> Value.singleton(PolicyId.of(POLICY), TokenName.of("X".getBytes()), BigInteger.ONE);
            default -> token(1);
        };
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).mint(mint).redeemer(PlutusData.integer(0));
        if (m != InitMutation.NO_SIGNER) b.signer(AUDITOR);
        TxOutRef seed = m == InitMutation.NO_SEED ? TestDataBuilder.randomTxOutRef_typed() : SEED;
        b.input(new TxInInfo(seed, new TxOut(WALLET, ada(10), new OutputDatum.NoOutputDatum(), Optional.empty())));
        if (m == InitMutation.REGISTRY_INPUT_SPENT) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(REGISTRY, ada(5),
                    new OutputDatum.OutputDatumInline(PlutusData.integer(0)), Optional.empty())));
        }
        PlutusData datum = m == InitMutation.GENERATION_ONE ? datum(atGeneration(gen0, 1)) : entry(gen0, e);
        Address at = m == InitMutation.STAKED_OUTPUT ? staked() : REGISTRY;
        Value value = ada(5).merge(m == InitMutation.MINT_TWO ? token(2) : token(1));
        if (m == InitMutation.EXTRA_ASSET) value = value.merge(foreignAsset());
        OutputDatum od = switch (m) {
            case HASHED_DATUM -> new OutputDatum.OutputDatumHash(DatumHash.of(filled(32, (byte) 9)));
            case NO_DATUM -> new OutputDatum.NoOutputDatum();
            default -> new OutputDatum.OutputDatumInline(datum);
        };
        if (m != InitMutation.NO_OUTPUT) b.output(new TxOut(at, value, od, Optional.empty()));
        if (m == InitMutation.TWO_OUTPUTS) {
            b.output(new TxOut(REGISTRY, ada(5), new OutputDatum.OutputDatumInline(datum(gen0)), Optional.empty()));
        }
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------ Rotate

    enum RotateMutation {
        NONE, NO_OLD_SIGNER, NO_NEW_SIGNER, SAME_GENERATION, GENERATION_PLUS_TWO, STAKED_OUTPUT, TOKEN_TO_WALLET,
        TWO_OUTPUTS, MINT_DURING_ROTATE, BURN_DURING_ROTATE, INPUT_WITHOUT_TOKEN, SECOND_REGISTRY_INPUT, EXTRA_ASSET,
        NEW_ENTRY_OF_OTHER_REGISTRANT
    }

    @Test
    @DisplayName("Rotate: the entry moves forward one generation under both auditors' signatures; every mutation is rejected")
    void rotate() {
        var rotateCtx = rotateContext(RotateMutation.NONE, EntryMutation.NONE);
        var honest = evaluate(program, rotateCtx);
        CostProfiler.profile("registry rotate", program, compiled, rotateCtx);
        assertInstanceOf(EvalResult.Success.class, honest);
        System.out.println("[AuditorRegistry rotate] budget: " + honest.budgetConsumed());
        for (RotateMutation m : RotateMutation.values()) {
            if (m != RotateMutation.NONE && evaluate(program, rotateContext(m, EntryMutation.NONE)) instanceof EvalResult.Success) {
                fail("Rotate accepted " + m);
            }
        }
        for (EntryMutation m : List.of(EntryMutation.NINE_FIELDS, EntryMutation.PK_ENC_OF_OTHER_KEY,
                EntryMutation.VIEW_KEY_OF_OTHER_KEY, EntryMutation.GARBAGE_VIEW_PROOF,
                EntryMutation.PROOF_FROM_OTHER_REGISTRY, EntryMutation.IDENTITY_KEY_WITH_VALID_PROOF,
                EntryMutation.NON_CANONICAL_PK_V)) {
            if (evaluate(program, rotateContext(RotateMutation.NONE, m)) instanceof EvalResult.Success) {
                fail("Rotate accepted new entry " + m);
            }
        }
    }

    private PlutusData rotateContext(RotateMutation m, EntryMutation e) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x61)), BigInteger.ZERO);
        PlutusData old = datum(atGeneration(gen0, 4));
        var b = ScriptContextTestBuilder.spending(ownRef, old).redeemer(PlutusData.integer(0));
        Value held = m == RotateMutation.INPUT_WITHOUT_TOKEN ? ada(5) : ada(5).merge(token(1));
        b.input(new TxInInfo(ownRef, new TxOut(REGISTRY, held, new OutputDatum.OutputDatumInline(old), Optional.empty())));
        if (m == RotateMutation.SECOND_REGISTRY_INPUT) {
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(staked(), ada(5),
                    new OutputDatum.OutputDatumInline(PlutusData.integer(0)), Optional.empty())));
        }
        if (m != RotateMutation.NO_OLD_SIGNER) b.signer(AUDITOR);
        if (m != RotateMutation.NO_NEW_SIGNER) b.signer(NEW_AUDITOR);
        if (m == RotateMutation.MINT_DURING_ROTATE) {
            b.mint(Value.singleton(PolicyId.of(POLICY), TokenName.of("X".getBytes()), BigInteger.ONE));
        }
        if (m == RotateMutation.BURN_DURING_ROTATE) b.mint(token(-1));
        long generation = switch (m) {
            case SAME_GENERATION -> 4;
            case GENERATION_PLUS_TWO -> 6;
            default -> 5;
        };
        PlutusData next = m == RotateMutation.NEW_ENTRY_OF_OTHER_REGISTRANT
                // gen0's keys and proofs (bound to AUDITOR) claimed by NEW_AUDITOR.
                ? datum(new RegistryEntry(NEW_AUDITOR, 5, gen0.pkU(), gen0.pkV(), gen0.pkEnc(), gen0.viewU(), gen0.viewV(),
                        gen0.viewKey(), gen0.pkProof(), gen0.viewProof()))
                : entry(atGeneration(gen5, generation), e);
        Value value = ada(5).merge(token(1));
        if (m == RotateMutation.EXTRA_ASSET) value = value.merge(foreignAsset());
        Address at = switch (m) {
            case STAKED_OUTPUT -> staked();
            case TOKEN_TO_WALLET -> WALLET;
            default -> REGISTRY;
        };
        b.output(new TxOut(at, value, new OutputDatum.OutputDatumInline(next), Optional.empty()));
        if (m == RotateMutation.TWO_OUTPUTS) {
            b.output(new TxOut(REGISTRY, ada(5), new OutputDatum.OutputDatumInline(datum(gen5)), Optional.empty()));
        }
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------

    static Address staked() {
        return new Address(REGISTRY.credential(), Optional.of(new StakingCredential.StakingHash(
                new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x5a))))));
    }

    static Value token(long qty) {
        return Value.singleton(PolicyId.of(POLICY), TokenName.of(TOKEN), BigInteger.valueOf(qty));
    }

    static Value foreignAsset() {
        return Value.singleton(PolicyId.of(filled(28, (byte) 0x77)), TokenName.of("Z".getBytes()), BigInteger.ONE);
    }

    static Value ada(long ada) {
        return Value.lovelace(BigInteger.valueOf(ada * 1_000_000));
    }

    static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
