package com.bloxbean.cardano.zeroj.usecases.dpp.onchain;

import com.bloxbean.cardano.zeroj.usecases.dpp.passport.Claim;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ClaimOpening;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.DppCircuits;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.Fields;
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
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code DppPassport} in the Plutus VM (ADR-0009 D1, invariants I2 and I3, M6 VM exit
 * criteria): an honest, auditor-co-signed passport mint is accepted and every mutation of mint
 * checks (a)–(d) is refused; the only spend accepted is an auditor-signed Revoke that burns the
 * passport.
 */
class DppPassportVmTest extends ContractTest {

    static final long THRESHOLD = 50;
    static final byte[] POLICY = filled(28, (byte) 0x7d);
    static final byte[] MALLORY_POLICY = filled(28, (byte) 0x6e);
    static final byte[] MANUFACTURER = filled(28, (byte) 0xa1);
    static final byte[] AUDITOR = filled(28, (byte) 0xb2);
    static final byte[] MALLORY = filled(28, (byte) 0x3e);
    static final byte[] PRODUCT = "BAT-SN001".getBytes(StandardCharsets.UTF_8);
    static final byte[] OTHER_PRODUCT = "BAT-SN002".getBytes(StandardCharsets.UTF_8);
    static final Address PASSPORT_ADDRESS = scriptAddress(POLICY);

    private static CompileResult compiled;
    private static Program program;
    private static Program malloryProgram;
    private static ClaimOpening carbon;
    private static List<ClaimOpening> others;
    private static SnarkjsToCardano.ProofCompressed proof;
    private static ClaimOpening highCarbon;
    private static SnarkjsToCardano.ProofCompressed looserThresholdProof;
    private static SnarkjsToCardano.ProofCompressed otherCommitmentProof;

    @BeforeAll
    static void setup() {
        DppCircuits circuits = DppCircuits.compile();
        carbon = ClaimOpening.fresh(Claim.CARBON, 7);
        others = List.of(ClaimOpening.fresh(Claim.RECYCLED, 45), ClaimOpening.fresh(Claim.ORIGIN, 276),
                ClaimOpening.fresh(Claim.INSPECTIONS, 11, 1000, 13, 2000, 11, 3000));
        proof = ProverToCardano.compressProof(circuits.prove(carbon, BigInteger.valueOf(THRESHOLD)));
        // 65 kg fails the policy's 50 kg, but proves against a threshold the manufacturer chose.
        highCarbon = ClaimOpening.fresh(Claim.CARBON, 65);
        looserThresholdProof = ProverToCardano.compressProof(circuits.prove(highCarbon, BigInteger.valueOf(100)));
        otherCommitmentProof = ProverToCardano.compressProof(
                circuits.prove(ClaimOpening.fresh(Claim.CARBON, 7), BigInteger.valueOf(THRESHOLD)));
        var vk = circuits.circuit(Claim.CARBON).compressedVk();
        compiled = new DppPassportVmTest().compileValidatorWithSourceMap(DppPassport.class, Path.of("src/main/java"));
        program = compiled.program().applyParams(params(MANUFACTURER, vk));
        malloryProgram = compiled.program().applyParams(params(MALLORY, vk));
    }

    static PlutusData[] params(byte[] manufacturer, SnarkjsToCardano.VkCompressed vk) {
        PlutusData[] ic = vk.ic().stream().map(PlutusData::bytes).toArray(PlutusData[]::new);
        return new PlutusData[]{PlutusData.bytes(manufacturer), PlutusData.bytes(AUDITOR),
                PlutusData.integer(BigInteger.valueOf(Claim.CARBON.id())), PlutusData.bytes(Claim.CARBON.sigma()),
                PlutusData.integer(BigInteger.valueOf(THRESHOLD)),
                PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()), PlutusData.bytes(vk.gamma()),
                PlutusData.bytes(vk.delta()), PlutusData.list(ic)};
    }

    // ------------------------------------------------------------------ Issue

    enum Mint {
        NONE, NO_AUDITOR_SIGNATURE, NO_MANUFACTURER_SIGNATURE, OTHER_MANUFACTURER_POLICY_REPLAY, MANUFACTURER_IMPOSTOR,
        DATUM_OTHER_MANUFACTURER, DATUM_OTHER_PRODUCT, TOKEN_NAME_NOT_PRODUCT_ID, EMPTY_PRODUCT_ID, PRODUCT_ID_33_BYTES,
        EXTRA_MINT_ENTRY, QUANTITY_TWO, LOOSER_THRESHOLD_PROOF, PROOF_FOR_OTHER_COMMITMENT, MALFORMED_PROOF,
        NON_CANONICAL_GATED_U, NON_CANONICAL_OTHER_V, SHORT_SIGMA, GATED_WRONG_SIGMA, GATED_MISSING, DUPLICATE_CLAIM,
        DUPLICATE_GATED_CLAIM, FIVE_CLAIMS, UNKNOWN_CLAIM_ID, PASSPORT_AT_MANUFACTURER, PASSPORT_WITH_STAKE_CREDENTIAL,
        PASSPORT_AT_OTHER_SCRIPT, TOKEN_IN_TWO_OUTPUTS, EXTRA_TOKEN_IN_PASSPORT, DATUM_NOT_INLINE, DATUM_EXTRA_FIELD,
        ENTRY_EXTRA_FIELD
    }

    @Test
    @DisplayName("Issue: an honest co-signed passport is accepted; every mutation of checks (a)-(d) is refused")
    void issue() {
        var ok = evaluate(program, issueContext(Mint.NONE));
        assertSuccess(ok);
        long cpu = ok.budgetConsumed().cpuSteps();
        long mem = ok.budgetConsumed().memoryUnits();
        System.out.printf("[DppPassport Issue] budget: cpu=%,d (%.1f%% of 10,000,000,000) mem=%,d (%.1f%% of 16,500,000)%n",
                cpu, 100.0 * cpu / 10_000_000_000L, mem, 100.0 * mem / 16_500_000L);
        for (Mint m : Mint.values()) {
            if (m == Mint.NONE) continue;
            Program p = m == Mint.OTHER_MANUFACTURER_POLICY_REPLAY ? malloryProgram : program;
            if (evaluate(p, issueContext(m)) instanceof EvalResult.Success) fail("Issue accepted " + m);
        }
    }

    @Test
    @DisplayName("Issue: the minimal passport (the gated claim only) is accepted")
    void issueGatedOnly() {
        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY))
                .mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(PRODUCT), BigInteger.ONE))
                .redeemer(issueRedeemer(proof)).signer(MANUFACTURER).signer(AUDITOR);
        b.output(passportOutput(PASSPORT_ADDRESS, PRODUCT, passport(PRODUCT, MANUFACTURER, List.of(entry(carbon)))));
        assertSuccess(evaluate(program, b.buildPlutusData()));
    }

    private PlutusData issueContext(Mint m) {
        byte[] policy = m == Mint.OTHER_MANUFACTURER_POLICY_REPLAY ? MALLORY_POLICY : POLICY;
        Address passportAddress = scriptAddress(policy);
        byte[] tokenName = switch (m) {
            case TOKEN_NAME_NOT_PRODUCT_ID -> OTHER_PRODUCT;
            case EMPTY_PRODUCT_ID -> new byte[0];
            case PRODUCT_ID_33_BYTES -> filled(33, (byte) 'P');
            default -> PRODUCT;
        };
        byte[] datumProduct = switch (m) {
            case DATUM_OTHER_PRODUCT -> OTHER_PRODUCT;
            case EMPTY_PRODUCT_ID, PRODUCT_ID_33_BYTES -> tokenName;
            default -> PRODUCT;
        };
        byte[] datumManufacturer = switch (m) {
            case DATUM_OTHER_MANUFACTURER, OTHER_MANUFACTURER_POLICY_REPLAY -> MALLORY;
            default -> MANUFACTURER;
        };

        // The claims: carbon (gated) first, then the three off-chain claims.
        ClaimOpening gated = m == Mint.LOOSER_THRESHOLD_PROOF ? highCarbon : carbon;
        List<PlutusData> claims = new ArrayList<>();
        JubjubPoint g = gated.point();
        BigInteger gu = m == Mint.NON_CANONICAL_GATED_U ? g.affineU().add(Fields.FR) : g.affineU();
        byte[] gatedSigma = m == Mint.GATED_WRONG_SIGMA ? Claim.RECYCLED.sigma() : Claim.CARBON.sigma();
        if (m != Mint.GATED_MISSING) claims.add(entry(Claim.CARBON.id(), gatedSigma, gu, g.affineV()));
        for (ClaimOpening o : others) claims.add(entry(o));
        switch (m) {
            case NON_CANONICAL_OTHER_V -> {
                JubjubPoint p = others.get(1).point();
                claims.set(2, entry(Claim.ORIGIN.id(), Claim.ORIGIN.sigma(), p.affineU(), p.affineV().add(Fields.FR)));
            }
            case SHORT_SIGMA -> {
                JubjubPoint p = others.get(0).point();
                claims.set(1, entry(Claim.RECYCLED.id(), Arrays.copyOf(Claim.RECYCLED.sigma(), 31), p.affineU(), p.affineV()));
            }
            case DUPLICATE_CLAIM -> claims.set(3, entry(others.get(1)));       // origin twice, no inspections
            case DUPLICATE_GATED_CLAIM -> claims.set(1, entry(ClaimOpening.fresh(Claim.CARBON, 7)));
            case FIVE_CLAIMS -> claims.add(entry(others.get(0)));
            case UNKNOWN_CLAIM_ID -> {
                JubjubPoint p = others.get(2).point();
                claims.set(3, entry(7, Claim.INSPECTIONS.sigma(), p.affineU(), p.affineV()));
            }
            case ENTRY_EXTRA_FIELD -> {
                JubjubPoint p = others.get(0).point();
                claims.set(1, PlutusData.constr(0, PlutusData.integer(BigInteger.valueOf(Claim.RECYCLED.id())),
                        PlutusData.bytes(Claim.RECYCLED.sigma()), PlutusData.integer(p.affineU()),
                        PlutusData.integer(p.affineV()), PlutusData.integer(BigInteger.ONE)));
            }
            default -> { }
        }
        PlutusData datum = m == Mint.DATUM_EXTRA_FIELD
                ? PlutusData.constr(0, PlutusData.bytes(datumProduct), PlutusData.bytes(datumManufacturer),
                        PlutusData.list(claims.toArray(PlutusData[]::new)), PlutusData.integer(BigInteger.ONE))
                : passport(datumProduct, datumManufacturer, claims);

        Value mint = Value.singleton(PolicyId.of(policy), TokenName.of(tokenName),
                BigInteger.valueOf(m == Mint.QUANTITY_TWO ? 2 : 1));
        if (m == Mint.EXTRA_MINT_ENTRY) {
            mint = mint.merge(Value.singleton(PolicyId.of(policy), TokenName.of(OTHER_PRODUCT), BigInteger.ONE));
        }
        SnarkjsToCardano.ProofCompressed p = switch (m) {
            case LOOSER_THRESHOLD_PROOF -> looserThresholdProof;
            case PROOF_FOR_OTHER_COMMITMENT -> otherCommitmentProof;
            default -> proof;
        };
        PlutusData redeemer = m == Mint.MALFORMED_PROOF
                ? PlutusData.constr(0, PlutusData.bytes(flipped(p.piA())), PlutusData.bytes(p.piB()), PlutusData.bytes(p.piC()))
                : issueRedeemer(p);

        var b = ScriptContextTestBuilder.minting(PolicyId.of(policy)).mint(mint).redeemer(redeemer);
        switch (m) {
            case NO_AUDITOR_SIGNATURE -> b.signer(MANUFACTURER);
            case NO_MANUFACTURER_SIGNATURE -> b.signer(AUDITOR);
            case OTHER_MANUFACTURER_POLICY_REPLAY -> b.signer(MALLORY);     // the auditor never co-signs it
            case MANUFACTURER_IMPOSTOR -> b.signer(MALLORY).signer(AUDITOR);
            default -> b.signer(MANUFACTURER).signer(AUDITOR);
        }

        Address at = switch (m) {
            case PASSPORT_AT_MANUFACTURER -> new Address(new Credential.PubKeyCredential(PubKeyHash.of(MANUFACTURER)), Optional.empty());
            case PASSPORT_WITH_STAKE_CREDENTIAL -> new Address(new Credential.ScriptCredential(ScriptHash.of(policy)),
                    Optional.of(new StakingCredential.StakingHash(new Credential.PubKeyCredential(PubKeyHash.of(MANUFACTURER)))));
            case PASSPORT_AT_OTHER_SCRIPT -> scriptAddress(MALLORY_POLICY);
            default -> passportAddress;
        };
        Value value = Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(policy), TokenName.of(tokenName), BigInteger.valueOf(m == Mint.QUANTITY_TWO ? 2 : 1)));
        if (m == Mint.EXTRA_TOKEN_IN_PASSPORT) {
            value = value.merge(Value.singleton(PolicyId.of(filled(28, (byte) 0x44)), TokenName.of(filled(4, (byte) 1)), BigInteger.ONE));
        }
        if (m == Mint.EXTRA_MINT_ENTRY) {
            value = value.merge(Value.singleton(PolicyId.of(policy), TokenName.of(OTHER_PRODUCT), BigInteger.ONE));
        }
        OutputDatum outputDatum = m == Mint.DATUM_NOT_INLINE
                ? new OutputDatum.OutputDatumHash(DatumHash.of(filled(32, (byte) 9)))
                : new OutputDatum.OutputDatumInline(datum);
        if (m == Mint.TOKEN_IN_TWO_OUTPUTS) {
            // An older passport token of the same name, spent in and paid out again beside the new one.
            b.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), new TxOut(PASSPORT_ADDRESS,
                    Value.lovelace(BigInteger.valueOf(2_000_000)).merge(Value.singleton(PolicyId.of(policy), TokenName.of(tokenName), BigInteger.ONE)),
                    new OutputDatum.OutputDatumInline(datum), Optional.empty())));
            b.output(new TxOut(new Address(new Credential.PubKeyCredential(PubKeyHash.of(MALLORY)), Optional.empty()),
                    Value.lovelace(BigInteger.valueOf(2_000_000)).merge(Value.singleton(PolicyId.of(policy), TokenName.of(tokenName), BigInteger.ONE)),
                    new OutputDatum.NoOutputDatum(), Optional.empty()));
        }
        b.output(new TxOut(at, value, outputDatum, Optional.empty()));
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------ Revoke and Burn

    enum Spend {
        REVOKE, REVOKE_WITHOUT_AUDITOR, TRANSFER, DATUM_CHANGE, BURN_OTHER_TOKEN, BURN_AND_MINT, BURN_TWO
    }

    @Test
    @DisplayName("Spend: only an auditor-signed Revoke that burns the passport is accepted (spend and burn purposes)")
    void spend() {
        var revoke = evaluate(program, spendContext(Spend.REVOKE, true));
        var burn = evaluate(program, spendContext(Spend.REVOKE, false));
        assertSuccess(revoke);
        assertSuccess(burn);
        long cpu = revoke.budgetConsumed().cpuSteps() + burn.budgetConsumed().cpuSteps();
        long mem = revoke.budgetConsumed().memoryUnits() + burn.budgetConsumed().memoryUnits();
        System.out.printf("[DppPassport Revoke] budget (spend + burn): cpu=%,d (%.2f%% of 10,000,000,000) mem=%,d (%.2f%% of 16,500,000)%n",
                cpu, 100.0 * cpu / 10_000_000_000L, mem, 100.0 * mem / 16_500_000L);
        for (Spend s : Spend.values()) {
            if (s == Spend.REVOKE) continue;
            if (evaluate(program, spendContext(s, true)) instanceof EvalResult.Success) fail("spend accepted " + s);
            // The Burn purpose checks the auditor and a single −1 entry; which token it is, is the
            // spending purpose's check (a passport token exists only at the script, so burning one
            // always spends it). TRANSFER and DATUM_CHANGE mint nothing, so no burn purpose runs.
            boolean burnRefuses = s == Spend.REVOKE_WITHOUT_AUDITOR || s == Spend.BURN_AND_MINT || s == Spend.BURN_TWO;
            if (burnRefuses && evaluate(program, spendContext(s, false)) instanceof EvalResult.Success) {
                fail("burn accepted " + s);
            }
        }
        // A datum change signed by both parties is still refused: the spend allows nothing but Revoke.
        assertInstanceOf(EvalResult.Failure.class, evaluate(program, spendContext(Spend.DATUM_CHANGE, true)));
    }

    @Test
    @DisplayName("Burn: refused without the auditor and for a positive quantity under the Burn redeemer")
    void burnNegatives() {
        var noAuditor = ScriptContextTestBuilder.minting(PolicyId.of(POLICY))
                .mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(PRODUCT), BigInteger.valueOf(-1)))
                .redeemer(PlutusData.constr(1, PlutusData.integer(BigInteger.ZERO))).signer(MANUFACTURER);
        assertInstanceOf(EvalResult.Failure.class, evaluate(program, noAuditor.buildPlutusData()));
        var positive = ScriptContextTestBuilder.minting(PolicyId.of(POLICY))
                .mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(PRODUCT), BigInteger.ONE))
                .redeemer(PlutusData.constr(1, PlutusData.integer(BigInteger.ZERO))).signer(AUDITOR);
        assertInstanceOf(EvalResult.Failure.class, evaluate(program, positive.buildPlutusData()));
    }

    private PlutusData spendContext(Spend s, boolean spending) {
        TxOutRef ownRef = new TxOutRef(TxId.of(filled(32, (byte) 0x51)), BigInteger.ZERO);
        PlutusData datum = passport(PRODUCT, MANUFACTURER, honestClaims());
        PlutusData revoke = PlutusData.constr(0, PlutusData.integer(BigInteger.ZERO));
        var b = spending
                ? ScriptContextTestBuilder.spending(ownRef, datum).redeemer(revoke)
                : ScriptContextTestBuilder.minting(PolicyId.of(POLICY)).redeemer(PlutusData.constr(1, PlutusData.integer(BigInteger.ZERO)));
        b.input(new TxInInfo(ownRef, passportOutput(PASSPORT_ADDRESS, PRODUCT, datum)));
        switch (s) {
            case REVOKE_WITHOUT_AUDITOR -> b.signer(MANUFACTURER);
            case DATUM_CHANGE -> b.signer(MANUFACTURER).signer(AUDITOR);
            default -> b.signer(AUDITOR);
        }
        switch (s) {
            case REVOKE, REVOKE_WITHOUT_AUDITOR -> b.mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(PRODUCT), BigInteger.valueOf(-1)));
            case TRANSFER -> b.output(passportOutput(new Address(new Credential.PubKeyCredential(PubKeyHash.of(MALLORY)),
                    Optional.empty()), PRODUCT, datum));
            case DATUM_CHANGE -> b.output(passportOutput(PASSPORT_ADDRESS, PRODUCT,
                    passport(PRODUCT, MANUFACTURER, List.of(entry(ClaimOpening.fresh(Claim.CARBON, 7))))));
            case BURN_OTHER_TOKEN -> b.mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(OTHER_PRODUCT), BigInteger.valueOf(-1)));
            case BURN_AND_MINT -> b.mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(PRODUCT), BigInteger.valueOf(-1))
                    .merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(OTHER_PRODUCT), BigInteger.ONE)));
            case BURN_TWO -> b.mint(Value.singleton(PolicyId.of(POLICY), TokenName.of(PRODUCT), BigInteger.valueOf(-2)));
        }
        return b.buildPlutusData();
    }

    // ------------------------------------------------------------------ helpers

    private static List<PlutusData> honestClaims() {
        List<PlutusData> claims = new ArrayList<>();
        claims.add(entry(carbon));
        for (ClaimOpening o : others) claims.add(entry(o));
        return claims;
    }

    static PlutusData passport(byte[] productId, byte[] manufacturer, List<PlutusData> claims) {
        return PlutusData.constr(0, PlutusData.bytes(productId), PlutusData.bytes(manufacturer),
                PlutusData.list(claims.toArray(PlutusData[]::new)));
    }

    static PlutusData entry(ClaimOpening o) {
        JubjubPoint p = o.point();
        return entry(o.claim().id(), o.claim().sigma(), p.affineU(), p.affineV());
    }

    static PlutusData entry(int claim, byte[] sigma, BigInteger u, BigInteger v) {
        return PlutusData.constr(0, PlutusData.integer(BigInteger.valueOf(claim)), PlutusData.bytes(sigma),
                PlutusData.integer(u), PlutusData.integer(v));
    }

    static PlutusData issueRedeemer(SnarkjsToCardano.ProofCompressed p) {
        return PlutusData.constr(0, PlutusData.bytes(p.piA()), PlutusData.bytes(p.piB()), PlutusData.bytes(p.piC()));
    }

    static TxOut passportOutput(Address at, byte[] productId, PlutusData datum) {
        return new TxOut(at, Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(POLICY), TokenName.of(productId), BigInteger.ONE)),
                new OutputDatum.OutputDatumInline(datum), Optional.empty());
    }

    static Address scriptAddress(byte[] hash) {
        return new Address(new Credential.ScriptCredential(ScriptHash.of(hash)), Optional.empty());
    }

    private static byte[] flipped(byte[] bytes) {
        byte[] copy = bytes.clone();
        copy[copy.length - 1] ^= 1;
        return copy;
    }

    static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
