package com.bloxbean.cardano.zeroj.usecases.airdrop.onchain;

import com.bloxbean.cardano.zeroj.usecases.airdrop.service.AirdropEpoch;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.AirdropProofService;
import com.bloxbean.cardano.zeroj.usecases.airdrop.service.HolderWallet;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PolicyId;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.StakingCredential;
import org.julclang.ledger.TokenName;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.Value;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.ScriptContextTestBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubMessage;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * {@code FaucetMintingPolicy} in the Plutus VM (ADR-0009 D3, milestone M3): a valid claim that
 * pays the proved key-hash recipient at least {@code payout} is accepted; a payout to another
 * key, to a script credential with the recipient's hash, or below {@code payout}, an epoch of 0
 * or ≥ r, and a credential signed with the formerly published issuer seed are refused.
 *
 * <p>Proofs are real Groth16 proofs of the unchanged circuit over a development setup; the
 * expected nullifier, message and epoch come from the ZeroJ host APIs ({@code PoseidonHash},
 * {@code EdDSAJubjub}), not from the circuit under test.
 */
class FaucetMintingPolicyVmTest extends ContractTest {

    private static final byte[] POLICY = filled(28, (byte) 0x7f);
    private static final byte[] RECIPIENT = filled(28, (byte) 0xa1);
    private static final byte[] MALLORY = filled(28, (byte) 0x3e);
    private static final long PAYOUT = 2_000_000L;
    private static final BigInteger R = FieldConfig.BLS12_381.prime();

    /** The issuer seed this demo used to publish in {@code PersonhoodIssuerService}. */
    private static final BigInteger OLD_PUBLISHED_SEED = new BigInteger(
            "deadbeefcafef00d0123456789abcdefdeadbeefcafef00d0123456789abcdef", 16);

    private static EdDSAJubjub.Keypair issuer;
    private static EdDSAJubjub.Keypair oldSeedIssuer;
    private static BigInteger epoch;
    private static Claim valid;
    private static Claim epochZero;
    private static Claim oldSeed;
    private static Program program;
    private static Program epochZeroProgram;
    private static Program epochAtLeastRProgram;
    private static Program oldSeedProgram;

    private record Claim(BigInteger pkU, BigInteger pkV, BigInteger epoch, BigInteger nullifier,
                         SnarkjsToCardano.ProofCompressed proof) {}

    @BeforeAll
    static void setup() {
        var prover = new AirdropProofService(14, Path.of("build", "airdrop-test-setup").toString());
        prover.init();
        var random = new SecureRandom();
        issuer = EdDSAJubjub.generateKeypair(random);
        BigInteger sk = OLD_PUBLISHED_SEED.mod(JubjubCurve.SUBGROUP_ORDER);
        oldSeedIssuer = EdDSAJubjub.keypairFromSecret(sk);

        byte[] seedTx = new byte[32];
        random.nextBytes(seedTx);
        epoch = AirdropEpoch.policyEpoch(
                AirdropEpoch.deploymentId(HexFormat.of().formatHex(seedTx), 0), 1);
        BigInteger recipient = new BigInteger(1, RECIPIENT);
        BigInteger pid = new BigInteger(252, random);

        valid = claim(prover, issuer, pid, epoch, recipient);
        epochZero = claim(prover, issuer, pid, BigInteger.ZERO, recipient);
        oldSeed = claim(prover, oldSeedIssuer, pid, epoch, recipient);

        var compiled = new FaucetMintingPolicyVmTest().compileValidatorWithSourceMap(
                FaucetMintingPolicy.class, Path.of("src/main/java"));
        var vk = ProverToCardano.compressVk(prover.getSetupResult());
        program = apply(compiled.program(), vk, issuer, epoch);
        epochZeroProgram = apply(compiled.program(), vk, issuer, BigInteger.ZERO);
        epochAtLeastRProgram = apply(compiled.program(), vk, issuer, epoch.add(R));
        oldSeedProgram = apply(compiled.program(), vk, oldSeedIssuer, epoch);
    }

    private static Claim claim(AirdropProofService prover, EdDSAJubjub.Keypair key, BigInteger pid,
                               BigInteger epoch, BigInteger recipient) {
        BigInteger m = HolderWallet.message(pid);
        var sig = EdDSAJubjub.signCompatibilityOffline(key, canonicalMessage(m));
        Groth16ProofBLS381 proof = prover.prove(key.pk(), sig, pid, epoch, recipient).proof();
        return new Claim(key.pk().affineU(), key.pk().affineV(), epoch,
                HolderWallet.nullifier(pid, epoch), ProverToCardano.compressProof(proof));
    }

    private static Program apply(Program program, SnarkjsToCardano.VkCompressed vk, EdDSAJubjub.Keypair issuer,
                                 BigInteger policyEpoch) {
        PlutusData[] ic = vk.ic().stream().map(PlutusData::bytes).toArray(PlutusData[]::new);
        return program.applyParams(
                PlutusData.bytes(vk.alpha()), PlutusData.bytes(vk.beta()),
                PlutusData.bytes(vk.gamma()), PlutusData.bytes(vk.delta()), PlutusData.list(ic),
                PlutusData.integer(issuer.pk().affineU()), PlutusData.integer(issuer.pk().affineV()),
                PlutusData.integer(policyEpoch), PlutusData.integer(BigInteger.valueOf(PAYOUT)));
    }

    enum Mutation {
        NONE, PAYOUT_TO_OTHER_KEY, DATUM_RECIPIENT_REWRITTEN, SCRIPT_CREDENTIAL_PAYOUT, PAYOUT_BELOW,
        NO_PAYOUT, EPOCH_ZERO, EPOCH_AT_LEAST_R, OLD_SEED_CREDENTIAL, RECEIPT_NAME_NOT_NULLIFIER,
        TWO_RECEIPTS, EXTRA_ENTRY_QTY_1, EXTRA_ENTRY_QTY_2, EXTRA_ENTRY_BURN, RECEIPT_WITH_STAKE_CREDENTIAL,
        TAMPERED_PROOF, NOT_ELIGIBLE
    }

    @Test
    @DisplayName("Faucet policy: a valid claim pays the proved key-hash recipient; every mutation is rejected")
    void faucet() {
        var ok = evaluate(program, context(Mutation.NONE));
        assertSuccess(ok);
        System.out.println("[FaucetMintingPolicy] budget: " + ok.budgetConsumed());
        List<Mutation> accepted = new ArrayList<>();
        for (Mutation m : Mutation.values()) {
            if (m == Mutation.NONE) continue;
            Program p = switch (m) {
                case EPOCH_ZERO -> epochZeroProgram;
                case EPOCH_AT_LEAST_R -> epochAtLeastRProgram;
                default -> program;
            };
            if (evaluate(p, context(m)) instanceof EvalResult.Success) {
                accepted.add(m);
            }
        }
        if (!accepted.isEmpty()) {
            fail("faucet policy accepted " + accepted);
        }
    }

    @Test
    @DisplayName("Faucet policy: the old-seed credential is a valid proof, refused only because the issuer key is pinned")
    void oldSeedCredentialIsRefusedByIssuerPinning() {
        // Control: under a policy pinned to the old published key, the same claim is accepted.
        // Under the deployed (random) key it is refused, so the refusal is the issuer binding.
        assertSuccess(evaluate(oldSeedProgram, context(Mutation.OLD_SEED_CREDENTIAL)));
        if (evaluate(program, context(Mutation.OLD_SEED_CREDENTIAL)) instanceof EvalResult.Success) {
            fail("a credential signed with the old published seed must be refused");
        }
    }

    private PlutusData context(Mutation m) {
        Claim c = switch (m) {
            case EPOCH_ZERO -> epochZero;
            case OLD_SEED_CREDENTIAL -> oldSeed;
            default -> valid;
        };
        BigInteger datumEpoch = m == Mutation.EPOCH_AT_LEAST_R ? c.epoch().add(R) : c.epoch();
        byte[] datumRecipient = m == Mutation.DATUM_RECIPIENT_REWRITTEN ? MALLORY : RECIPIENT;
        BigInteger eligible = m == Mutation.NOT_ELIGIBLE ? BigInteger.ZERO : BigInteger.ONE;
        byte[] receiptName = m == Mutation.RECEIPT_NAME_NOT_NULLIFIER
                ? i2osp32(c.nullifier().add(BigInteger.ONE)) : i2osp32(c.nullifier());
        // TWO_RECEIPTS: the receipt output holds both units, so only the quantity rule refuses it.
        BigInteger quantity = BigInteger.valueOf(m == Mutation.TWO_RECEIPTS ? 2 : 1);
        var p = c.proof();
        byte[] piA = m == Mutation.TAMPERED_PROOF ? flipped(p.piA()) : p.piA();

        PlutusData datum = PlutusData.list(
                PlutusData.integer(c.pkU()), PlutusData.integer(c.pkV()), PlutusData.integer(datumEpoch),
                PlutusData.integer(c.nullifier()), PlutusData.integer(new BigInteger(1, datumRecipient)),
                PlutusData.integer(eligible));
        Value receipt = Value.singleton(PolicyId.of(POLICY), TokenName.of(receiptName), quantity);
        // An extra entry under the policy, placed after the receipt (as the ledger's sorted map
        // would place 0xff…ff): the receipt is still found, so only the exact-entry rule can
        // refuse the mint. (Value.merge prepends new names, hence extra.merge(receipt).)
        long extra = switch (m) {
            case EXTRA_ENTRY_QTY_1 -> 1;
            case EXTRA_ENTRY_QTY_2 -> 2;
            case EXTRA_ENTRY_BURN -> -1;
            default -> 0;
        };
        Value mint = extra == 0 ? receipt : Value.singleton(PolicyId.of(POLICY),
                TokenName.of(filled(32, (byte) 0xff)), BigInteger.valueOf(extra)).merge(receipt);
        Optional<StakingCredential> receiptStake = m == Mutation.RECEIPT_WITH_STAKE_CREDENTIAL
                ? Optional.of(new StakingCredential.StakingHash(new Credential.PubKeyCredential(PubKeyHash.of(MALLORY))))
                : Optional.empty();

        var b = ScriptContextTestBuilder.minting(PolicyId.of(POLICY))
                .mint(mint)
                .redeemer(PlutusData.constr(0, PlutusData.bytes(piA), PlutusData.bytes(p.piB()), PlutusData.bytes(p.piC())));
        b.output(new TxOut(new Address(new Credential.ScriptCredential(ScriptHash.of(POLICY)), receiptStake),
                Value.lovelace(BigInteger.valueOf(2_000_000)).merge(receipt),
                new OutputDatum.OutputDatumInline(datum), Optional.empty()));

        if (m != Mutation.NO_PAYOUT) {
            Credential payee = switch (m) {
                case PAYOUT_TO_OTHER_KEY, DATUM_RECIPIENT_REWRITTEN -> new Credential.PubKeyCredential(PubKeyHash.of(MALLORY));
                case SCRIPT_CREDENTIAL_PAYOUT -> new Credential.ScriptCredential(ScriptHash.of(RECIPIENT));
                default -> new Credential.PubKeyCredential(PubKeyHash.of(RECIPIENT));
            };
            long amount = m == Mutation.PAYOUT_BELOW ? PAYOUT - 1 : PAYOUT;
            b.output(new TxOut(new Address(payee, Optional.empty()), Value.lovelace(BigInteger.valueOf(amount)),
                    new OutputDatum.NoOutputDatum(), Optional.empty()));
        }
        // Change back to the faucet admin: an unrelated key output that never satisfies the rule.
        b.output(new TxOut(new Address(new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x0d))), Optional.empty()),
                Value.lovelace(BigInteger.valueOf(500_000_000)), new OutputDatum.NoOutputDatum(), Optional.empty()));
        return b.buildPlutusData();
    }

    private static byte[] i2osp32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - len, out, 32 - len, len);
        return out;
    }

    private static JubjubMessage canonicalMessage(BigInteger fieldElement) {
        return JubjubMessage.fromCanonicalFieldBytes(i2osp32(fieldElement));
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
