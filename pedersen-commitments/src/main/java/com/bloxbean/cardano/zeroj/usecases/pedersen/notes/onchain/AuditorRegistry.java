package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MultiValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.Purpose;
import org.julclang.stdlib.lib.ContextsLib;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * An auditor's key registry (ADR-0007 N1; ZeroJ ADR-0055 spec §8.1, singleton option). One script
 * is the registry token's policy and the registry address.
 *
 * <p>The registry holds exactly one entry, ever: a single {@code registryToken} minted once (the
 * transaction must spend the seed output {@code seedRef = txId ‖ I2OSP2(index)}), and moved
 * forward on every rotation by spending the entry and recreating it. The token is never burned or
 * duplicated, so no older entry stays unspent and a ledger that reads the registry always sees the
 * current generation.
 *
 * <p>Entry datum, exactly {@code Constr 0 [auditor B28, generation I, pkU, pkV, pkEnc B32, viewU,
 * viewV, viewKey B32, pkProof B192, viewProof B192]}: both keys as canonical coordinates and as
 * the encoding of exactly those coordinates, and different from each other ({@link RegistryLib#isEntry}).
 *
 * <p><b>Possession</b> (ADR-0055 Q6). Every Init and Rotate verifies both Groth16 possession
 * proofs, each over {@code [ctx, G.u, G.v, u, v, u, v]} with
 * {@code ctx = OS2IP(blake2b_256(prefix ‖ type ‖ policy ‖ auditor)[0..30])} (ADR-0007 N7). So
 * every registered key is a valid subgroup key its registrant holds: no ledger's spend circuits can
 * be made unsatisfiable through it, honest senders can always admit it, and a proof copied from
 * another registry, registrant or key type fails.
 *
 * <ul>
 *   <li><b>Init</b> (mint): spends the seed; mints exactly one {@code registryToken}; exactly one
 *       output under the registry credential, at the exact enterprise address, holding lovelace
 *       and the token only, with a well-formed entry of generation 0; the entry's auditor signs.</li>
 *   <li><b>Rotate</b> (spend): the spent entry holds the token; exactly one registry input; no
 *       mint under the policy; exactly one output under the registry credential, as for Init,
 *       with generation {@code old + 1}; the old and the new auditor both sign.</li>
 * </ul>
 */
@MultiValidator
public class AuditorRegistry {

    @Param static byte[] seedRef;
    @Param static byte[] registryToken;
    @Param static byte[] elgamalCtxPrefix;  // ASCII("zeroj.usecases.key-possession.v1") ‖ 0x01
    @Param static byte[] viewCtxPrefix;     // ASCII("zeroj.usecases.key-possession.v1") ‖ 0x02
    @Param static BigInteger genU;      // the Jubjub generator G (pedersen-jubjub-v1 §2)
    @Param static BigInteger genV;
    @Param static byte[] possAlpha;
    @Param static byte[] possBeta;
    @Param static byte[] possGamma;
    @Param static byte[] possDelta;
    @Param static PlutusData possIc;

    @Entrypoint(purpose = Purpose.MINT)
    public static boolean mint(PlutusData redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        Address exact = new Address(own, Optional.empty());

        boolean seedConsumed = false;
        for (TxInInfo input : txInfo.inputs()) {
            seedConsumed = seedConsumed
                    || Builtins.equalsByteString(ValuesLib.refBytes(input.outRef()), seedRef);
        }
        if (!seedConsumed
                || ChainLib.policyEntryCount(txInfo.mint(), policy) != 1
                || ValuesLib.assetOf(txInfo.mint(), policy, registryToken).compareTo(BigInteger.ONE) != 0
                || ChainLib.countInputs(txInfo.inputs(), own) != 0) {
            return false;
        }
        TxOut entry = onlyEntryOutput(txInfo, own, exact, policy);
        PlutusData datum = ChainLib.inlineDatum(entry);
        return RegistryLib.isEntry(datum)
                && RegistryLib.entryGeneration(datum).compareTo(BigInteger.ZERO) == 0
                && ChainLib.signedBy(txInfo, RegistryLib.entryAuditor(datum))
                && possessed(datum, policy);
    }

    @Entrypoint(purpose = Purpose.SPEND)
    public static boolean spend(PlutusData datum, PlutusData redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        byte[] policy = ContextsLib.ownHash(ctx);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        Address exact = new Address(own, Optional.empty());
        var ownInputOptional = ContextsLib.findOwnInput(ctx);
        if (ownInputOptional.isEmpty()) return false;
        TxInInfo ownInput = ownInputOptional.get();
        if (ValuesLib.assetOf(ownInput.resolved().value(), policy, registryToken).compareTo(BigInteger.ONE) != 0
                || ChainLib.countInputs(txInfo.inputs(), own) != 1
                || ChainLib.policyEntryCount(txInfo.mint(), policy) != 0
                || !RegistryLib.isEntry(datum)) {
            return false;
        }
        TxOut entry = onlyEntryOutput(txInfo, own, exact, policy);
        PlutusData next = ChainLib.inlineDatum(entry);
        return RegistryLib.isEntry(next)
                && RegistryLib.entryGeneration(next).compareTo(RegistryLib.entryGeneration(datum).add(BigInteger.ONE)) == 0
                && ChainLib.signedBy(txInfo, RegistryLib.entryAuditor(datum))
                && ChainLib.signedBy(txInfo, RegistryLib.entryAuditor(next))
                && possessed(next, policy);
    }

    /**
     * Both possession proofs verify under this registry and the entry's auditor: {@code pkProof}
     * for {@code (pkU, pkV)} with type {@code 0x01} and {@code viewProof} for {@code (viewU, viewV)}
     * with type {@code 0x02}. With the encodings bound to the coordinates ({@code isEntry}), every
     * registered key is a valid subgroup key the auditor holds, and honest senders can admit it.
     */
    private static boolean possessed(PlutusData entry, byte[] policy) {
        byte[] auditor = RegistryLib.entryAuditor(entry);
        return possession(elgamalCtxPrefix, policy, auditor, RegistryLib.entryPkU(entry), RegistryLib.entryPkV(entry),
                        RegistryLib.entryPkProof(entry))
                && possession(viewCtxPrefix, policy, auditor, RegistryLib.entryViewU(entry), RegistryLib.entryViewV(entry),
                        RegistryLib.entryViewProof(entry));
    }

    /** One possession proof over {@code [ctx, G.u, G.v, u, v, u, v]} (ADR-0007 N7). */
    private static boolean possession(byte[] prefix, byte[] policy, byte[] auditor, BigInteger u, BigInteger v,
                                      byte[] proof) {
        byte[] digest = Builtins.blake2b_256(Builtins.appendByteString(prefix, Builtins.appendByteString(policy, auditor)));
        BigInteger ctx = Builtins.byteStringToInteger(true, Builtins.sliceByteString(0, 31, digest));
        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(ctx),
                Builtins.mkCons(Builtins.iData(genU),
                Builtins.mkCons(Builtins.iData(genV),
                Builtins.mkCons(Builtins.iData(u),
                Builtins.mkCons(Builtins.iData(v),
                Builtins.mkCons(Builtins.iData(u),
                Builtins.mkCons(Builtins.iData(v),
                        Builtins.mkNilData()))))))));
        return Groth16BLS12381Lib.verify(publicInputs,
                Builtins.sliceByteString(0, 48, proof),
                Builtins.sliceByteString(48, 96, proof),
                Builtins.sliceByteString(144, 48, proof),
                possAlpha, possBeta, possGamma, possDelta, possIc);
    }

    /**
     * The one output under the registry credential: it must be the only one, sit at the exact
     * address and hold lovelace plus exactly one registry token. Anything else fails the script.
     */
    private static TxOut onlyEntryOutput(TxInfo txInfo, Credential own, Address exact, byte[] policy) {
        if (ChainLib.countOutputs(txInfo.outputs(), own) != 1) Builtins.error();
        TxOut found = txInfo.outputs().get(0);
        for (TxOut output : txInfo.outputs()) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                found = output;
            } else {
                found = found;
            }
        }
        if (!Builtins.equalsData(found.address(), exact)
                || ChainLib.outerEntryCount(found.value()) != 2
                || ChainLib.policyEntryCount(found.value(), policy) != 1
                || ValuesLib.assetOf(found.value(), policy, registryToken).compareTo(BigInteger.ONE) != 0) {
            Builtins.error();
        }
        return found;
    }
}
