package com.bloxbean.cardano.zeroj.usecases.pedersen.notes.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.PubKeyHash;
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

import java.math.BigInteger;
import java.util.Optional;

/**
 * A confidential note ledger (ADR-0007 N2–N4; ZeroJ ADR-0055 M3): the points demo with trusted
 * issuance, or the payroll demo with proof-enforced issuance. One script is both the note-token
 * policy and the note address.
 *
 * <p>A <b>note</b> is an output at the ledger's exact enterprise address holding exactly lovelace
 * and one {@code noteToken}, with inline datum {@code Note(owner, u, v, generation, audit,
 * deliveries)}: the owner's key hash; the affine {@code pedersen-jubjub-v1} commitment; the
 * registry generation it was created under; two {@code elgamal-jubjub-v1} limb ciphertexts of the
 * amount to the auditor (8 coordinates); and one {@code confidential-note-jubjub-v1} delivery each
 * for the owner and the auditor.
 *
 * <p><b>Address policy.</b> In every ledger transaction, every output under the ledger's payment
 * credential must be a note at the exact address (no stake credential) of the current registry
 * generation. Inputs are counted by payment credential, so one note is spent per transaction.
 *
 * <ul>
 *   <li><b>Issue</b> (trusted mode): the issuer signs and mints {@code n ≥ 1} tokens into exactly
 *       {@code n} notes; no note is spent. The issuer is trusted for supply and for the issued
 *       notes' audit data (ADR-0055 Q9 (a)).</li>
 *   <li><b>ProvedIssue</b> (proved mode): as Issue with {@code n ∈ {1, 2}}, plus a proof that every
 *       issued note's limbs encrypt its committed amount to the registry key, and distinct
 *       handles (Q9 (b)).</li>
 *   <li><b>Transfer</b> (spend + Split mint): the owner splits one note into two, proving
 *       {@code in = out1 + out2} and both new notes' audit limbs (D3a).</li>
 *   <li><b>Redeem</b> (spend + Receipt mint): the owner pays a public {@code price}, keeps a hidden
 *       change note with audit limbs, and mints a one-time receipt to the issuer.</li>
 * </ul>
 *
 * <p>Verification keys are pinned by hash ({@link VkLib}); each proof's redeemer carries its key.
 *
 * <p>Every public input comes from the ledger: commitments and audit coordinates from datums,
 * {@code PK_a} from exactly one registry reference input, the price from the redeemer (bound by
 * the proof and recorded in the receipt).
 */
@MultiValidator
public class NoteLedger {

    @Param static byte[] issuerPkh;
    @Param static byte[] noteToken;
    @Param static BigInteger provedIssuance;   // 0: trusted Issue only; 1: ProvedIssue only
    @Param static byte[] registryPolicy;
    @Param static byte[] registryToken;
    @Param static byte[] transferVkHash;   // blake2b_256(serialiseData(vk)), VkLib
    @Param static byte[] redeemVkHash;
    @Param static byte[] issue1VkHash;
    @Param static byte[] issue2VkHash;

    record Note(byte[] owner, BigInteger u, BigInteger v, BigInteger generation, PlutusData audit,
                PlutusData deliveries) {}

    sealed interface NoteMint permits Issue, Split, Receipt, ProvedIssue {}
    record Issue(BigInteger count) implements NoteMint {}
    record Split(BigInteger count) implements NoteMint {}
    record Receipt(BigInteger count) implements NoteMint {}
    record ProvedIssue(byte[] piA, byte[] piB, byte[] piC) implements NoteMint {}

    sealed interface NoteSpend permits Transfer, Redeem {}
    record Transfer(byte[] piA, byte[] piB, byte[] piC) implements NoteSpend {}
    record Redeem(BigInteger price, byte[] piA, byte[] piB, byte[] piC) implements NoteSpend {}

    // ------------------------------------------------------------------
    //  Minting
    // ------------------------------------------------------------------

    @Entrypoint(purpose = Purpose.MINT)
    public static boolean mint(NoteMint redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policy = PlutusData.cast(mintInfo.policyId(), byte[].class);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        Address exact = new Address(own, Optional.empty());
        int ownInputs = ChainLib.countInputs(txInfo.inputs(), own);
        // Every action mints exactly one token name under this policy.
        if (ChainLib.policyEntryCount(txInfo.mint(), policy) != 1) return false;

        return switch (redeemer) {
            case Issue issue -> provedIssuance.equals(BigInteger.ZERO)
                    && issued(txInfo, own, exact, policy, ownInputs, BigInteger.valueOf(1000000));
            case ProvedIssue proved -> provedIssuance.equals(BigInteger.ONE)
                    && issued(txInfo, own, exact, policy, ownInputs, BigInteger.TWO)
                    && provedIssue(proved, txInfo, own);
            // The spent note's spending purpose proves the transfer; here only the count.
            case Split split -> ownInputs == 1
                    && ValuesLib.assetOf(txInfo.mint(), policy, noteToken).compareTo(BigInteger.ONE) == 0;
            // The spent note's spending purpose proves the redemption and pins the receipt name.
            case Receipt receipt -> {
                byte[] name = ValuesLib.findTokenName(txInfo.mint(), policy, BigInteger.ONE);
                yield ownInputs == 1 && Builtins.lengthOfByteString(name) == 32;
            }
        };
    }

    /**
     * Both issuance modes: the issuer signs, no ledger input is spent, the mint is {@code n} note
     * tokens with {@code 1 ≤ n ≤ maxNotes}, and exactly {@code n} outputs under the ledger
     * credential, each a note of the current registry generation.
     */
    private static boolean issued(TxInfo txInfo, Credential own, Address exact, byte[] policy, int ownInputs,
                                  BigInteger maxNotes) {
        BigInteger n = ValuesLib.assetOf(txInfo.mint(), policy, noteToken);
        PlutusData entry = RegistryLib.currentEntry(txInfo, registryPolicy, registryToken);
        return ChainLib.signedBy(txInfo, issuerPkh) && ownInputs == 0
                && n.compareTo(BigInteger.ONE) >= 0 && n.compareTo(maxNotes) <= 0
                && BigInteger.valueOf(ChainLib.countOutputs(txInfo.outputs(), own)).compareTo(n) == 0
                && NoteLib.allNoteOutputs(txInfo.outputs(), own, exact, policy, noteToken,
                        RegistryLib.entryGeneration(entry));
    }

    /**
     * The issuance proof over {@code u_1 … u_n, v_1 … v_n, PK, audit_1, …, audit_n} (n = 1 or 2,
     * the number of note outputs), with {@code PK} from the registry and every handle distinct.
     */
    private static boolean provedIssue(ProvedIssue p, TxInfo txInfo, Credential own) {
        PlutusData entry = RegistryLib.currentEntry(txInfo, registryPolicy, registryToken);
        int notes = 0;
        PlutusData first = Builtins.iData(BigInteger.ZERO);
        PlutusData second = Builtins.iData(BigInteger.ZERO);
        for (TxOut output : txInfo.outputs()) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                PlutusData d = ChainLib.inlineDatum(output);
                if (notes == 0) {
                    first = d;
                } else {
                    first = first;
                }
                if (notes == 1) {
                    second = d;
                } else {
                    second = second;
                }
                notes = notes + 1;
            } else {
                notes = notes;
            }
        }
        PlutusData a1 = NoteLib.noteAudit(first);
        if (!NoteLib.ownHandlesDistinct(a1)) return false;
        PlutusData pk = Builtins.mkCons(Builtins.iData(RegistryLib.entryPkU(entry)),
                Builtins.mkCons(Builtins.iData(RegistryLib.entryPkV(entry)), Builtins.mkNilData()));
        if (notes == 1) {
            PlutusData inputs = Builtins.listData(
                    Builtins.mkCons(Builtins.iData(NoteLib.noteU(first)),
                    Builtins.mkCons(Builtins.iData(NoteLib.noteV(first)),
                            appendList(pk, NoteLib.prependAudit(a1, Builtins.mkNilData())))));
            return VkLib.verify(inputs, p.piA(), p.piB(), p.piC(), VkLib.referenceVk(txInfo, own, 2), issue1VkHash);
        }
        PlutusData a2 = NoteLib.noteAudit(second);
        if (!NoteLib.ownHandlesDistinct(a2) || !NoteLib.handlesDisjoint(a1, a2)) return false;
        PlutusData inputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(NoteLib.noteU(first)),
                Builtins.mkCons(Builtins.iData(NoteLib.noteU(second)),
                Builtins.mkCons(Builtins.iData(NoteLib.noteV(first)),
                Builtins.mkCons(Builtins.iData(NoteLib.noteV(second)),
                        appendList(pk, NoteLib.prependAudit(a1, NoteLib.prependAudit(a2, Builtins.mkNilData()))))))));
        return VkLib.verify(inputs, p.piA(), p.piB(), p.piC(), VkLib.referenceVk(txInfo, own, 3), issue2VkHash);
    }

    /** The two-element list {@code pair} followed by {@code rest}. */
    private static PlutusData appendList(PlutusData pair, PlutusData rest) {
        return Builtins.mkCons(Builtins.headList(pair), Builtins.mkCons(Builtins.headList(Builtins.tailList(pair)), rest));
    }

    // ------------------------------------------------------------------
    //  Spending a note
    // ------------------------------------------------------------------

    @Entrypoint(purpose = Purpose.SPEND)
    public static boolean spend(Note datum, NoteSpend redeemer, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();
        byte[] policy = ContextsLib.ownHash(ctx);
        Credential own = new Credential.ScriptCredential(PlutusData.cast(policy, ScriptHash.class));
        Address exact = new Address(own, Optional.empty());
        if (Builtins.lengthOfByteString(datum.owner()) != 28
                || !ChainLib.canonicalField(datum.u()) || !ChainLib.canonicalField(datum.v())
                || !ChainLib.signedBy(txInfo, datum.owner())) {
            return false;
        }
        var ownInputOptional = ContextsLib.findOwnInput(ctx);
        if (ownInputOptional.isEmpty()) return false;
        TxInInfo ownInput = ownInputOptional.get();
        if (ChainLib.countInputs(txInfo.inputs(), own) != 1
                || ValuesLib.assetOf(ownInput.resolved().value(), policy, noteToken).compareTo(BigInteger.ONE) != 0
                || ChainLib.policyEntryCount(txInfo.mint(), policy) != 1) {
            return false;
        }
        PlutusData entry = RegistryLib.currentEntry(txInfo, registryPolicy, registryToken);
        if (!NoteLib.allNoteOutputs(txInfo.outputs(), own, exact, policy, noteToken, RegistryLib.entryGeneration(entry))) {
            return false;
        }
        return switch (redeemer) {
            case Transfer transfer -> transfer(transfer, datum, txInfo, own, policy, entry);
            case Redeem redeem -> redeem(redeem, datum, ownInput, txInfo, own, policy, entry);
        };
    }

    private static boolean transfer(Transfer t, Note in, TxInfo txInfo, Credential own, byte[] policy,
                                    PlutusData entry) {
        if (ValuesLib.assetOf(txInfo.mint(), policy, noteToken).compareTo(BigInteger.ONE) != 0) return false;
        int notes = 0;
        PlutusData o1 = Builtins.iData(BigInteger.ZERO);
        PlutusData o2 = Builtins.iData(BigInteger.ZERO);
        for (TxOut output : txInfo.outputs()) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                PlutusData d = ChainLib.inlineDatum(output);
                if (notes == 0) {
                    o1 = d;
                } else {
                    o1 = o1;
                }
                if (notes == 1) {
                    o2 = d;
                } else {
                    o2 = o2;
                }
                notes = notes + 1;
            } else {
                notes = notes;
            }
        }
        if (notes != 2) return false;
        PlutusData a1 = NoteLib.noteAudit(o1);
        PlutusData a2 = NoteLib.noteAudit(o2);
        if (!NoteLib.ownHandlesDistinct(a1) || !NoteLib.ownHandlesDistinct(a2) || !NoteLib.handlesDisjoint(a1, a2)) {
            return false;
        }
        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(in.u()),
                Builtins.mkCons(Builtins.iData(in.v()),
                Builtins.mkCons(Builtins.iData(NoteLib.noteU(o1)),
                Builtins.mkCons(Builtins.iData(NoteLib.noteV(o1)),
                Builtins.mkCons(Builtins.iData(NoteLib.noteU(o2)),
                Builtins.mkCons(Builtins.iData(NoteLib.noteV(o2)),
                Builtins.mkCons(Builtins.iData(RegistryLib.entryPkU(entry)),
                Builtins.mkCons(Builtins.iData(RegistryLib.entryPkV(entry)),
                        NoteLib.prependAudit(a1, NoteLib.prependAudit(a2, Builtins.mkNilData())))))))))));
        return VkLib.verify(publicInputs, t.piA(), t.piB(), t.piC(), VkLib.referenceVk(txInfo, own, 0), transferVkHash);
    }

    private static boolean redeem(Redeem r, Note in, TxInInfo ownInput, TxInfo txInfo, Credential own,
                                  byte[] policy, PlutusData entry) {
        BigInteger price = r.price();
        if (price.compareTo(BigInteger.ONE) < 0 || price.compareTo(BigInteger.valueOf(4294967296L)) >= 0) {
            return false;
        }
        // The receipt token is named after the redeemed note's output reference: one per note.
        byte[] receiptName = ValuesLib.uniqueTokenName(ownInput.outRef());
        if (ValuesLib.assetOf(txInfo.mint(), policy, receiptName).compareTo(BigInteger.ONE) != 0) return false;

        Credential issuer = new Credential.PubKeyCredential(PlutusData.cast(issuerPkh, PubKeyHash.class));
        PlutusData expectedReceipt = Builtins.constrData(0,
                Builtins.mkCons(Builtins.bData(in.owner()),
                Builtins.mkCons(Builtins.iData(price),
                        Builtins.mkNilData())));
        int notes = 0;
        boolean receipted = false;
        PlutusData change = Builtins.iData(BigInteger.ZERO);
        for (TxOut output : txInfo.outputs()) {
            if (Builtins.equalsData(output.address().credential(), own)) {
                PlutusData d = ChainLib.inlineDatum(output);
                if (notes == 0) {
                    change = d;
                } else {
                    change = change;
                }
                notes = notes + 1;
            } else {
                notes = notes;
            }
            boolean receipt = Builtins.equalsData(output.address().credential(), issuer)
                    && ValuesLib.assetOf(output.value(), policy, receiptName).compareTo(BigInteger.ONE) == 0
                    && Builtins.equalsData(ChainLib.inlineDatum(output), expectedReceipt);
            receipted = receipted || receipt;
        }
        if (notes != 1 || !receipted) return false;
        PlutusData audit = NoteLib.noteAudit(change);
        if (!NoteLib.ownHandlesDistinct(audit)) return false;
        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(in.u()),
                Builtins.mkCons(Builtins.iData(in.v()),
                Builtins.mkCons(Builtins.iData(NoteLib.noteU(change)),
                Builtins.mkCons(Builtins.iData(NoteLib.noteV(change)),
                Builtins.mkCons(Builtins.iData(price),
                Builtins.mkCons(Builtins.iData(RegistryLib.entryPkU(entry)),
                Builtins.mkCons(Builtins.iData(RegistryLib.entryPkV(entry)),
                        NoteLib.prependAudit(audit, Builtins.mkNilData())))))))));
        return VkLib.verify(publicInputs, r.piA(), r.piB(), r.piC(), VkLib.referenceVk(txInfo, own, 1), redeemVkHash);
    }
}
