package com.bloxbean.cardano.zeroj.usecases.airdrop.onchain;

import org.julclang.core.PlutusData;
import org.julclang.core.types.JulcList;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.ScriptInfo;
import org.julclang.ledger.TxInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.Value;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.MintingValidator;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.lib.OutputLib;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;
import java.util.Optional;

/**
 * On-chain Sybil-resistant airdrop minting policy (ADR-0009 D3).
 *
 * <p>Mints exactly one "claim receipt" token per claim, named after the nullifier
 * {@code Poseidon(personhoodId, policyEpoch)}. The receipt is a public record that the nullifier
 * was used. The faucet refuses to pay a nullifier it has recorded or that already has a
 * receipt; the policy itself keeps no "minted once" state, so receipt uniqueness on-chain is
 * deferred (ADR-0009 Alternatives). A replay with the claimant's own funds can mint a second
 * receipt but takes no faucet payout, because the faucet's ADA is at the admin's key address.
 *
 * <p>Public inputs (6) are read from the claim output's inline datum:
 * {@code [pkU, pkV, epoch, nullifier, recipient, eligible]}. The policy requires:
 * <ol>
 *   <li>the mint map under this policy is exactly one entry, {@code I2OSP32(nullifier)} with
 *       quantity 1 (an extra entry of any quantity, including a burn, is refused);</li>
 *   <li>the receipt goes to the exact receipt address: this script's payment credential with no
 *       stake credential, so every receipt is at one address the faucet can check;</li>
 *   <li>{@code (pkU, pkV)} equal the parameterised issuer key;</li>
 *   <li>{@code epoch} equals the parameter {@code policyEpoch}, which must be non-zero and
 *       below the BLS12-381 scalar field order {@code r};</li>
 *   <li>{@code eligible == 1};</li>
 *   <li>an output whose payment credential is a key hash {@code h}, with {@code |h| = 28} and
 *       {@code integer(h) = recipient}, carrying at least {@code payout} lovelace (a script
 *       credential never qualifies, whatever its hash);</li>
 *   <li>the Groth16 BLS12-381 proof verifies under the parameterised verification key.</li>
 * </ol>
 */
@MintingValidator
public class FaucetMintingPolicy {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;
    @Param static BigInteger issuerPkU;
    @Param static BigInteger issuerPkV;
    @Param static BigInteger policyEpoch;
    @Param static BigInteger payout;

    record AirdropProof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(AirdropProof proof, ScriptContext ctx) {
        TxInfo txInfo = ctx.txInfo();

        // 1. The mint map under this policy is exactly one entry, of quantity 1 (any other
        //    entry, whatever its quantity, refuses the mint).
        ScriptInfo.MintingScript mintInfo = (ScriptInfo.MintingScript) ctx.scriptInfo();
        byte[] policyBytes = PlutusData.cast(mintInfo.policyId(), byte[].class);
        byte[] mintedName = onlyEntryName(txInfo.mint(), policyBytes);
        boolean exactlyOne = policyEntryCount(txInfo.mint(), policyBytes) == 1
                && ValuesLib.assetOf(txInfo.mint(), policyBytes, mintedName).compareTo(BigInteger.ONE) == 0;

        // 2. Read public inputs from the receipt output: the output holding the receipt at
        //    the exact receipt address (this script's payment credential, no stake credential).
        //    Datum = ListData [pkU, pkV, epoch, nullifier, recipient, eligible].
        Address receiptAddress = new Address(
                new Credential.ScriptCredential(PlutusData.cast(policyBytes, ScriptHash.class)), Optional.empty());
        TxOut claimOutput = receiptOutput(txInfo.outputs(), receiptAddress, policyBytes, mintedName);
        PlutusData datumData = OutputLib.getInlineDatum(claimOutput);
        PlutusData inputs = Builtins.unListData(datumData);
        PlutusData r1 = Builtins.tailList(inputs);
        PlutusData r2 = Builtins.tailList(r1);
        PlutusData r3 = Builtins.tailList(r2);
        PlutusData r4 = Builtins.tailList(r3);
        PlutusData r5 = Builtins.tailList(r4);
        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs));      // pkU
        BigInteger pub1 = Builtins.asInteger(Builtins.headList(r1));          // pkV
        BigInteger pub2 = Builtins.asInteger(Builtins.headList(r2));          // epoch
        BigInteger pub3 = Builtins.asInteger(Builtins.headList(r3));          // nullifier
        BigInteger pub4 = Builtins.asInteger(Builtins.headList(r4));          // recipient
        BigInteger pub5 = Builtins.asInteger(Builtins.headList(r5));          // eligible

        // 3. Bind the registered issuer required by verifyWithRegisteredKey, require
        //    eligibility, and bind the token name to the public nullifier.
        boolean registeredIssuer = isRegisteredIssuer(pub0, pub1);
        boolean registeredEpoch = isRegisteredEpoch(pub2);
        boolean isEligible = pub5.compareTo(BigInteger.ONE) == 0;
        boolean nameCorrect = Builtins.equalsByteString(mintedName, Builtins.integerToByteString(true, 32, pub3));

        // 4. The payout goes to the proved recipient's key credential.
        boolean recipientPaid = paysRecipient(txInfo, pub4);

        // 5. Groth16 BLS12-381 pairing check with 6 public inputs.
        PlutusData publicInputs = Groth16BLS12381Lib.publicInputs6(pub0, pub1, pub2, pub3, pub4, pub5);
        boolean proofValid = Groth16BLS12381Lib.verify(publicInputs,
                proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return registeredIssuer && registeredEpoch
                && exactlyOne && nameCorrect && isEligible && recipientPaid && proofValid;
    }

    static boolean isRegisteredIssuer(BigInteger publicKeyU, BigInteger publicKeyV) {
        return publicKeyU.equals(issuerPkU) && publicKeyV.equals(issuerPkV);
    }

    /** The only output at {@code receiptAddress} holding the receipt; fails if there is none. */
    static TxOut receiptOutput(JulcList<TxOut> outputs, Address receiptAddress, byte[] policy, byte[] name) {
        TxOut result = outputs.head();
        boolean found = false;
        for (TxOut out : outputs) {
            if (!found
                    && Builtins.equalsData(out.address(), receiptAddress)
                    && ValuesLib.assetOf(out.value(), policy, name).compareTo(BigInteger.ZERO) > 0) {
                result = out;
                found = true;
            }
        }
        if (!found) {
            Builtins.error();
        }
        return result;
    }

    /** Number of entries (token names, any quantity) under {@code policy} in {@code value}. */
    static int policyEntryCount(Value value, byte[] policy) {
        PlutusData target = Builtins.bData(policy);
        int count = 0;
        PlutusData current = Builtins.unMapData(value);
        while (!Builtins.nullList(current)) {
            var outerPair = Builtins.headList(current);
            if (Builtins.equalsData(Builtins.fstPair(outerPair), target)) {
                count = innerEntryCount((PlutusData.MapData) Builtins.sndPair(outerPair));
                current = Builtins.mkNilPairData();
            } else {
                current = Builtins.tailList(current);
            }
        }
        return count;
    }

    /** The first token name under {@code policy}, whatever its quantity; empty if none. */
    static byte[] onlyEntryName(Value value, byte[] policy) {
        PlutusData target = Builtins.bData(policy);
        byte[] name = Builtins.emptyByteString();
        PlutusData current = Builtins.unMapData(value);
        while (!Builtins.nullList(current)) {
            var outerPair = Builtins.headList(current);
            if (Builtins.equalsData(Builtins.fstPair(outerPair), target)) {
                name = firstName((PlutusData.MapData) Builtins.sndPair(outerPair));
                current = Builtins.mkNilPairData();
            } else {
                current = Builtins.tailList(current);
            }
        }
        return name;
    }

    static int innerEntryCount(PlutusData.MapData innerPairs) {
        int count = 0;
        PlutusData current = Builtins.unMapData(innerPairs);
        while (!Builtins.nullList(current)) {
            count = count + 1;
            current = Builtins.tailList(current);
        }
        return count;
    }

    static byte[] firstName(PlutusData.MapData innerPairs) {
        PlutusData pairs = Builtins.unMapData(innerPairs);
        if (Builtins.nullList(pairs)) {
            return Builtins.emptyByteString();
        }
        return Builtins.unBData(Builtins.fstPair(Builtins.headList(pairs)));
    }

    /** {@code policyEpoch} is a non-zero field element, and the proof's epoch is it. */
    static boolean isRegisteredEpoch(BigInteger epoch) {
        return policyEpoch.compareTo(BigInteger.ZERO) > 0
                && policyEpoch.compareTo(fr()) < 0
                && epoch.equals(policyEpoch);
    }

    /** Some output pays at least {@code payout} lovelace to the key hash {@code recipient}. */
    static boolean paysRecipient(TxInfo txInfo, BigInteger recipient) {
        boolean paid = false;
        if (payout.compareTo(BigInteger.ZERO) > 0) {
            for (TxOut output : txInfo.outputs()) {
                paid = paid
                        || (isKeyHashOf(output.address().credential(), recipient)
                            && ValuesLib.lovelaceOf(output.value()).compareTo(payout) >= 0);
            }
        }
        return paid;
    }

    /** {@code cred} is a key credential {@code h} with {@code |h| = 28} and {@code integer(h) = recipient}. */
    static boolean isKeyHashOf(Credential cred, BigInteger recipient) {
        if (cred instanceof Credential.PubKeyCredential pk) {
            byte[] h = Builtins.toByteString(pk.hash());
            return Builtins.lengthOfByteString(h) == 28
                    && Builtins.byteStringToInteger(true, h).equals(recipient);
        }
        return false;
    }

    /** The BLS12-381 scalar field order r. */
    static BigInteger fr() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        return BigInteger.valueOf(52435L).multiply(base)
                .add(BigInteger.valueOf(875175126190479447L)).multiply(base)
                .add(BigInteger.valueOf(740508185965837690L)).multiply(base)
                .add(BigInteger.valueOf(552500527637822603L)).multiply(base)
                .add(BigInteger.valueOf(658699938581184513L));
    }
}
