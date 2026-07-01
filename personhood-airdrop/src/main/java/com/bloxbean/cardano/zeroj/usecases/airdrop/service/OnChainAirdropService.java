package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.airdrop.onchain.FaucetMintingPolicy;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * On-chain airdrop service. Submits the Groth16 proof to the
 * {@link FaucetMintingPolicy} which mints a single NFT named after the
 * nullifier — chain-state evidence of "this credential has claimed this
 * epoch".
 *
 * <p>Off-chain double-claim defense: this service maintains a set of
 * nullifiers it has already submitted, refusing duplicates. On chain the
 * minting policy gates on Groth16 proof + eligible flag; the asset-name
 * collision prevents a second claim with the same nullifier from being
 * built (the user-facing tx builder would reject minting the same NFT
 * twice in the same UTXO set).
 */
@Service
public class OnChainAirdropService {

    private static final Logger log = LoggerFactory.getLogger(OnChainAirdropService.class);

    private final BackendService backendService;
    private final Account adminAccount;
    private final AirdropProofService proofService;

    private PlutusScript mintingScript;
    private String policyHex;
    private boolean initialized;
    private final Set<String> claimedNullifiersHex = new HashSet<>();

    public OnChainAirdropService(BackendService backendService, Account adminAccount,
                                  AirdropProofService proofService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.proofService = proofService;
    }

    @PostConstruct
    public synchronized void initialize() throws Exception {
        if (initialized) return;
        log.info("Compiling faucet minting policy (with on-chain Groth16 verification)...");
        var vk = ProofCompressor.compressVk(proofService.getSetupResult());

        mintingScript = JulcScriptLoader.load(FaucetMintingPolicy.class,
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()));

        policyHex = HexUtil.encodeHexString(mintingScript.getScriptHash());
        initialized = true;
        log.info("Faucet minting policy: {}", policyHex);
    }

    /**
     * Submits an airdrop claim. Mints one NFT (asset name = nullifier) under
     * the faucet policy, attaches the public inputs in the inline datum, and
     * pays the airdrop amount to {@code recipientAddress}.
     *
     * @return Cardano tx hash
     */
    public String submitClaim(Groth16ProofBLS381 proof,
                              BigInteger pkU, BigInteger pkV,
                              BigInteger epoch, BigInteger nullifier,
                              BigInteger recipient, String recipientAddressBech32,
                              long lovelaceAmount) throws Exception {
        ensureInitialized();

        String nullifierHex = nullifier.toString(16);
        if (claimedNullifiersHex.contains(nullifierHex)) {
            throw new IllegalStateException("Nullifier already claimed in this epoch: " + nullifierHex);
        }

        log.info("Submitting airdrop claim: nullifier={}", nullifierHex.substring(0, 16) + "...");

        var compressed = ProofCompressor.compressProof(proof);
        var redeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressed.piA()),
                        new BytesPlutusData(compressed.piB()),
                        new BytesPlutusData(compressed.piC())))
                .build();

        // Datum: 6 public inputs [pkU, pkV, epoch, nullifier, recipient, eligible].
        var datum = ListPlutusData.of(
                BigIntPlutusData.of(pkU),
                BigIntPlutusData.of(pkV),
                BigIntPlutusData.of(epoch),
                BigIntPlutusData.of(nullifier),
                BigIntPlutusData.of(recipient),
                BigIntPlutusData.of(BigInteger.ONE)); // eligible

        // The minted NFT's asset name = nullifier bytes.
        // The claim output carries the NFT + the public-inputs datum.
        byte[] nullifierBytes = padOrTrunc(nullifier.toByteArray(), 32);
        String tokenNameHex = HexUtil.encodeHexString(nullifierBytes);
        var nftAsset = new Asset("0x" + tokenNameHex, BigInteger.ONE);

        // First output: NFT custodied at the script address (carries datum).
        String policyHolderAddr = AddressProvider
                .getEntAddress(mintingScript, Networks.testnet()).toBech32();

        // Second output: the airdrop ADA → recipient.
        var mintTx = new ScriptTx()
                .mintAsset(mintingScript, List.of(nftAsset), redeemer)
                .payToContract(policyHolderAddr,
                        List.of(Amount.ada(2), new Amount(policyHex + tokenNameHex, BigInteger.ONE)),
                        datum)
                .payToAddress(recipientAddressBech32, Amount.lovelace(BigInteger.valueOf(lovelaceAmount)));

        var result = new QuickTxBuilder(backendService)
                .compose(mintTx)
                .withTxEvaluator(LocalJulcEvaluator.create(backendService))
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Claim mint failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Airdrop claim minted: nullifier={}, tx={}",
                nullifierHex.substring(0, 16) + "...", txHash);
        claimedNullifiersHex.add(nullifierHex);
        waitForTx(txHash);
        return txHash;
    }

    public boolean alreadyClaimed(BigInteger nullifier) {
        return claimedNullifiersHex.contains(nullifier.toString(16));
    }

    public int totalClaims() {
        return claimedNullifiersHex.size();
    }

    public String getPolicyId() {
        return policyHex;
    }

    private void ensureInitialized() throws Exception {
        if (!initialized) initialize();
    }

    private static byte[] padOrTrunc(byte[] in, int width) {
        // Truncate (keep low bytes) or zero-pad to width. Cardano asset names
        // are limited to 32 bytes; nullifiers are field elements ≤ 32 bytes
        // so this is essentially a normalize-length op.
        if (in.length == width) return in;
        byte[] out = new byte[width];
        if (in.length > width) {
            System.arraycopy(in, in.length - width, out, 0, width);
        } else {
            System.arraycopy(in, 0, out, width - in.length, in.length);
        }
        return out;
    }

    private static ListPlutusData vkIcData(List<byte[]> ic) {
        PlutusData[] values = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) {
            values[i] = new BytesPlutusData(ic.get(i));
        }
        return ListPlutusData.of(values);
    }

    private void waitForTx(String txHash) {
        try {
            for (int i = 0; i < 60; i++) {
                Thread.sleep(1000);
                var r = backendService.getTransactionService().getTransaction(txHash);
                if (r != null && r.isSuccessful() && r.getValue() != null) return;
            }
        } catch (Exception ignored) {}
    }
}
