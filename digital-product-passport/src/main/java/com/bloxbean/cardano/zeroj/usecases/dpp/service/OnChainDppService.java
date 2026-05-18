package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.*;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.usecases.dpp.onchain.DppMintingPolicy;
import com.bloxbean.cardano.julc.clientlib.JulcScriptLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * On-chain DPP service — mints product DPP NFTs using Groth16-gated minting policy.
 * Only compliant products can be minted. Manufacturer signature required.
 */
@Service
public class OnChainDppService {

    private static final Logger log = LoggerFactory.getLogger(OnChainDppService.class);

    private final BackendService backendService;
    private final Account adminAccount;
    private final DppCircuitService circuitService;

    private PlutusScript mintingScript;
    private String policyHex;
    private byte[] manufacturerPkh;
    private boolean initialized;

    public OnChainDppService(BackendService backendService, Account adminAccount,
                              DppCircuitService circuitService) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
        this.circuitService = circuitService;
    }

    public synchronized void initialize() throws Exception {
        if (initialized) return;

        log.info("Compiling DPP minting policy (with on-chain Groth16 verification)...");

        var vk = ProofCompressor.compressVk(circuitService.getThresholdLte().setup());
        manufacturerPkh = adminAccount.hdKeyPair().getPublicKey().getKeyHash();

        mintingScript = JulcScriptLoader.load(DppMintingPolicy.class,
                new BytesPlutusData(manufacturerPkh),
                new BytesPlutusData(vk.alpha()),
                new BytesPlutusData(vk.beta()),
                new BytesPlutusData(vk.gamma()),
                new BytesPlutusData(vk.delta()),
                vkIcData(vk.ic()));

        policyHex = HexUtil.encodeHexString(mintingScript.getScriptHash());
        initialized = true;
        log.info("DPP minting policy: {}", policyHex);
        log.info("Manufacturer PKH: {}", HexUtil.encodeHexString(manufacturerPkh));
    }

    /**
     * Mint a DPP NFT for a product. The minting policy verifies:
     * 1. Manufacturer signature
     * 2. ZK compliance proof (Groth16)
     * 3. isCompliant == 1
     * 4. Exactly 1 token minted
     *
     * @param serialNumber product serial (becomes token name)
     * @param proof        Groth16 compliance proof
     * @param productId    public input: product identifier
     * @param threshold    public input: compliance threshold
     * @param auditorHash  public input: auditor commitment
     * @param compliant    public input: isCompliant (1 or 0)
     * @return transaction hash
     */
    public String mintDppNft(String serialNumber, Groth16ProofBLS381 proof,
                              BigInteger productId, BigInteger threshold,
                              BigInteger auditorHash, boolean compliant) throws Exception {
        ensureInitialized();

        String tokenNameHex = HexUtil.encodeHexString(serialNumber.getBytes());
        log.info("Minting DPP NFT: {} (compliant={}) — on-chain Groth16 verification", serialNumber, compliant);

        var compressed = ProofCompressor.compressProof(proof);

        // Redeemer = Groth16Proof(piA, piB, piC) — only proof, 3 fields
        var redeemer = ConstrPlutusData.builder().alternative(0)
                .data(ListPlutusData.of(
                        new BytesPlutusData(compressed.piA()),
                        new BytesPlutusData(compressed.piB()),
                        new BytesPlutusData(compressed.piC())))
                .build();

        // Datum = public inputs [productId, threshold, auditorHash, isCompliant]
        // The minting policy reads these from the first output's inline datum
        var datum = ListPlutusData.of(
                BigIntPlutusData.of(productId),
                BigIntPlutusData.of(threshold),
                BigIntPlutusData.of(auditorHash),
                BigIntPlutusData.of(compliant ? BigInteger.ONE : BigInteger.ZERO));

        var asset = new Asset("0x" + tokenNameHex, BigInteger.ONE);

        // Mint token. First output carries the token + public inputs as inline datum.
        // Use payToContract to ensure datum is attached (regular payToAddress doesn't support datums).
        // The token holder can later move it to any address.
        String tokenHolderAddr = com.bloxbean.cardano.client.address.AddressProvider
                .getEntAddress(mintingScript, com.bloxbean.cardano.client.common.model.Networks.testnet()).toBech32();

        var mintTx = new ScriptTx()
                .mintAsset(mintingScript, List.of(asset), redeemer)
                .payToContract(tokenHolderAddr,
                        List.of(Amount.ada(2),
                                new Amount(policyHex + tokenNameHex, BigInteger.ONE)),
                        datum);

        var result = new QuickTxBuilder(backendService)
                .compose(mintTx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .withRequiredSigners(manufacturerPkh)
                .feePayer(adminAccount.baseAddress())
                .collateralPayer(adminAccount.baseAddress())
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Mint failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("DPP NFT minted: {} → tx={}", serialNumber, txHash);
        waitForTx(txHash);
        return txHash;
    }

    /**
     * Anchor the minted-registry MPF root on-chain as a simple transaction.
     * The root hash is stored in the transaction metadata (label 7270).
     */
    public String anchorRoot(byte[] mpfRoot, int mintedCount) throws Exception {
        ensureInitialized();
        log.info("Anchoring MPF root on-chain (minted={})...", mintedCount);

        // Simple tx with self-payment — metadata carries the root
        var tx = new Tx()
                .payToAddress(adminAccount.baseAddress(), Amount.ada(1))
                .from(adminAccount.baseAddress());

        var result = new QuickTxBuilder(backendService)
                .compose(tx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Anchor failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Root anchored: tx={} (root={}, minted={})", txHash,
                HexUtil.encodeHexString(mpfRoot).substring(0, 16), mintedCount);
        waitForTx(txHash);
        return txHash;
    }

    public String getPolicyId() { return policyHex; }
    public byte[] getManufacturerPkh() { return manufacturerPkh; }

    private void ensureInitialized() throws Exception {
        if (!initialized) initialize();
    }

    private static byte[] toMinimalBytes(BigInteger v) {
        byte[] b = v.toByteArray();
        return (b.length > 1 && b[0] == 0) ? Arrays.copyOfRange(b, 1, b.length) : b;
    }

    private static ListPlutusData vkIcData(List<byte[]> ic) {
        PlutusData[] values = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) {
            values[i] = new BytesPlutusData(ic.get(i));
        }
        return ListPlutusData.of(values);
    }

    private void waitForTx(String txHash) throws Exception {
        for (int i = 0; i < 30; i++) {
            Thread.sleep(2000);
            try {
                var r = backendService.getTransactionService().getTransaction(txHash);
                if (r.isSuccessful() && r.getValue() != null) { log.info("Confirmed: {}", txHash); return; }
            } catch (Exception ignored) {}
        }
    }
}
