package com.bloxbean.cardano.zeroj.usecases.nft.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.crypto.KeyGenUtil;
import com.bloxbean.cardano.client.crypto.Keys;
import com.bloxbean.cardano.client.crypto.SecretKey;
import com.bloxbean.cardano.client.crypto.VerificationKey;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.bloxbean.cardano.client.transaction.spec.Asset;
import com.bloxbean.cardano.client.transaction.spec.script.ScriptPubkey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class MintService {
    private static final Logger log = LoggerFactory.getLogger(MintService.class);
    private final BackendService backendService;
    private final Account adminAccount;
    private String policyId;
    private SecretKey policySecretKey;
    private ScriptPubkey policyScript;
    private final List<String> mintedTokenNames = Collections.synchronizedList(new ArrayList<>());

    public MintService(BackendService backendService, Account adminAccount) {
        this.backendService = backendService;
        this.adminAccount = adminAccount;
    }

    public MintResult mintToAdmin(String collectionName, int count) throws Exception {
        initPolicy();
        log.info("Minting {} NFTs with policy: {}", count, policyId);

        QuickTxBuilder quickTx = new QuickTxBuilder(backendService);
        Tx tx = new Tx();
        tx.from(adminAccount.baseAddress());

        List<String> tokenNames = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String name = collectionName + "_" + (i + 1);
            tokenNames.add(name);
            // Use NativeScript overload instead of Policy overload (avoids Java 25 NPE)
            tx.mintAssets(policyScript, new Asset(name, BigInteger.ONE), adminAccount.baseAddress());
        }

        var result = quickTx.compose(tx)
                .withSigner(SignerProviders.signerFrom(adminAccount))
                .withSigner(SignerProviders.signerFrom(policySecretKey))
                .complete();

        if (!result.isSuccessful()) {
            throw new RuntimeException("Mint failed: " + result.getResponse());
        }

        String txHash = result.getValue();
        log.info("Mint tx: {}", txHash);
        waitForTx(txHash);
        mintedTokenNames.addAll(tokenNames);
        return new MintResult(policyId, tokenNames, txHash);
    }

    private void initPolicy() throws Exception {
        if (policyScript != null) return;
        Keys keys = KeyGenUtil.generateKey();
        VerificationKey vk = keys.getVkey();
        policySecretKey = keys.getSkey();
        policyScript = ScriptPubkey.create(vk);
        policyId = policyScript.getPolicyId();
    }

    private void waitForTx(String txHash) throws Exception {
        for (int i = 0; i < 30; i++) {
            Thread.sleep(2000);
            try {
                var r = backendService.getTransactionService().getTransaction(txHash);
                if (r.isSuccessful() && r.getValue() != null) {
                    log.info("Confirmed: {}", txHash);
                    return;
                }
            } catch (Exception ignored) {}
        }
        log.warn("Tx confirmation timeout: {}", txHash);
    }

    public String getPolicyId() { return policyId != null ? policyId : "not minted"; }
    public List<String> getMintedTokens() { return Collections.unmodifiableList(mintedTokenNames); }
    public String getAdminAddress() { return adminAccount.baseAddress(); }

    public record MintResult(String policyId, List<String> tokenNames, String mintTxHash) {}
}
