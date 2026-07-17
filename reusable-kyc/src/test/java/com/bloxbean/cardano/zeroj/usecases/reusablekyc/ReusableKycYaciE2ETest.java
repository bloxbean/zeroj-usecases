package com.bloxbean.cardano.zeroj.usecases.reusablekyc;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.bbs.internal.BbsCodec;
import com.bloxbean.cardano.zeroj.bbs.internal.CfrgBbsCore;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Providers;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycCredential;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.HolderService;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.IssuerService;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.OnChainKycClaimService;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.VerifierService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Live end-to-end claim against a local <b>Yaci DevKit</b>: issue a KYC credential, present only
 * {@code country}+{@code kycLevel}, lock a voucher at the claim validator, and spend it with the BBS
 * presentation — the ledger verifies the BBS proof natively and enforces the payout.
 *
 * <p>Needs a running DevKit (API {@code http://localhost:8080/api/v1/}, faucet
 * {@code http://localhost:10000}). Gated: run with
 * {@code ./gradlew test --tests '*ReusableKycYaciE2ETest' -Dkyc.e2e=true}.</p>
 */
class ReusableKycYaciE2ETest {

    private static final String DEVKIT_API = "http://localhost:8080/api/v1/";
    private static final String DEVKIT_FAUCET = "http://localhost:10000";
    private static final BbsCiphersuite SUITE = BbsCiphersuite.BLS12381_SHA256;
    private static final Bls12381Provider BLS = Bls12381Providers.pureJava();

    private static final String FUNDER_MNEMONIC =
            "test test test test test test test test test test test test test test test test test test test test test test test sauce";

    private static byte[] u(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static byte[] a(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] g1c(com.bloxbean.cardano.zeroj.bls12381.ec.G1Point p) { return Bls12381Codecs.g1ToCompressed(p); }

    @Test
    @EnabledIfSystemProperty(named = "kyc.e2e", matches = "true")
    void issue_present_and_claim_onchain() throws Exception {
        // ---- 1. Issue + present (reveal country + kycLevel only) ----
        byte[] seed = new byte[32]; Arrays.fill(seed, (byte) 11);
        IssuerService issuer = new IssuerService(seed, "kyc-provider-1");
        var credential = issuer.issue(new KycCredential(
                "Alice Example", "1990-05-01", "USA", "verified", "9f86d081884c7d659a2feaa0c55ad015a"));
        // Off-chain sanity: a presentation bound to a challenge the verifier issued.
        var verifier = new VerifierService();
        var holder = new HolderService(credential);
        assertTrue(verifier.verifyFresh(issuer.publicKey(),
                        holder.present(List.of("country", "kycLevel"), verifier.newChallenge())),
                "off-chain sanity");

        // ---- 2. Issuer verification material (validator params) ----
        byte[] apiId = SUITE.apiId();
        byte[] w = issuer.publicKey().bytes();
        CfrgBbsCore.Generators gens = CfrgBbsCore.createGenerators(6, SUITE, BLS);
        var params = new OnChainKycClaimService.BbsParams(
                w,
                Bls12381Codecs.g2ToCompressed(BLS.g2Generator()),
                g1c(SUITE.p1()),
                g1c(gens.q1()),
                List.of(g1c(gens.h().get(0)), g1c(gens.h().get(1)), g1c(gens.h().get(2)),
                        g1c(gens.h().get(3)), g1c(gens.h().get(4))),
                BbsCodec.scalarToBytesAllowZero(CfrgBbsCore.calculateDomain(w, gens, issuer.header(), SUITE)),
                concat(apiId, a("H2S_")),
                concat(apiId, a("MAP_MSG_TO_SCALAR_AS_HASH_")));

        // ---- 3. Accounts: a funder (locks the voucher, pays fees) and the recipient ----
        var funder = new Account(Networks.testnet(), FUNDER_MNEMONIC);
        var recipient = new Account(Networks.testnet());
        byte[] recipientPkh = new Address(recipient.baseAddress()).getPaymentCredentialHash().orElseThrow();
        topUp(funder.baseAddress(), 10000);

        // ---- 4. Lock a voucher and claim it with the presentation ----
        var service = new OnChainKycClaimService(
                new BFBackendService(DEVKIT_API, ""), funder, params, Networks.testnet());
        System.out.println("claim validator address: " + service.scriptAddress());

        // The presentation is derived only once the voucher exists: its header is bound to that
        // voucher's ref + the recipient, which the validator recomputes on-chain.
        String txHash = service.lockAndClaim(
                ph -> {
                    BbsPresentation presentation = holder.present(List.of("country", "kycLevel"), ph);
                    BbsCodec.ProofParts pp = BbsCodec.octetsToProof(presentation.proof().bytes(), SUITE);
                    return new OnChainKycClaimService.Claim(
                            g1c(pp.aBar()), g1c(pp.bBar()), g1c(pp.d()),
                            pp.eHat(), pp.r1Hat(), pp.r3Hat(), pp.mHats(), pp.challenge(),
                            u("USA"), u("verified"), ph);
                },
                "USA", "verified",
                recipient.baseAddress(), recipientPkh, OnChainKycClaimService.DEMO_REFUND_LOVELACE);

        assertNotNull(txHash, "claim tx submitted");
        System.out.println("✅ BBS presentation verified ON-CHAIN; claim tx = " + txHash);
        System.out.println("   refund paid to " + recipient.baseAddress());
    }

    private static void topUp(String address, int ada) throws Exception {
        String body = "{\"address\":\"" + address + "\",\"adaAmount\":" + ada + "}";
        var req = HttpRequest.newBuilder(URI.create(DEVKIT_FAUCET + "/local-cluster/api/addresses/topup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        var resp = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 == 2) Thread.sleep(1500);
    }

    private static byte[] concat(byte[] x, byte[] y) {
        byte[] out = Arrays.copyOf(x, x.length + y.length);
        System.arraycopy(y, 0, out, x.length, y.length);
        return out;
    }
}
