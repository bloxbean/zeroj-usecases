package com.bloxbean.cardano.zeroj.usecases.reusablekyc.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycCredential;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycSchema;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.SignedCredential;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Drives the reusable-KYC demo for the web UI: one issuer, one holder wallet, and a verifier.
 * Issue once → present any subset → verify off-chain → claim on-chain.
 */
@Service
public class ReusableKycDemoService {

    /** The on-chain claim gate is specialised to this disclosure (see ADR-0003). */
    public static final List<String> ONCHAIN_DISCLOSURE = List.of("country", "kycLevel");

    private final BackendService backendService;
    private final Account funder;
    private final IssuerService issuer;
    private final VerifierService verifier = new VerifierService();

    private volatile SignedCredential credential;
    private volatile BbsPresentation presentation;
    private volatile List<String> revealed = List.of();

    public ReusableKycDemoService(BackendService backendService, Account funder) {
        this.backendService = backendService;
        this.funder = funder;
        byte[] keyMaterial = new byte[32];
        new SecureRandom().nextBytes(keyMaterial);
        this.issuer = new IssuerService(keyMaterial, "demo-kyc-provider");
    }

    public Map<String, Object> status() {
        return Map.of(
                "issuer", issuer.issuerId(),
                "schema", KycSchema.ATTRIBUTES,
                "credentialIssued", credential != null,
                "presented", presentation != null,
                "revealed", revealed,
                "onchainDisclosure", ONCHAIN_DISCLOSURE,
                "validatorAddress", claimService().scriptAddress(),
                "funder", funder.baseAddress());
    }

    /**
     * The KYC provider verifies the subject once (out of band) and signs their attributes. The
     * response deliberately does <b>not</b> echo the attribute values — the credential now lives in
     * the holder's wallet, and nothing downstream needs the cleartext back over the wire. Only the
     * schema (attribute names) is returned, for the UI.
     */
    public Map<String, Object> issue(KycCredential attributes) {
        credential = issuer.issue(attributes);
        presentation = null;
        revealed = List.of();
        return Map.of("issued", true, "schema", KycSchema.ATTRIBUTES);
    }

    /**
     * A fresh single-use challenge from the verifier. The holder must bind their presentation to it,
     * which is what makes the presentation non-replayable — see {@link VerifierService#newChallenge}.
     */
    public Map<String, Object> challenge() {
        return Map.of("challenge", HexFormat.of().formatHex(verifier.newChallenge()),
                "bytes", VerifierService.CHALLENGE_BYTES);
    }

    /**
     * Reveal only {@code reveal} to the verifier, bound to {@code challengeHex} (which the verifier
     * issued via {@link #challenge()}), then check the presentation off-chain. The verifier accepts a
     * challenge exactly once, so re-posting the same presentation is rejected as a replay.
     */
    public Map<String, Object> present(List<String> reveal, String challengeHex) {
        requireCredential();
        byte[] ph = HexFormat.of().parseHex(challengeHex);
        presentation = new HolderService(credential).present(reveal, ph);
        revealed = List.copyOf(reveal);
        boolean valid = verifier.verifyFresh(issuer.publicKey(), presentation);
        var disclosed = verifier.disclosed(presentation);
        var hidden = KycSchema.ATTRIBUTES.stream().filter(a -> !disclosed.containsKey(a)).toList();
        return Map.of("valid", valid, "disclosed", disclosed, "hidden", hidden, "challenge", challengeHex);
    }

    /**
     * Lock a voucher for the credential's {@code (country, kycLevel)} and claim it on-chain — the
     * ledger verifies the BBS presentation natively and pays {@code recipientAddress}.
     *
     * <p>No caller-supplied nonce here: the presentation header is derived from the voucher UTxO being
     * spent plus the recipient, and the validator recomputes it. That binds the proof to exactly this
     * claim, and the voucher can only be spent once.</p>
     */
    public Map<String, Object> claim(String recipientAddress) throws Exception {
        requireCredential();
        String country = credential.credential().country();
        String kycLevel = credential.credential().kycLevel();

        byte[] recipientPkh = new Address(recipientAddress).getPaymentCredentialHash()
                .orElseThrow(() -> new IllegalArgumentException("Recipient has no payment credential"));

        // The on-chain gate is specialised to (country, kycLevel). The presentation is derived once
        // the voucher exists, since its ref is an input to the header the validator expects.
        var holder = new HolderService(credential);
        String txHash = claimService().lockAndClaim(
                ph -> BbsParamsFactory.claimFrom(
                        holder.present(ONCHAIN_DISCLOSURE, ph), country, kycLevel, ph),
                country, kycLevel, recipientAddress, recipientPkh,
                OnChainKycClaimService.DEMO_REFUND_LOVELACE);

        return Map.of("txHash", txHash,
                "validatorAddress", claimService().scriptAddress(),
                "recipient", recipientAddress,
                "refundLovelace", OnChainKycClaimService.DEMO_REFUND_LOVELACE,
                "disclosed", Map.of("country", country, "kycLevel", kycLevel),
                "verifiedOnChain", true);
    }

    /** A fresh receiving wallet, so the demo can show the refund landing somewhere new. */
    public Map<String, Object> newRecipient() {
        var account = new Account(Networks.testnet());
        return Map.of("address", account.baseAddress());
    }

    private OnChainKycClaimService claimService;

    private synchronized OnChainKycClaimService claimService() {
        if (claimService == null) {
            claimService = new OnChainKycClaimService(
                    backendService, funder, BbsParamsFactory.of(issuer), Networks.testnet());
        }
        return claimService;
    }

    private void requireCredential() {
        if (credential == null) throw new IllegalStateException("Issue a credential first");
    }
}
