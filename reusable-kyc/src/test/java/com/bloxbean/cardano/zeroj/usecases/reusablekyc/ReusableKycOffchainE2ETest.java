package com.bloxbean.cardano.zeroj.usecases.reusablekyc;

import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycCredential;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.SignedCredential;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.HolderService;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.IssuerService;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.VerifierService;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The reusable-KYC off-chain flow, end to end: a KYC provider signs a 5-attribute credential once,
 * the holder presents only {@code kycLevel} + {@code country} to a verifier, and the verifier checks
 * the BBS proof + its policy — learning nothing about name, DOB, or document hash.
 */
class ReusableKycOffchainE2ETest {

    private static byte[] seed(int b) {
        byte[] a = new byte[32];
        Arrays.fill(a, (byte) b);
        return a;
    }

    private static final KycCredential ALICE = new KycCredential(
            "Alice Example", "1990-05-01", "USA", "verified",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");

    @Test
    void issue_reveal_subset_verify() {
        IssuerService issuer = new IssuerService(seed(1), "kyc-provider-1");

        // 1. Issue: the provider signs Alice's full credential once.
        SignedCredential credential = issuer.issue(ALICE);

        // 2. Present: the VERIFIER issues a fresh challenge; the holder reveals ONLY kycLevel +
        //    country, bound to it.
        VerifierService verifier = new VerifierService();
        HolderService holder = new HolderService(credential);
        BbsPresentation presentation = holder.present(List.of("kycLevel", "country"), verifier.newChallenge());

        // 3. Verify: crypto check (+ challenge freshness) + policy.
        assertTrue(verifier.verifyFresh(issuer.publicKey(), presentation),
                "BBS presentation must verify under the issuer key");

        Map<String, String> disclosed = verifier.disclosed(presentation);
        assertEquals(2, disclosed.size(), "only 2 attributes revealed");
        assertEquals("verified", disclosed.get("kycLevel"));
        assertEquals("USA", disclosed.get("country"));
        // the rest stay private
        assertFalse(disclosed.containsKey("givenName"), "name must not be revealed");
        assertFalse(disclosed.containsKey("dob"), "DOB must not be revealed");
        assertFalse(disclosed.containsKey("docHash"), "document hash must not be revealed");

        // policy: verified + country in the allowed set → pass
        assertTrue(verifier.satisfies(presentation,
                Map.of("kycLevel", "verified"),
                Map.of("country", Set.of("USA", "GBR", "DEU"))));
        // policy: country not in a different allowed set → fail
        assertFalse(verifier.satisfies(presentation,
                Map.of("kycLevel", "verified"),
                Map.of("country", Set.of("JPN", "FRA"))));
    }

    @Test
    void a_captured_presentation_cannot_be_replayed() {
        IssuerService issuer = new IssuerService(seed(1), "kyc-provider-1");
        HolderService holder = new HolderService(issuer.issue(ALICE));
        VerifierService verifier = new VerifierService();

        // The holder answers the verifier's challenge once — accepted.
        byte[] challenge = verifier.newChallenge();
        BbsPresentation presentation = holder.present(List.of("kycLevel"), challenge);
        assertTrue(verifier.verifyFresh(issuer.publicKey(), presentation), "first use is accepted");

        // An attacker who captured that exact presentation replays it — rejected: the challenge is
        // single-use, even though the proof itself is still cryptographically valid.
        assertFalse(verifier.verifyFresh(issuer.publicKey(), presentation), "replay must be rejected");
        assertTrue(verifier.verify(issuer.publicKey(), presentation),
                "the proof itself stays valid — freshness is what rejects the replay");

        // ...and it doesn't satisfy the NEXT challenge either: the holder must present again.
        byte[] next = verifier.newChallenge();
        assertFalse(java.util.Arrays.equals(challenge, next), "each challenge is unique");
        assertTrue(verifier.verifyFresh(issuer.publicKey(), holder.present(List.of("kycLevel"), next)),
                "a fresh presentation for the new challenge is accepted");
    }

    @Test
    void presentation_does_not_verify_under_a_different_issuer_key() {
        IssuerService realIssuer = new IssuerService(seed(1), "kyc-provider-1");
        IssuerService imposter = new IssuerService(seed(2), "kyc-provider-2");

        SignedCredential credential = realIssuer.issue(ALICE);
        BbsPresentation presentation = new HolderService(credential)
                .present(List.of("kycLevel"), "nonce".getBytes(StandardCharsets.UTF_8));

        VerifierService verifier = new VerifierService();
        assertTrue(verifier.verify(realIssuer.publicKey(), presentation), "valid under the real issuer");
        assertFalse(verifier.verify(imposter.publicKey(), presentation),
                "must NOT verify under a different issuer's key");
    }
}
