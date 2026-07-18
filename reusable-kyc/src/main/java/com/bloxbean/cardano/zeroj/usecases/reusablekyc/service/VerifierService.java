package com.bloxbean.cardano.zeroj.usecases.reusablekyc.service;

import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.bbs.BbsPublicKey;
import com.bloxbean.cardano.zeroj.bbs.BbsService;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycSchema;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A verifier (e.g. a DeFi app). Two independent checks:
 * <ol>
 *   <li><b>Cryptographic</b> — {@link #verify}: the presentation is a valid BBS proof under the
 *       issuer's key, i.e. the disclosed attributes really were signed by the issuer and the rest
 *       are hidden but genuine.</li>
 *   <li><b>Policy</b> — {@link #satisfies}: the disclosed values meet the verifier's requirements
 *       (e.g. {@code kycLevel=verified} and {@code country ∈ allowed}).</li>
 * </ol>
 * Both must pass. The verifier only ever sees the revealed attributes.
 */
public class VerifierService {

    /** Challenge size — 256 bits of CSPRNG entropy: unguessable and collision-free. */
    public static final int CHALLENGE_BYTES = 32;

    private final BbsService bbs = BbsService.pureJava();
    private final SecureRandom random = new SecureRandom();
    /** Challenges this verifier issued and has not yet consumed (single-use). */
    private final Set<String> outstanding = ConcurrentHashMap.newKeySet();

    /**
     * Issue a fresh challenge for a holder to bind their presentation to.
     *
     * <p>The <b>verifier</b> must pick this — never the holder — and it must be random and single-use.
     * That is what stops a captured presentation from being replayed: it only verifies against the
     * one challenge it was made for, and {@link #verifyFresh} accepts each challenge once.</p>
     */
    public byte[] newChallenge() {
        byte[] nonce = new byte[CHALLENGE_BYTES];
        random.nextBytes(nonce);
        outstanding.add(HexFormat.of().formatHex(nonce));
        return nonce;
    }

    /**
     * Full verifier check: the presentation is cryptographically valid <b>and</b> is bound to a
     * challenge this verifier issued and has not seen before. The challenge is consumed, so a replay
     * of the same presentation fails.
     */
    public boolean verifyFresh(BbsPublicKey issuerPublicKey, BbsPresentation presentation) {
        String ph = HexFormat.of().formatHex(presentation.presentationHeader());
        if (!outstanding.remove(ph)) {
            return false;   // unknown, expired, or already-used challenge → replay
        }
        return bbs.verifyPresentation(issuerPublicKey, presentation);
    }

    /**
     * Cryptographic check only: the presentation verifies under the issuer's public key. Does
     * <b>not</b> check challenge freshness — prefer {@link #verifyFresh} for a real verifier.
     */
    public boolean verify(BbsPublicKey issuerPublicKey, BbsPresentation presentation) {
        return bbs.verifyPresentation(issuerPublicKey, presentation);
    }

    /** The revealed attributes as {@code name -> value} (what the verifier is allowed to see). */
    public Map<String, String> disclosed(BbsPresentation presentation) {
        Map<String, String> out = new HashMap<>();
        presentation.revealedMessages().forEach(rm ->
                out.put(KycSchema.attributeAt(rm.index()), new String(rm.message(), StandardCharsets.UTF_8)));
        return out;
    }

    /**
     * Policy check over the disclosed attributes.
     *
     * @param presentation   the (already crypto-verified) presentation
     * @param mustEqual      attributes that must equal a specific value (e.g. {@code kycLevel=verified})
     * @param mustBeIn       attributes whose value must be in an allowed set (e.g. {@code country ∈ {…}})
     */
    public boolean satisfies(BbsPresentation presentation,
                             Map<String, String> mustEqual,
                             Map<String, Set<String>> mustBeIn) {
        Map<String, String> disclosed = disclosed(presentation);
        for (var e : mustEqual.entrySet()) {
            if (!e.getValue().equals(disclosed.get(e.getKey()))) return false;
        }
        for (var e : mustBeIn.entrySet()) {
            String v = disclosed.get(e.getKey());
            if (v == null || !e.getValue().contains(v)) return false;
        }
        return true;
    }
}
