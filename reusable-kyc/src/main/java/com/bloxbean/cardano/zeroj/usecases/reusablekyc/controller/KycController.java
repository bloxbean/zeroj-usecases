package com.bloxbean.cardano.zeroj.usecases.reusablekyc.controller;

import com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential.KycCredential;
import com.bloxbean.cardano.zeroj.usecases.reusablekyc.service.ReusableKycDemoService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/** REST API behind the reusable-KYC demo UI. */
@RestController
@RequestMapping("/api/kyc")
public class KycController {

    private final ReusableKycDemoService service;

    public KycController(ReusableKycDemoService service) {
        this.service = service;
    }

    public record IssueRequest(String givenName, String dob, String country, String kycLevel, String docHash) {}
    public record PresentRequest(List<String> reveal, String challenge) {}
    public record ClaimRequest(String recipientAddress) {}

    @GetMapping("/status")
    public Map<String, Object> status() {
        return service.status();
    }

    @PostMapping("/issue")
    public ResponseEntity<?> issue(@RequestBody IssueRequest r) {
        return call(() -> service.issue(new KycCredential(
                r.givenName(), r.dob(), r.country(), r.kycLevel(), r.docHash())));
    }

    /**
     * Step 1 of a presentation: the <b>verifier</b> issues a fresh single-use challenge. The holder
     * cannot pick this — that is the whole point — so there is no request body.
     */
    @PostMapping("/challenge")
    public Map<String, Object> challenge() {
        return service.challenge();
    }

    /** Step 2: the holder presents a subset, bound to a challenge from {@link #challenge()}. */
    @PostMapping("/present")
    public ResponseEntity<?> present(@RequestBody PresentRequest r) {
        return call(() -> service.present(r.reveal(), r.challenge()));
    }

    @PostMapping("/claim")
    public ResponseEntity<?> claim(@RequestBody ClaimRequest r) {
        return call(() -> service.claim(r.recipientAddress()));
    }

    @PostMapping("/recipient")
    public Map<String, Object> newRecipient() {
        return service.newRecipient();
    }

    private interface Call { Object run() throws Exception; }

    private static ResponseEntity<?> call(Call c) {
        try {
            return ResponseEntity.ok(c.run());
        } catch (Exception e) {
            String msg = e.getMessage() == null ? e.toString() : e.getMessage();
            return ResponseEntity.badRequest().body(Map.of("error", msg));
        }
    }
}
