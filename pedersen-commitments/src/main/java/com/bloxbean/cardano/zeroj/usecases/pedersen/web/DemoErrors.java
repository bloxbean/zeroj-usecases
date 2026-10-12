package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.api.model.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The two ways a demo action is refused, mapped to JSON the UI shows:
 * <ul>
 *   <li>{@link NoProof}: the statement is false, so the prover cannot produce a proof at all
 *       (nothing reaches the chain);</li>
 *   <li>{@link Rejected}: a transaction was built, and a validator returned false when the
 *       transaction was evaluated (locally with Julc, as the node would run it), so it was not
 *       submitted.</li>
 * </ul>
 */
@RestControllerAdvice
public class DemoErrors {

    private static final Logger log = LoggerFactory.getLogger(DemoErrors.class);

    /** The relation does not hold for this witness: no proof exists. */
    public static class NoProof extends RuntimeException {
        public NoProof(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** A transaction failed; {@link #scriptRejection} tells whether a validator rejected it. */
    public static class Rejected extends RuntimeException {
        private final String what;
        private final String detail;

        public Rejected(String what, String detail) {
            super(what + ": " + detail);
            this.what = what;
            this.detail = detail;
        }

        boolean scriptRejection() {
            return detail != null && (detail.contains("Script evaluation failed")
                    || detail.equals("Error while evaluating script cost"));
        }
    }

    /** A computation that may find no satisfying witness. */
    public interface Prover<T> {
        T prove();
    }

    /** The prover's result, or {@link NoProof} with {@code noProofMessage} if the relation does not hold. */
    public static <T> T prove(Prover<T> prover, String noProofMessage) {
        try {
            return prover.prove();
        } catch (RuntimeException e) {
            throw new NoProof(noProofMessage, e);
        }
    }

    /** The submitted transaction's hash, or {@link Rejected} if it failed. */
    public static String require(Result<String> result, String what) {
        if (!result.isSuccessful()) throw new Rejected(what, String.valueOf(result.getResponse()));
        return result.getValue();
    }

    @ExceptionHandler(NoProof.class)
    public ResponseEntity<Map<String, Object>> noProof(NoProof e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.getMessage());
        body.put("noProof", true);
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(body);
    }

    @ExceptionHandler(Rejected.class)
    public ResponseEntity<Map<String, Object>> rejected(Rejected e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.getMessage());
        body.put("onChainRejection", e.scriptRejection());
        if (e.scriptRejection()) {
            body.put("onChainValidation", Map.of(
                    "title", "The on-chain validator rejected this transaction",
                    "summary", e.what + " was built and evaluated against the real ledger state, and the Plutus script"
                            + " returned false, so it was not submitted.",
                    "detail", e.detail.equals("Error while evaluating script cost")
                            ? e.detail + " — cardano-client-lib reports a failing minting script this way;"
                                    + " the script's own failure trace is in the server log."
                            : e.detail));
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    @ExceptionHandler({IllegalArgumentException.class, IllegalStateException.class})
    public ResponseEntity<Map<String, Object>> badRequest(RuntimeException e) {
        log.warn("Request failed: {}", e.getMessage());
        return ResponseEntity.badRequest().body(Map.of("error", String.valueOf(e.getMessage())));
    }
}
