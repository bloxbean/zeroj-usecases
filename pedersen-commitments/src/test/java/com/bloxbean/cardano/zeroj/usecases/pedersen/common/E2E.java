package com.bloxbean.cardano.zeroj.usecases.pedersen.common;

import com.bloxbean.cardano.client.api.model.Result;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Shared assertions for the DevKit end-to-end tests. */
public final class E2E {

    private E2E() {}

    /** Whether DevKit tests are enabled ({@code ZEROJ_YACI_E2E=true}) and DevKit answers. */
    public static boolean enabled() {
        return Boolean.getBoolean("zeroj.yaci.e2e") && DevKit.reachable();
    }

    /**
     * The transaction failed, and it failed in script evaluation (not, say, for lack of funds).
     * CCL reports a failing script as {@code "... Script evaluation failed for <purpose>[i] ..."}
     * when a spend is involved, and as {@code "Error while evaluating script cost"} for mint-only
     * transactions (the script's own failure is logged); both come only from the script
     * evaluator.
     */
    public static void assertScriptRejected(Result<String> result, String what) {
        assertFalse(result.isSuccessful(), what + " must be rejected");
        String response = String.valueOf(result.getResponse());
        System.out.println("Rejected (" + what + "): " + response.substring(0, Math.min(140, response.length())));
        assertTrue(response.contains("Script evaluation failed") || response.equals("Error while evaluating script cost"),
                what + " must be rejected by a script: " + response);
    }
}
