package com.bloxbean.cardano.zeroj.usecases.pedersen.credential;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.util.HexUtil;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.DevKit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.E2E;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Plutus;
import com.bloxbean.cardano.zeroj.usecases.pedersen.credential.CreditGate.Profile;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Demo B on Yaci DevKit: a bureau issues Alice a committed credit profile and records the
 * issuance on-chain; Alice proves {@code income ≥ 50,000 ∧ credit_score ≥ 650} to a lender's gate
 * and receives a badge, revealing nothing else. Rejected by the gate on the ledger path: the claim
 * without the issuance record, and Mallory presenting Alice's commitment with a valid proof.
 * A profile below the thresholds cannot be proved at all.
 *
 * <p>Runs only with {@code ZEROJ_YACI_E2E=true}.
 */
class CreditGateDevKitE2ETest {

    @Test
    void creditGateOnDevKit() throws Exception {
        assumeTrue(E2E.enabled(), "Set ZEROJ_YACI_E2E=true with DevKit running");
        var backend = DevKit.backend();
        var bureau = new Account(Networks.testnet());
        var alice = new Account(Networks.testnet());
        var mallory = new Account(Networks.testnet());
        for (Account a : List.of(bureau, alice, mallory)) DevKit.topUp(a.baseAddress(), 200);
        byte[] alicePkh = alice.hdKeyPair().getPublicKey().getKeyHash();

        var credit = new CreditGate();
        long minIncome = 50_000;
        int minScore = 650;
        byte[] bureauPolicy = HexUtil.decodeHexString(CreditGate.bureauPolicy(bureau).getPolicyId());
        var gate = credit.gate(bureauPolicy, minIncome, minScore);

        // The bureau issues Alice's profile: the opening goes to Alice, the record goes on-chain.
        Profile profile = Profile.of(85_000, 720, 1990, 356);
        var commitment = profile.commitment();
        var issued = CreditGate.issueRecord(backend, bureau, alice.baseAddress(), alicePkh, commitment);
        assertTrue(issued.isSuccessful(), "issue: " + issued.getResponse());
        DevKit.waitForTx(backend, issued.getValue());
        Utxo record = DevKit.utxosOf(backend, alice.baseAddress(), issued.getValue()).stream()
                .filter(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().startsWith(HexUtil.encodeHexString(bureauPolicy))))
                .findFirst().orElseThrow();

        var proof = credit.prove(profile, minIncome, minScore);

        // Without the issuance record: fail closed.
        E2E.assertScriptRejected(
                CreditGate.claim(backend, gate, alice, commitment, null, proof), "a claim without the issuance record");
        // Mallory with Alice's commitment and a valid proof (say the opening leaked): the record names Alice.
        E2E.assertScriptRejected(
                CreditGate.claim(backend, gate, mallory, commitment, record, proof), "Mallory presenting Alice's credential");
        // A profile below the thresholds has no proof at all.
        assertThrows(RuntimeException.class, () -> credit.prove(Profile.of(42_000, 720, 1990, 356), minIncome, minScore));

        var claimed = CreditGate.claim(backend, gate, alice, commitment, record, proof);
        assertTrue(claimed.isSuccessful(), "claim: " + claimed.getResponse());
        DevKit.waitForTx(backend, claimed.getValue());
        String badgeUnit = Plutus.policyId(gate) + HexUtil.encodeHexString(alicePkh);
        assertTrue(DevKit.utxosOf(backend, alice.baseAddress(), claimed.getValue()).stream()
                .anyMatch(u -> u.getAmount().stream().anyMatch(a -> a.getUnit().equals(badgeUnit))), "Alice holds the badge");
        System.out.println("Credit gate on DevKit: record " + issued.getValue() + ", badge " + claimed.getValue());
    }
}
