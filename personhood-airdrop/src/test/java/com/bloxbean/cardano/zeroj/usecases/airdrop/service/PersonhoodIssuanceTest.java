package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.lib.jubjub.EdDSAJubjub;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Holder-chosen identifiers and one credential per person (ADR-0009 D3.1, D3.2, I6). Expected
 * messages come from ZeroJ's {@link PoseidonHash} and signatures are checked with
 * {@link EdDSAJubjub#verify}.
 */
class PersonhoodIssuanceTest {

    /** Records everything the holder sends the issuer. */
    private static final class RecordingIssuer implements PersonhoodIssuer {
        final PersonhoodIssuer delegate;
        final List<Object> received = new ArrayList<>();

        RecordingIssuer(PersonhoodIssuer delegate) {
            this.delegate = delegate;
        }

        @Override
        public EdDSAJubjub.Signature issue(String person, BigInteger m) {
            received.add(person);
            received.add(m);
            return delegate.issue(person, m);
        }

        @Override
        public JubjubPoint publicKey() {
            return delegate.publicKey();
        }
    }

    @Test
    void issuerApiNeverReceivesThePersonhoodId(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        var issuer = new RecordingIssuer(new PersonhoodIssuerService(new AirdropKeys(data), data));
        var wallet = new HolderWallet(issuer, data);

        var alice = wallet.enroll("Alice");
        BigInteger pid = alice.personhoodId();
        BigInteger m = PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, pid, BigInteger.ZERO);

        assertEquals(List.of("Alice", m), issuer.received, "the issuer receives only the person and m");
        assertFalse(issuer.received.contains(pid), "the issuer never receives personhoodId");
        assertTrue(EdDSAJubjub.verify(issuer.publicKey(), m, alice.signature()));
        assertTrue(pid.bitLength() <= 252 && pid.signum() > 0, "pid is a 252-bit value");
        assertTrue(pid.bitLength() > 200, "pid is not a small counter");

        // The issuer's own state holds no trace of pid.
        String pidHex = pid.toString(16);
        assertFalse(Files.readString(data.issuedPersons()).contains(pidHex));
        assertFalse(Files.readString(data.issuerKey()).contains(pidHex));

        // The issuer interface cannot receive pid: its only input besides the person is m.
        for (Method method : PersonhoodIssuer.class.getDeclaredMethods()) {
            if (Modifier.isStatic(method.getModifiers())) continue;
            if (method.getName().equals("issue")) {
                assertEquals(List.of(String.class, BigInteger.class), List.of(method.getParameterTypes()));
            } else {
                assertEquals(0, method.getParameterCount(), method.getName());
            }
        }
    }

    @Test
    void holdersChooseDistinctIdentifiers(@TempDir Path dir) {
        var data = new AirdropDataDir(dir);
        var wallet = new HolderWallet(new PersonhoodIssuerService(new AirdropKeys(data), data), data);
        assertNotEquals(wallet.enroll("Alice").personhoodId(), wallet.enroll("Bob").personhoodId());
    }

    @Test
    void secondIssuanceForTheSamePersonIsRefusedAlsoAfterRestart(@TempDir Path dir) {
        var data = new AirdropDataDir(dir);
        var issuer = new PersonhoodIssuerService(new AirdropKeys(data), data);
        BigInteger m1 = HolderWallet.message(BigInteger.valueOf(11));
        BigInteger m2 = HolderWallet.message(BigInteger.valueOf(22));
        issuer.issue("Alice", m1);
        assertThrows(PersonhoodIssuer.AlreadyIssuedException.class, () -> issuer.issue("Alice", m2));
        assertThrows(PersonhoodIssuer.AlreadyIssuedException.class, () -> issuer.issue(" Alice ", m2));

        var restarted = new PersonhoodIssuerService(new AirdropKeys(new AirdropDataDir(dir)), new AirdropDataDir(dir));
        assertTrue(restarted.hasIssued("Alice"));
        assertThrows(PersonhoodIssuer.AlreadyIssuedException.class, () -> restarted.issue("Alice", m2));
        restarted.issue("Bob", m2);
    }

    @Test
    void lostCredentialCannotBeReissued(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        var issuer = new PersonhoodIssuerService(new AirdropKeys(data), data);
        new HolderWallet(issuer, data).enroll("Alice");
        Files.delete(data.holderWallet());
        var freshWallet = new HolderWallet(issuer, data);
        assertThrows(PersonhoodIssuer.AlreadyIssuedException.class, () -> freshWallet.enroll("Alice"));
    }

    @Test
    void nonCanonicalMessageIsRefusedAndNotRecorded(@TempDir Path dir) {
        var data = new AirdropDataDir(dir);
        var issuer = new PersonhoodIssuerService(new AirdropKeys(data), data);
        BigInteger r = FieldConfig.BLS12_381.prime();
        assertThrows(IllegalArgumentException.class, () -> issuer.issue("Alice", r));
        assertThrows(IllegalArgumentException.class, () -> issuer.issue("Alice", BigInteger.ONE.negate()));
        assertFalse(issuer.hasIssued("Alice"), "a refused request does not use up the person's issuance");
        issuer.issue("Alice", HolderWallet.message(BigInteger.TEN));
    }

    @Test
    void walletSurvivesRestartAndFailsClosedUnderAnotherIssuerKey(@TempDir Path dir) throws Exception {
        var data = new AirdropDataDir(dir);
        var issuer = new PersonhoodIssuerService(new AirdropKeys(data), data);
        var alice = new HolderWallet(issuer, data).enroll("Alice");

        var reloaded = new HolderWallet(issuer, data).get("Alice");
        assertEquals(alice.personhoodId(), reloaded.personhoodId());
        assertEquals(alice.signature().s(), reloaded.signature().s());

        // A wallet whose credentials do not verify under the current issuer key stops startup.
        var otherData = new AirdropDataDir(dir.resolve("other"));
        var otherIssuer = new PersonhoodIssuerService(new AirdropKeys(otherData), otherData);
        assertThrows(IllegalStateException.class, () -> new HolderWallet(otherIssuer, data));
        // So does an issued-person record written under another key.
        Files.copy(data.issuedPersons(), otherData.issuedPersons(), StandardCopyOption.REPLACE_EXISTING);
        assertThrows(IllegalStateException.class,
                () -> new PersonhoodIssuerService(new AirdropKeys(otherData), otherData));
    }
}
