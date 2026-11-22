package com.bloxbean.cardano.zeroj.usecases.pedersen.auction;

import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.circuit.BidProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.auction.circuit.SettleProofCircuit;
import com.bloxbean.cardano.zeroj.usecases.pedersen.common.Fields;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The auction relations (ADR-0008 D3, D4): honest bids and settlements prove and verify; bids
 * outside {@code [reserve, deposit]}, proofs for another bidder, and every wrong settlement (another
 * winner, a later equal bid, a wrong price, a wrong secret, a wrong decryption) have no proof.
 */
class AuctionCircuitTest {

    static final SecureRandom RANDOM = new SecureRandom();
    static final byte[] ALICE = filled(28, (byte) 0x0a);
    static final byte[] BOB = filled(28, (byte) 0x0b);
    static final byte[] CAROL = filled(28, (byte) 0x0c);
    static AuctionProofs proofs;
    static ElGamalSecretKey auctioneer;
    static NOfNKeyContext context;

    @BeforeAll
    static void setup() {
        proofs = new AuctionProofs();
        auctioneer = ElGamalSecretKey.generate(RANDOM);
        context = NOfNKeyContext.singleKey(auctioneer);
        System.out.printf("[auction circuits] bid %d constraints / %d public; settle n1 %d, n2 %d, n3 %d%n",
                proofs.bid().numConstraints(), proofs.bid().numPublicInputs(), proofs.settle(1).numConstraints(),
                proofs.settle(2).numConstraints(), proofs.settle(3).numConstraints());
    }

    static ElGamalEncryption enc(long amount) {
        return ElGamal.encryptWithOpening(context, BigInteger.valueOf(amount), 32, RANDOM);
    }

    static BigInteger pkU() { return auctioneer.publicKey().affineU(); }

    static BigInteger pkV() { return auctioneer.publicKey().affineV(); }

    @Test
    @DisplayName("Bid: an honest bid proves and is bound to its bidder; a bid outside [reserve, deposit] has no proof")
    void bid() {
        ElGamalEncryption e = enc(40);
        var inputs = AuctionProofs.bidInputs(ALICE, 100, 10, pkU(), pkV(), e);
        var proof = proofs.proveBid(ALICE, 100, 10, pkU(), pkV(), e);
        List<BigInteger> pub = BidProofCircuit.publicInputs(inputs);
        assertTrue(proofs.bid().verify(proof, pub));
        List<BigInteger> otherBidder = new ArrayList<>(pub);
        otherBidder.set(0, AuctionProofs.bidderInt(BOB));
        assertFalse(proofs.bid().verify(proof, otherBidder), "a proof is bound to its bidder");
        for (int i = 1; i < pub.size(); i++) {
            List<BigInteger> changed = new ArrayList<>(pub);
            changed.set(i, changed.get(i).add(BigInteger.ONE));
            assertFalse(proofs.bid().verify(proof, changed), "public input " + i + " is bound");
        }
        // Boundaries are inclusive.
        proofs.proveBid(ALICE, 100, 10, pkU(), pkV(), enc(10));
        proofs.proveBid(ALICE, 100, 10, pkU(), pkV(), enc(100));
        assertThrows(RuntimeException.class, () -> proofs.proveBid(ALICE, 100, 10, pkU(), pkV(), enc(101)), "above the deposit");
        assertThrows(RuntimeException.class, () -> proofs.proveBid(ALICE, 100, 10, pkU(), pkV(), enc(9)), "below the reserve");
        // A ciphertext of another amount than the witness claims.
        var lying = AuctionProofs.bidInputs(ALICE, 100, 10, pkU(), pkV(), e).bid(41);
        assertThrows(RuntimeException.class, () -> proofs.bid().prove(lying.toWitnessMap()), "the ciphertext encrypts the bid");
        // Encrypted to another key than the public one.
        var stranger = NOfNKeyContext.singleKey(ElGamalSecretKey.generate(RANDOM));
        var foreign = ElGamal.encryptWithOpening(stranger, BigInteger.valueOf(40), 32, RANDOM);
        assertThrows(RuntimeException.class, () -> proofs.proveBid(ALICE, 100, 10, pkU(), pkV(), foreign), "another key");
    }

    static Lot lot(List<ElGamalEncryption> encs, List<byte[]> bidders) {
        List<Lot.Bid> bids = new ArrayList<>();
        for (int i = 0; i < encs.size(); i++) {
            var ct = encs.get(i).ciphertext();
            bids.add(new Lot.Bid(bidders.get(i), ct.handle().affineU(), ct.handle().affineV(),
                    ct.blinded().affineU(), ct.blinded().affineV()));
        }
        return new Lot(null, "00".repeat(32), ALICE, BOB, new byte[28], "x".getBytes(), 2_000_000, 100, 10, 0, 0,
                pkU(), pkV(), 0, bids);
    }

    @Test
    @DisplayName("Settle: the earliest highest bid at its amount proves for n = 1, 2, 3; every wrong settlement has no proof")
    void settle() {
        BigInteger sk = auctioneer.secretScalar();
        // n = 3 with a tie: bids 40, 70, 70. The earliest highest bid is #2.
        List<Long> amounts = List.of(40L, 70L, 70L);
        Lot lot = lot(List.of(enc(40), enc(70), enc(70)), List.of(ALICE, BOB, CAROL));
        var proof = proofs.proveSettle(lot, 2, 70, sk, amounts);
        var pub = SettleProofCircuit.publicInputs(AuctionProofs.settleInputs(lot, 2, 70, sk, amounts));
        assertTrue(proofs.settle(3).verify(proof, pub));
        for (int i = 0; i < pub.size(); i++) {
            List<BigInteger> changed = new ArrayList<>(pub);
            changed.set(i, changed.get(i).add(BigInteger.ONE));
            assertFalse(proofs.settle(3).verify(proof, changed), "public input " + i + " is bound");
        }
        assertThrows(RuntimeException.class, () -> proofs.proveSettle(lot, 3, 70, sk, amounts), "a later equal bid is not the winner");
        assertThrows(RuntimeException.class, () -> proofs.proveSettle(lot, 1, 40, sk, amounts), "a lower bid is not the winner");
        assertThrows(RuntimeException.class, () -> proofs.proveSettle(lot, 2, 69, sk, amounts), "the price is the winning bid");
        assertThrows(RuntimeException.class, () -> proofs.proveSettle(lot, 2, 70, sk, List.of(40L, 70L, 69L)),
                "a bid decrypted to another amount");
        assertThrows(RuntimeException.class, () -> proofs.proveSettle(lot, 2, 70, sk, List.of(10L, 70L, 70L)),
                "an under-reported losing bid");
        BigInteger otherSk = ElGamalSecretKey.generate(RANDOM).secretScalar();
        assertThrows(RuntimeException.class, () -> proofs.proveSettle(lot, 2, 70, otherSk, amounts), "another secret key");
        assertThrows(RuntimeException.class, () -> proofs.proveSettle(lot, 4, 70, sk, amounts), "w out of range");
        assertThrows(RuntimeException.class, () -> proofs.proveSettle(lot, 0, 70, sk, amounts), "w = 0");
        // A field element that is no index: 2^-1 mod r, and r - 1. Every one-hot flag is 0, so no proof.
        BigInteger r = Fields.FR;
        for (BigInteger w : List.of(BigInteger.TWO.modInverse(r), r.subtract(BigInteger.ONE))) {
            var inputs = AuctionProofs.settleInputs(lot, 2, 70, sk, amounts).w(w);
            assertThrows(RuntimeException.class, () -> proofs.settle(3).prove(inputs.toWitnessMap()), "w = " + w);
        }

        // n = 1 and n = 2.
        Lot one = lot(List.of(enc(55)), List.of(ALICE));
        assertTrue(proofs.settle(1).verify(proofs.proveSettle(one, 1, 55, sk, List.of(55L)),
                SettleProofCircuit.publicInputs(AuctionProofs.settleInputs(one, 1, 55, sk, List.of(55L)))));
        Lot two = lot(List.of(enc(30), enc(90)), List.of(ALICE, BOB));
        assertTrue(proofs.settle(2).verify(proofs.proveSettle(two, 2, 90, sk, List.of(30L, 90L)),
                SettleProofCircuit.publicInputs(AuctionProofs.settleInputs(two, 2, 90, sk, List.of(30L, 90L)))));
    }

    static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
