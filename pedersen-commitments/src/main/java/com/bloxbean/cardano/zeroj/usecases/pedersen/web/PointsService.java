package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Demo A, confidential points, as confidential notes (ADR-0007; ZeroJ ADR-0055 M3). The retailer
 * issues points (trusted issuance), Alice and Bob transfer and redeem them, and an auditor reads
 * every amount from chain data. Wallet balances are recovered by scanning the chain with each
 * wallet's viewing key, never from server memory.
 */
@Service
public class PointsService {

    static final List<String> HOLDERS = List.of("alice", "bob");

    private final NoteDemo demo;

    public PointsService(BackendService backend, Funding funding) {
        this.demo = new NoteDemo("points", backend, funding, "retailer", HOLDERS, "auditor", "PTS", false);
    }

    void ensureReady() throws Exception {
        demo.ensureReady();
    }

    public synchronized Map<String, Object> issue(String to, long amount, Long reported) throws Exception {
        demo.ensureReady();
        return demo.issue(to, amount, reported);
    }

    public synchronized Map<String, Object> transfer(String from, String to, long amount, String cheat) throws Exception {
        demo.ensureReady();
        return demo.transfer(from, to, amount, cheat(cheat));
    }

    public synchronized Map<String, Object> redeem(String from, long price) throws Exception {
        demo.ensureReady();
        return demo.redeem(from, price);
    }

    public synchronized Map<String, Object> steal(String thief, String victim) throws Exception {
        demo.ensureReady();
        return demo.steal(thief, victim);
    }

    public synchronized Map<String, Object> rotate() throws Exception {
        demo.ensureReady();
        return demo.rotate();
    }

    public synchronized Map<String, Object> state() throws Exception {
        demo.ensureReady();
        return demo.state();
    }

    static byte[] pkh(Account account) {
        return NoteDemo.pkh(account);
    }

    static String shortHex(BigInteger value) {
        return NoteDemo.shortHex(value);
    }

    static NoteDemo.Cheat cheat(String name) {
        if (name == null || name.isBlank()) return NoteDemo.Cheat.NONE;
        return switch (name) {
            case "garbageDelivery" -> NoteDemo.Cheat.GARBAGE_DELIVERY;
            case "retiredKey" -> NoteDemo.Cheat.RETIRED_KEY;
            case "stakeVariant" -> NoteDemo.Cheat.STAKE_VARIANT_OUTPUT;
            default -> throw new IllegalArgumentException("unknown cheat: " + name);
        };
    }
}
