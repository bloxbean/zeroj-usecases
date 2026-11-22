package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import com.bloxbean.cardano.client.backend.api.BackendService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Confidential payroll (ADR-0007 N8): the employer pays salaries as notes with <b>proof-enforced
 * issuance</b> (ZeroJ ADR-0055 Q9 (b)), so the tax authority reads every salary from chain data and
 * the employer cannot under-report one. Employees read their payslips from the chain and can
 * transfer or cash out through the same proved paths as points.
 */
@Service
public class PayrollService {

    static final List<String> EMPLOYEES = List.of("carol", "dave");

    private final NoteDemo demo;

    public PayrollService(BackendService backend, Funding funding) {
        this.demo = new NoteDemo("payroll", backend, funding, "employer", EMPLOYEES, "tax authority", "SAL", true);
    }

    void ensureReady() throws Exception {
        demo.ensureReady();
    }

    /** Pays {@code amount} to {@code to}; with {@code reported}, the employer tries to under-report it. */
    public synchronized Map<String, Object> pay(String to, long amount, Long reported) throws Exception {
        demo.ensureReady();
        return demo.issue(to, amount, reported);
    }

    public synchronized Map<String, Object> transfer(String from, String to, long amount, String cheat) throws Exception {
        demo.ensureReady();
        return demo.transfer(from, to, amount, PointsService.cheat(cheat));
    }

    /** Cashes out {@code price} at the employer (a public amount), keeping the hidden rest. */
    public synchronized Map<String, Object> cashOut(String from, long price) throws Exception {
        demo.ensureReady();
        return demo.redeem(from, price);
    }

    public synchronized Map<String, Object> rotate() throws Exception {
        demo.ensureReady();
        return demo.rotate();
    }

    public synchronized Map<String, Object> state() throws Exception {
        demo.ensureReady();
        return demo.state();
    }
}
