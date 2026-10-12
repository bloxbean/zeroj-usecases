package com.bloxbean.cardano.zeroj.usecases.pedersen.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** REST API behind the three tabs. Every action runs on Yaci DevKit; errors map in {@link DemoErrors}. */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class DemoController {

    private static final Logger log = LoggerFactory.getLogger(DemoController.class);

    private final PointsService points;
    private final CreditService credit;
    private final SolvencyService solvency;
    private final Map<String, String> readiness = new ConcurrentHashMap<>(
            Map.of("points", "starting", "credit", "starting", "solvency", "starting"));

    public DemoController(PointsService points, CreditService credit, SolvencyService solvency) {
        this.points = points;
        this.credit = credit;
        this.solvency = solvency;
    }

    /** Compiles circuits, loads or generates dev keys and funds wallets in the background. */
    @EventListener(ApplicationReadyEvent.class)
    public void warmUp() {
        warm("points", () -> points.ensureReady());
        warm("credit", () -> credit.ensureReady());
        warm("solvency", () -> solvency.ensureReady());
    }

    private interface Init {
        void run() throws Exception;
    }

    private void warm(String name, Init init) {
        Thread.ofVirtual().name("warm-" + name).start(() -> {
            try {
                init.run();
                readiness.put(name, "ready");
                log.info("{} demo ready", name);
            } catch (Exception e) {
                readiness.put(name, "failed: " + e.getMessage());
                log.error("{} demo failed to start", name, e);
            }
        });
    }

    /** Health and readiness of the three demos. */
    @GetMapping("/status")
    public Map<String, Object> status() {
        return Map.of("demos", Map.copyOf(readiness),
                "ready", readiness.values().stream().allMatch("ready"::equals));
    }

    // --- A. Confidential points -------------------------------------------------------------

    @GetMapping("/points")
    public Map<String, Object> pointsState() throws Exception {
        return points.state();
    }

    @PostMapping("/points/issue")
    public Map<String, Object> issue(@RequestBody Map<String, Object> r) throws Exception {
        return points.issue(str(r, "to"), num(r, "amount"));
    }

    @PostMapping("/points/transfer")
    public Map<String, Object> transfer(@RequestBody Map<String, Object> r) throws Exception {
        return points.transfer(str(r, "from"), str(r, "to"), num(r, "amount"));
    }

    @PostMapping("/points/redeem")
    public Map<String, Object> redeem(@RequestBody Map<String, Object> r) throws Exception {
        return points.redeem(str(r, "from"), num(r, "price"));
    }

    @PostMapping("/points/steal")
    public Map<String, Object> steal(@RequestBody Map<String, Object> r) throws Exception {
        return points.steal(str(r, "thief"), str(r, "victim"));
    }

    // --- B. Committed credential ------------------------------------------------------------

    @GetMapping("/credit")
    public Map<String, Object> creditState() throws Exception {
        return credit.state();
    }

    @PostMapping("/credit/issue")
    public Map<String, Object> issueProfile(@RequestBody Map<String, Object> r) throws Exception {
        return credit.issue(num(r, "income"), (int) num(r, "creditScore"), (int) num(r, "birthYear"),
                (int) num(r, "country"));
    }

    @PostMapping("/credit/claim")
    public Map<String, Object> claim(@RequestBody Map<String, Object> r) throws Exception {
        return credit.claim(str(r, "who"), num(r, "minIncome"), (int) num(r, "minScore"));
    }

    // --- C. Solvency ------------------------------------------------------------------------

    @GetMapping("/solvency")
    public Map<String, Object> solvencyState() throws Exception {
        return solvency.state();
    }

    @PostMapping("/solvency/book")
    @SuppressWarnings("unchecked")
    public Map<String, Object> book(@RequestBody Map<String, Object> r) throws Exception {
        return solvency.setBook((List<Map<String, Object>>) r.get("customers"));
    }

    @PostMapping("/solvency/attest")
    public Map<String, Object> attest(@RequestBody Map<String, Object> r) throws Exception {
        return solvency.attest(num(r, "reservesAda"));
    }

    @PostMapping("/solvency/attest-again")
    public Map<String, Object> attestAgain() throws Exception {
        return solvency.attestAgain();
    }

    @PostMapping("/solvency/check")
    public Map<String, Object> check(@RequestBody Map<String, Object> r) throws Exception {
        return solvency.check(str(r, "id"));
    }

    @PostMapping("/solvency/audit")
    public Map<String, Object> audit() throws Exception {
        return solvency.audit();
    }

    @PostMapping("/solvency/release")
    public Map<String, Object> release() throws Exception {
        return solvency.release();
    }

    // ----------------------------------------------------------------------------------------

    private static String str(Map<String, Object> r, String key) {
        Object v = r.get(key);
        if (v == null) throw new IllegalArgumentException("missing " + key);
        return v.toString();
    }

    private static long num(Map<String, Object> r, String key) {
        Object v = r.get(key);
        if (v instanceof Number n) return n.longValue();
        if (v instanceof String s && !s.isBlank()) return Long.parseLong(s.trim());
        throw new IllegalArgumentException("missing or invalid " + key);
    }
}
