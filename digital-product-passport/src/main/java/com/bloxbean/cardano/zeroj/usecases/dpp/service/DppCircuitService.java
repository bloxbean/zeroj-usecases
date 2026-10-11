package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.zeroj.usecases.dpp.passport.DppCircuits;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.zeroj.circuit.lib.poseidon.PoseidonCacheVersion;

import java.nio.file.Path;
import java.util.List;

/**
 * Compiles the four passport claim circuits and their development Groth16 keys (cached in
 * {@code dpp.data-dir}, keyed by each circuit's constraint digest).
 */
@Service
public class DppCircuitService {

    private static final Logger log = LoggerFactory.getLogger(DppCircuitService.class);
    @Value("${dpp.data-dir}")
    private String dataDir;

    private DppCircuits circuits;

    @PostConstruct
    public void init() {
        // Wipe setup caches and Poseidon-hashed state if the Poseidon parameters changed since
        // they were generated (stale constants would make witnesses fail).
        boolean wiped = PoseidonCacheVersion.ensureFresh(Path.of(dataDir),
                List.of("setup-*", "dpp-passport-registry"));
        if (wiped) {
            log.info("Poseidon parameters changed since last run: wiped stale setup and registry caches");
        }
        log.info("Compiling the passport claim circuits...");
        circuits = DppCircuits.compile(Path.of(dataDir));
        log.info("Passport claim circuits ready.");
    }

    public DppCircuits circuits() {
        return circuits;
    }
}
