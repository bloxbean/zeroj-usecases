package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The demo data directory and the files the airdrop keeps in it (ADR-0009 D3, D11).
 *
 * <p>Keys and deployment state live together, so {@code ./demo.sh airdrop --clean-cache} (which
 * removes the whole data volume) resets both at once: a fresh deployment. Outside Docker, delete
 * the {@code airdrop-*.json} files in this directory together.
 */
@Component
public class AirdropDataDir {

    private final Path dir;

    @Autowired
    public AirdropDataDir(@Value("${airdrop.data-dir:./data}") String dir) {
        this(Path.of(dir));
    }

    public AirdropDataDir(Path dir) {
        this.dir = dir;
        DemoFiles.ensureDirectory(dir);
    }

    public Path dir() {
        return dir;
    }

    /** The issuer's EdDSA-Jubjub signing key. */
    Path issuerKey() {
        return dir.resolve("airdrop-issuer-key.json");
    }

    /** The faucet admin wallet, whose signature releases payouts. */
    Path adminKey() {
        return dir.resolve("airdrop-faucet-admin-key.json");
    }

    /** The faucet's seed outref and the keys it was deployed with. */
    Path deployment() {
        return dir.resolve("airdrop-deployment.json");
    }

    /** The issuer's record of persons it has issued a credential to. */
    Path issuedPersons() {
        return dir.resolve("airdrop-issued-persons.json");
    }

    /** The faucet's record of nullifiers it has paid (or is paying). */
    Path paidNullifiers() {
        return dir.resolve("airdrop-paid-nullifiers.json");
    }

    /** The custodial demo holder wallet: each holder's {@code personhoodId} and credential. */
    Path holderWallet() {
        return dir.resolve("airdrop-holder-wallet.json");
    }

    /**
     * Whether any deployment state exists. If it does, a missing key is an error, never a
     * reason to create a new one (ADR-0009 D11, fail closed).
     */
    boolean hasState() {
        for (Path p : List.of(deployment(), issuedPersons(), paidNullifiers(), holderWallet())) {
            if (Files.exists(p)) {
                return true;
            }
        }
        return false;
    }
}
