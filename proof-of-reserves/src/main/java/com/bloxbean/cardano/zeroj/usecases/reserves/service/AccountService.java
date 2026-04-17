package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.zeroj.usecases.reserves.model.AccountEntity;
import com.bloxbean.cardano.zeroj.usecases.reserves.model.AccountRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.*;

@Service
public class AccountService {

    private static final Logger log = LoggerFactory.getLogger(AccountService.class);
    private static final Random RNG = new Random();

    private final AccountRepository repository;

    public AccountService(AccountRepository repository) {
        this.repository = repository;
    }

    @PostConstruct
    public void init() {
        if (repository.count() == 0) {
            createDemoAccounts();
        } else {
            log.info("Loaded {} accounts from H2", repository.count());
        }
    }

    private void createDemoAccounts() {
        addAccount("alice", "Alice", 500_000_000L);
        addAccount("bob", "Bob", 1_200_000_000L);
        addAccount("charlie", "Charlie", 300_000_000L);
        addAccount("diana", "Diana", 2_500_000_000L);
        addAccount("eve", "Eve", 800_000_000L);
        addAccount("frank", "Frank", 150_000_000L);
        addAccount("grace", "Grace", 3_000_000_000L);
        addAccount("henry", "Henry", 50_000_000L);
        log.info("Created 8 demo accounts (total: {} ADA)", getTotalBalanceAda());
    }

    public void addAccount(String id, String name, long balanceLovelace) {
        repository.save(new AccountEntity(id, name, balanceLovelace));
    }

    public List<String> addRandomAccounts(int count) {
        String[] names = {"Ivan", "Julia", "Kevin", "Laura", "Mike", "Nina", "Oscar", "Paula"};
        List<String> ids = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String id = "user_" + System.currentTimeMillis() % 100000 + "_" + RNG.nextInt(9000);
            String name = names[RNG.nextInt(names.length)] + "_" + id.substring(5, 10);
            long balance = (RNG.nextInt(5000) + 10) * 1_000_000L; // 10-5010 ADA
            addAccount(id, name, balance);
            ids.add(id);
        }
        log.info("Added {} random accounts", count);
        return ids;
    }

    public Page<AccountEntity> listAccounts(int page, int size) {
        return repository.findAllByOrderByNameAsc(PageRequest.of(page, size));
    }

    public AccountEntity getAccount(String id) {
        return repository.findById(id).orElse(null);
    }

    public List<AccountEntity> getAllAccounts() {
        return repository.findAll();
    }

    public long getTotalBalanceLovelace() {
        Long sum = repository.sumBalances();
        return sum != null ? sum : 0;
    }

    public double getTotalBalanceAda() {
        return getTotalBalanceLovelace() / 1_000_000.0;
    }

    public long getAccountCount() {
        return repository.count();
    }

    /**
     * Get account IDs as BigIntegers (for circuit input).
     * accountId string → Poseidon hash as identifier.
     */
    public BigInteger getAccountIdHash(String accountId) {
        return new BigInteger(1, accountId.getBytes());
    }
}
