package com.bloxbean.cardano.zeroj.usecases.reserves.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "accounts")
public class AccountEntity {

    @Id
    private String accountId;
    private String name;
    private long balanceLovelace; // in lovelace (1 ADA = 1,000,000)
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public AccountEntity() {}

    public AccountEntity(String accountId, String name, long balanceLovelace) {
        this.accountId = accountId;
        this.name = name;
        this.balanceLovelace = balanceLovelace;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    public String getAccountId() { return accountId; }
    public void setAccountId(String accountId) { this.accountId = accountId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public long getBalanceLovelace() { return balanceLovelace; }
    public void setBalanceLovelace(long balanceLovelace) { this.balanceLovelace = balanceLovelace; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    /** Balance in ADA (display) */
    public double getBalanceAda() { return balanceLovelace / 1_000_000.0; }
}
