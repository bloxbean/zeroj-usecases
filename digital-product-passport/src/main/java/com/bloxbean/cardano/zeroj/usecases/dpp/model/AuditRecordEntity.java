package com.bloxbean.cardano.zeroj.usecases.dpp.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

/**
 * The auditor's own record of a product: when it attested, and the passport transaction it
 * reserved and signed. The auditor co-signs at most one passport per product (ADR-0009 D1
 * uniqueness): {@code cosignedTx} is set by an atomic compare-and-set before signing
 * ({@link AuditRecordRepository#reserve}), and cleared only when that transaction can no longer
 * reach the chain.
 */
@Entity
@Table(name = "audit_records")
public class AuditRecordEntity {

    @Id
    private String serialNumber;

    private LocalDateTime attestedAt;
    /** The body hash of the passport transaction the auditor reserved and signed; null if none. */
    private String cosignedTx;
    /** That transaction's TTL slot. */
    private Long cosignTtlSlot;
    /** Whether that transaction is known to be on chain. */
    private boolean cosignConfirmed;

    public AuditRecordEntity() {}

    public AuditRecordEntity(String serialNumber) {
        this.serialNumber = serialNumber;
        this.attestedAt = LocalDateTime.now();
    }

    public String getSerialNumber() { return serialNumber; }
    public LocalDateTime getAttestedAt() { return attestedAt; }
    public String getCosignedTx() { return cosignedTx; }
    public Long getCosignTtlSlot() { return cosignTtlSlot; }
    public boolean isCosignConfirmed() { return cosignConfirmed; }
}
