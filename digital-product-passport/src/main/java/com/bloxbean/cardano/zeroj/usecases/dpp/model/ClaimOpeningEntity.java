package com.bloxbean.cardano.zeroj.usecases.dpp.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One claim's opening {@code (m…, r)}, as the auditor hands it to the manufacturer with its report
 * (ADR-0009 D1). Values and blinding are decimal strings; the blinding is the manufacturer's
 * secret. In this custodial demo the auditor's copy and the manufacturer's copy are this row.
 */
@Entity
@Table(name = "claim_openings")
public class ClaimOpeningEntity {

    @Id
    private String id; // serial + ":" + claim id

    private String serialNumber;
    private int claimId;
    @Column(length = 512)
    private String claimValues;
    @Column(length = 128)
    private String blinding;

    public ClaimOpeningEntity() {}

    public ClaimOpeningEntity(String serialNumber, int claimId, String claimValues, String blinding) {
        this.id = serialNumber + ":" + claimId;
        this.serialNumber = serialNumber;
        this.claimId = claimId;
        this.claimValues = claimValues;
        this.blinding = blinding;
    }

    public String getId() { return id; }
    public String getSerialNumber() { return serialNumber; }
    public int getClaimId() { return claimId; }
    public String getClaimValues() { return claimValues; }
    public String getBlinding() { return blinding; }
}
