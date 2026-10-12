package com.bloxbean.cardano.zeroj.usecases.dpp.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * A product or batch in the manufacturer's own database. The measurements here are the
 * manufacturer's private data (ADR-0009 D10): no public endpoint returns them, and they never go
 * on-chain or into the MPF registry.
 */
@Entity
@Table(name = "products")
public class ProductEntity {

    @Id
    private String serialNumber;

    private String name;
    private String manufacturer;
    private String productType; // "battery" or "textile"

    private int carbonKg;
    private int recycledPct;
    private int country;
    /** Passed inspections as {@code inspectorId:unixSeconds}, comma-separated; null for none. */
    private String inspections;
    private int unitCount; // for batches (0 for individual products)

    private boolean minted;
    private String passportTxHash;
    private Integer passportIndex;
    private boolean revoked;

    private LocalDateTime createdAt;
    private LocalDateTime mintedAt;

    public ProductEntity() {}

    public ProductEntity(String serialNumber, String name, String manufacturer, String productType,
                          int carbonKg, int recycledPct, int country, String inspections, int unitCount) {
        this.serialNumber = serialNumber;
        this.name = name;
        this.manufacturer = manufacturer;
        this.productType = productType;
        this.carbonKg = carbonKg;
        this.recycledPct = recycledPct;
        this.country = country;
        this.inspections = inspections;
        this.unitCount = unitCount;
        this.createdAt = LocalDateTime.now();
    }

    // Getters and setters
    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getManufacturer() { return manufacturer; }
    public void setManufacturer(String manufacturer) { this.manufacturer = manufacturer; }
    public String getProductType() { return productType; }
    public void setProductType(String productType) { this.productType = productType; }
    public int getCarbonKg() { return carbonKg; }
    public void setCarbonKg(int carbonKg) { this.carbonKg = carbonKg; }
    public int getRecycledPct() { return recycledPct; }
    public void setRecycledPct(int recycledPct) { this.recycledPct = recycledPct; }
    public int getCountry() { return country; }
    public void setCountry(int country) { this.country = country; }
    public String getInspections() { return inspections; }
    public void setInspections(String inspections) { this.inspections = inspections; }
    public int getUnitCount() { return unitCount; }
    public void setUnitCount(int unitCount) { this.unitCount = unitCount; }
    public boolean isMinted() { return minted; }
    public void setMinted(boolean minted) { this.minted = minted; }
    public String getPassportTxHash() { return passportTxHash; }
    public void setPassportTxHash(String passportTxHash) { this.passportTxHash = passportTxHash; }
    public Integer getPassportIndex() { return passportIndex; }
    public void setPassportIndex(Integer passportIndex) { this.passportIndex = passportIndex; }
    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    public LocalDateTime getMintedAt() { return mintedAt; }
    public void setMintedAt(LocalDateTime mintedAt) { this.mintedAt = mintedAt; }
}
