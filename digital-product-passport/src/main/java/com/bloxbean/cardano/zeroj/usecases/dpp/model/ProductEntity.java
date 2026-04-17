package com.bloxbean.cardano.zeroj.usecases.dpp.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

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
    private int inspectionCount;
    private int unitCount; // for batches (0 for individual products)

    private boolean minted;
    private String mintTxHash;

    private LocalDateTime createdAt;
    private LocalDateTime mintedAt;

    public ProductEntity() {}

    public ProductEntity(String serialNumber, String name, String manufacturer, String productType,
                          int carbonKg, int recycledPct, int country, int inspectionCount, int unitCount) {
        this.serialNumber = serialNumber;
        this.name = name;
        this.manufacturer = manufacturer;
        this.productType = productType;
        this.carbonKg = carbonKg;
        this.recycledPct = recycledPct;
        this.country = country;
        this.inspectionCount = inspectionCount;
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
    public int getInspectionCount() { return inspectionCount; }
    public void setInspectionCount(int inspectionCount) { this.inspectionCount = inspectionCount; }
    public int getUnitCount() { return unitCount; }
    public void setUnitCount(int unitCount) { this.unitCount = unitCount; }
    public boolean isMinted() { return minted; }
    public void setMinted(boolean minted) { this.minted = minted; }
    public String getMintTxHash() { return mintTxHash; }
    public void setMintTxHash(String mintTxHash) { this.mintTxHash = mintTxHash; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    public LocalDateTime getMintedAt() { return mintedAt; }
    public void setMintedAt(LocalDateTime mintedAt) { this.mintedAt = mintedAt; }
}
