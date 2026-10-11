package com.bloxbean.cardano.zeroj.usecases.dpp.model;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The auditor's records; the reservation operations are single atomic updates. */
public interface AuditRecordRepository extends JpaRepository<AuditRecordEntity, String> {

    /** Compare-and-set: reserves the product for {@code txHash} only if it holds no reservation. */
    @Modifying(clearAutomatically = true)
    @Transactional
    @Query("update AuditRecordEntity r set r.cosignedTx = :txHash, r.cosignTtlSlot = :ttl, r.cosignConfirmed = false"
            + " where r.serialNumber = :serial and r.cosignedTx is null")
    int reserve(@Param("serial") String serial, @Param("txHash") String txHash, @Param("ttl") long ttl);

    @Modifying(clearAutomatically = true)
    @Transactional
    @Query("update AuditRecordEntity r set r.cosignConfirmed = true"
            + " where r.serialNumber = :serial and r.cosignedTx = :txHash")
    int confirm(@Param("serial") String serial, @Param("txHash") String txHash);

    @Modifying(clearAutomatically = true)
    @Transactional
    @Query("update AuditRecordEntity r set r.cosignedTx = null, r.cosignTtlSlot = null"
            + " where r.serialNumber = :serial and r.cosignedTx = :txHash and r.cosignConfirmed = false")
    int release(@Param("serial") String serial, @Param("txHash") String txHash);
}
