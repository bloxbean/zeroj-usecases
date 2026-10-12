package com.bloxbean.cardano.zeroj.usecases.dpp.model;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ClaimOpeningRepository extends JpaRepository<ClaimOpeningEntity, String> {
    List<ClaimOpeningEntity> findBySerialNumberOrderByClaimId(String serialNumber);
}
