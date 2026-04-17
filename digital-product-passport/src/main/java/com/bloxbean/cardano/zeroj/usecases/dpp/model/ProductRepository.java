package com.bloxbean.cardano.zeroj.usecases.dpp.model;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ProductRepository extends JpaRepository<ProductEntity, String> {
    Page<ProductEntity> findByProductType(String productType, Pageable pageable);
    List<ProductEntity> findByMintedTrue();
    long countByMintedTrue();
    long countByProductType(String productType);
}
