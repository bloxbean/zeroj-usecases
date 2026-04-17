package com.bloxbean.cardano.zeroj.usecases.reserves.model;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface AccountRepository extends JpaRepository<AccountEntity, String> {
    Page<AccountEntity> findAllByOrderByNameAsc(Pageable pageable);

    @Query("SELECT SUM(a.balanceLovelace) FROM AccountEntity a")
    Long sumBalances();
}
