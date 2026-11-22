package com.bloxbean.cardano.zeroj.usecases.dpp.service;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.backend.api.BackendService;
import com.bloxbean.cardano.client.function.TxSigner;
import com.bloxbean.cardano.zeroj.usecases.dpp.config.CardanoConfig;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.AuditRecordEntity;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.AuditRecordRepository;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.ClaimOpeningEntity;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.ClaimOpeningRepository;
import com.bloxbean.cardano.zeroj.usecases.dpp.model.ProductEntity;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.BackendChain;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.Claim;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.ClaimOpening;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.CoSignGuard;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportDatum;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.PassportScript;
import com.bloxbean.cardano.zeroj.usecases.dpp.passport.RoleKeys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The auditor (ADR-0009 D1): measures, commits, and co-signs.
 *
 * <p>For each claim it attests, the auditor draws a fresh 252-bit blinding from
 * {@code SecureRandom}, computes the {@code pedersen-jubjub-vector-v1} commitment under the claim's
 * schema, and hands the opening {@code (m…, r)} to the manufacturer with its report. It co-signs
 * a passport transaction only if the transaction carries exactly its own commitments for exactly
 * this product and manufacturer, and only once per product: it reserves the product for the
 * transaction atomically before signing, and refuses unless the policy's mint history for the
 * product is empty ({@link CoSignGuard}).
 *
 * <p>Custodial demo: this server holds the auditor's key as well as the manufacturer's, and the
 * measurements come from the manufacturer's product database standing in for the auditor's
 * measurement report.
 */
@Service
public class AuditorService {

    private static final Logger log = LoggerFactory.getLogger(AuditorService.class);

    private final Account auditor;
    private final ClaimOpeningRepository openings;
    private final AuditRecordRepository records;

    private final BackendService backendService;
    private final CardanoConfig cardanoConfig;

    public AuditorService(RoleKeys keys, ClaimOpeningRepository openings, AuditRecordRepository records,
                          BackendService backendService, CardanoConfig cardanoConfig) {
        this.auditor = keys.auditor();
        this.openings = openings;
        this.records = records;
        this.backendService = backendService;
        this.cardanoConfig = cardanoConfig;
    }

    public Account account() { return auditor; }

    /**
     * Attests a product once: commits every claim it measured with a fresh blinding and stores the
     * openings for the manufacturer. Later calls return the same openings, so a product's
     * commitments never change.
     */
    @Transactional
    public synchronized List<ClaimOpening> attest(ProductEntity p) {
        List<ClaimOpening> existing = openingsOf(p.getSerialNumber());
        if (!existing.isEmpty()) return existing;
        List<ClaimOpening> fresh = new ArrayList<>();
        fresh.add(ClaimOpening.fresh(Claim.CARBON, p.getCarbonKg()));
        fresh.add(ClaimOpening.fresh(Claim.RECYCLED, p.getRecycledPct()));
        fresh.add(ClaimOpening.fresh(Claim.ORIGIN, p.getCountry()));
        if (p.getInspections() != null && !p.getInspections().isBlank()) {
            fresh.add(ClaimOpening.fresh(Claim.INSPECTIONS, inspectionValues(p.getInspections())));
        }
        for (ClaimOpening o : fresh) {
            openings.save(new ClaimOpeningEntity(p.getSerialNumber(), o.claim().id(),
                    o.values().stream().map(BigInteger::toString).collect(Collectors.joining(",")),
                    o.blinding().toString()));
        }
        records.save(new AuditRecordEntity(p.getSerialNumber()));
        log.info("Auditor attested {}: {} claims committed", p.getSerialNumber(), fresh.size());
        return fresh;
    }

    /** The openings of a product's claims, in claim order; empty if not attested. */
    public List<ClaimOpening> openingsOf(String serial) {
        return openings.findBySerialNumberOrderByClaimId(serial).stream()
                .map(e -> new ClaimOpening(Claim.of(e.getClaimId()),
                        Arrays.stream(e.getClaimValues().split(",")).map(BigInteger::new).toList(),
                        new BigInteger(e.getBlinding())))
                .toList();
    }

    /** The datum the auditor expects for this product: its own commitments, this manufacturer. */
    public PassportDatum expectedDatum(String serial, byte[] manufacturerPkh) {
        return PassportDatum.of(serial.getBytes(StandardCharsets.UTF_8), manufacturerPkh, openingsOf(serial));
    }

    /**
     * The auditor's co-signature for a product's passport transaction, guarded by the
     * once-per-product reservation ({@link CoSignGuard}) against the live chain.
     */
    public TxSigner coSigner(String serial, PassportScript script) {
        return coSigner(serial, script, chain(script));
    }

    /** As {@link #coSigner(String, PassportScript)}, against {@code chain} (tests). */
    public TxSigner coSigner(String serial, PassportScript script, CoSignGuard.Chain chain) {
        if (records.findById(serial).isEmpty()) throw new IllegalStateException("the auditor has not attested " + serial);
        return guard(chain).signer(auditor, serial, script, expectedDatum(serial, script.manufacturerPkh()));
    }

    public CoSignGuard guard(CoSignGuard.Chain chain) {
        return new CoSignGuard(reservations, chain);
    }

    /** Called once the passport transaction is confirmed on chain. */
    public void confirmed(String serial, String txHash) {
        records.confirm(serial, txHash);
    }

    private CoSignGuard.Chain chain(PassportScript script) {
        return new BackendChain(backendService, cardanoConfig.indexerBaseUrl(), script);
    }

    /** The reservations, as single atomic updates of the auditor's records. */
    private final CoSignGuard.Reservations reservations = new CoSignGuard.Reservations() {
        @Override
        public boolean reserve(String serial, String txHash, long ttlSlot) {
            return records.reserve(serial, txHash, ttlSlot) == 1;
        }

        @Override
        public Optional<CoSignGuard.Reservation> find(String serial) {
            return records.findById(serial).filter(r -> r.getCosignedTx() != null)
                    .map(r -> new CoSignGuard.Reservation(r.getCosignedTx(),
                            r.getCosignTtlSlot() == null ? 0 : r.getCosignTtlSlot(), r.isCosignConfirmed()));
        }

        @Override
        public void confirm(String serial, String txHash) {
            records.confirm(serial, txHash);
        }

        @Override
        public void release(String serial, String txHash) {
            records.release(serial, txHash);
            log.info("Auditor released the reservation of {} for {} (TTL passed, not on chain)", serial, txHash);
        }
    };

    /** {@code inspectorId:unixSeconds,…} as the schema's values: inspector_0, time_0, inspector_1, …. */
    static List<BigInteger> inspectionValues(String inspections) {
        List<BigInteger> values = new ArrayList<>();
        for (String part : inspections.split(",")) {
            String[] idTime = part.trim().split(":");
            values.add(new BigInteger(idTime[0]));
            values.add(new BigInteger(idTime[1]));
        }
        return values;
    }
}
