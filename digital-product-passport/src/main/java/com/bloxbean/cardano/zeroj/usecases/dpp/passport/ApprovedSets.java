package com.bloxbean.cardano.zeroj.usecases.dpp.passport;

import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.InspectionClaimProof;
import com.bloxbean.cardano.zeroj.usecases.dpp.circuit.OriginClaimProof;

import java.util.List;

/** The demo's published approved sets: the roots verifiers prove origin and inspections against. */
public final class ApprovedSets {

    /** The 27 EU member states, ISO 3166-1 numeric. */
    public static final List<Long> EU_COUNTRY_CODES = List.of(
            40L, 56L, 100L, 191L, 196L, 203L, 208L, 233L, 246L, 250L, 276L, 300L, 348L, 372L,  // AUT … IRL
            380L, 428L, 440L, 442L, 470L, 528L, 616L, 620L, 642L, 703L, 705L, 724L, 752L);     // ITA … SWE

    /** Approved inspection bodies, as 8-bit ids. */
    public static final List<Long> INSPECTOR_IDS = List.of(11L, 12L, 13L, 14L, 15L);

    /** Countries: a depth-5 tree over 16-bit codes, padded with {@code 2^16}. */
    public static final ApprovedSet EU_COUNTRIES = ApprovedSet.ofLongs(EU_COUNTRY_CODES, OriginClaimProof.DEPTH, 16);

    /** Inspectors: a depth-3 tree over 8-bit ids, padded with {@code 2^8}. */
    public static final ApprovedSet INSPECTORS = ApprovedSet.ofLongs(INSPECTOR_IDS, InspectionClaimProof.DEPTH, 8);

    private ApprovedSets() {}
}
