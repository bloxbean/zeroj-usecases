package com.bloxbean.cardano.zeroj.usecases.reusablekyc.credential;

import java.util.List;

/**
 * The reusable-KYC credential schema: the <b>ordered</b> list of attributes the issuer signs. BBS
 * signs a list of messages by position, so this order is the contract shared by issuer, holder, and
 * verifier — an attribute's index here is its BBS message index.
 */
public final class KycSchema {

    public static final String SCHEMA_ID = "reusable-kyc/v1";

    /** Attribute order — index in this list == BBS message index. */
    public static final List<String> ATTRIBUTES =
            List.of("givenName", "dob", "country", "kycLevel", "docHash");

    private KycSchema() {}

    /** The BBS message index of an attribute (throws if unknown). */
    public static int indexOf(String attribute) {
        int i = ATTRIBUTES.indexOf(attribute);
        if (i < 0) throw new IllegalArgumentException("Unknown attribute: " + attribute);
        return i;
    }

    /** The attribute name at a given BBS message index. */
    public static String attributeAt(int index) {
        return ATTRIBUTES.get(index);
    }
}
