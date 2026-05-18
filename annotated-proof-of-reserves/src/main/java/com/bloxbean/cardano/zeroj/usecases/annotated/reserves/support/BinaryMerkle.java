package com.bloxbean.cardano.zeroj.usecases.annotated.reserves.support;

import java.math.BigInteger;
import java.util.List;

public final class BinaryMerkle {
    private BinaryMerkle() {
    }

    public static BigInteger root(BigInteger leaf, List<BigInteger> siblings, List<BigInteger> pathBits, BigInteger prime) {
        if (siblings.size() != pathBits.size()) {
            throw new IllegalArgumentException("siblings and pathBits must have equal length");
        }

        var current = leaf;
        for (int i = 0; i < siblings.size(); i++) {
            var sibling = siblings.get(i);
            var pathBit = pathBits.get(i);
            current = BigInteger.ZERO.equals(pathBit)
                    ? OffchainMiMC.hash(current, sibling, prime)
                    : OffchainMiMC.hash(sibling, current, prime);
        }
        return current;
    }
}
