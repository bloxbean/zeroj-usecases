package com.bloxbean.cardano.zeroj.usecases.nft;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * ZeroJ NFT Ownership Demo — Private token-gated access on Cardano.
 *
 * <p>Proves NFT ownership via ZK proof without revealing the holder's wallet address.
 * Supports Yaci DevKit (local) and Preprod (testnet) networks.</p>
 *
 * <p>Run: {@code java -jar nft-ownership.jar}</p>
 */
@SpringBootApplication
public class NftOwnershipApplication {

    public static void main(String[] args) {
        SpringApplication.run(NftOwnershipApplication.class, args);
    }
}
