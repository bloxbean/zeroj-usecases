package com.bloxbean.cardano.zeroj.usecases.pedersen;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Web UI for the three Pedersen commitment demos (ADR-0006): confidential points, a committed
 * credential gate, and solvency with hidden liabilities, on Yaci DevKit.
 */
@SpringBootApplication
public class PedersenCommitmentsApplication {

    public static void main(String[] args) {
        SpringApplication.run(PedersenCommitmentsApplication.class, args);
    }
}
