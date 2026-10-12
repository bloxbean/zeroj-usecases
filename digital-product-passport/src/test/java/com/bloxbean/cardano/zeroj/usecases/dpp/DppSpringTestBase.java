package com.bloxbean.cardano.zeroj.usecases.dpp;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Path;

/**
 * The application context the Spring tests share: an in-memory database and a demo data
 * directory under {@code build/} (keys, deployment state, circuit keys, registry), so no test
 * touches {@code ./data}. The chain backend points at a closed local port, so no test reaches a
 * running DevKit; chain reads fail, and the readers fail closed.
 */
@SpringBootTest
@AutoConfigureMockMvc
public abstract class DppSpringTestBase {

    protected static final Path DATA = Path.of("build", "dpp-spring-test-data");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("dpp.data-dir", DATA::toString);
        registry.add("dpp.registry-path", () -> DATA.resolve("registry").toString());
        registry.add("spring.datasource.url", () -> "jdbc:h2:mem:dpp-test;DB_CLOSE_DELAY=-1");
        registry.add("cardano.yaci.base-url", () -> "http://127.0.0.1:9/api/v1/");
        registry.add("cardano.yaci.admin-url", () -> "http://127.0.0.1:9");
    }
}
