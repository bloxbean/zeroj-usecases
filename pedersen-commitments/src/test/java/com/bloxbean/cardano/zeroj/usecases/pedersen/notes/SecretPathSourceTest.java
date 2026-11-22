package com.bloxbean.cardano.zeroj.usecases.pedersen.notes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * ADR-0007 N-I6 (ZeroJ ADR-0055 M3 criterion (b)): main code never calls ZeroJ's variable-time
 * {@code scalarMul} (meant for public scalars). Secret limbs, ephemerals and openings go through
 * {@code ElGamal.encryptWithOpening}, {@code ConfidentialNotes.seal} and the scanner, which use
 * the blinded best-effort schedule. The blinded {@code scalarMulSecretBlindedBestEffort} is not
 * matched.
 */
class SecretPathSourceTest {

    private static final Pattern VARIABLE_TIME = Pattern.compile("\\.scalarMul\\(");

    @Test
    @DisplayName("No variable-time scalarMul in main sources")
    void noVariableTimeScalarMulInMain() throws IOException {
        List<String> offenders;
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            offenders = files.filter(p -> p.toString().endsWith(".java")).flatMap(p -> {
                try {
                    List<String> lines = Files.readAllLines(p);
                    return IntStream.range(0, lines.size())
                            .filter(i -> VARIABLE_TIME.matcher(lines.get(i)).find())
                            .mapToObj(i -> p + ":" + (i + 1));
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }).toList();
        }
        assertEquals(List.of(), offenders, "variable-time scalarMul in main code");
    }
}
