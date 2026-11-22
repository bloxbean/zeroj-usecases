package com.bloxbean.cardano.zeroj.usecases.reserves.service;

import com.bloxbean.cardano.zeroj.usecases.reserves.model.AccountEntity;
import com.bloxbean.cardano.zeroj.usecases.reserves.verify.CustomerCheck;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The attested snapshot survives a restart (review R-4): restored inclusion data still recomputes
 * the attested root, and a tampered, truncated or wrong-depth file fails closed.
 */
class AttestedSnapshotStoreTest {

    @TempDir
    Path dir;

    private static MerkleSumTreeService.Snapshot snapshot() {
        return MerkleSumTreeService.build(List.of(new AccountEntity("alice", "Alice", 500_000_000L),
                new AccountEntity("bob", "Bob", 1_200_000_000L), new AccountEntity("charlie", "Charlie", 300_000_000L)),
                3, new SecureRandom());
    }

    @Test
    void restoredSnapshotStillMatchesTheAttestedRoot() throws Exception {
        assertNull(AttestedSnapshotStore.read(dir, 3));
        var s = snapshot();
        AttestedSnapshotStore.write(dir, s, 7);
        Path file = AttestedSnapshotStore.path(dir);
        if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        }
        var restored = AttestedSnapshotStore.read(dir, 3);
        assertEquals(s.root(), restored.root());
        assertEquals(s.totalLiabilities(), restored.totalLiabilities());
        var p = restored.inclusionProof("bob");
        assertEquals(s.root(), CustomerCheck.recomputeRoot(new CustomerCheck.Inclusion("bob", p.salt(), p.balance(),
                p.leafIndex(), Arrays.asList(p.siblings()))));
    }

    @Test
    void tamperedOrMismatchedFileFailsClosed() throws Exception {
        var s = snapshot();
        AttestedSnapshotStore.write(dir, s, 7);
        Path file = AttestedSnapshotStore.path(dir);
        String json = Files.readString(file, StandardCharsets.UTF_8);

        assertThrows(IllegalStateException.class, () -> AttestedSnapshotStore.read(dir, 4));

        Files.writeString(file, json.replace(s.salts()[0].toString(), s.salts()[0].flipBit(0).toString()));
        assertThrows(IllegalStateException.class, () -> AttestedSnapshotStore.read(dir, 3));

        Files.writeString(file, json.replace(s.leafBalances()[1].toString(), "1"));
        assertThrows(IllegalStateException.class, () -> AttestedSnapshotStore.read(dir, 3));

        Files.writeString(file, json.substring(0, json.length() / 2));
        assertThrows(IllegalStateException.class, () -> AttestedSnapshotStore.read(dir, 3));
    }
}
