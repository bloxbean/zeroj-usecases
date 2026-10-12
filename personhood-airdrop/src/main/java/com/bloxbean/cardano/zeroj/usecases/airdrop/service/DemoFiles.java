package com.bloxbean.cardano.zeroj.usecases.airdrop.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * Durable demo state files (ADR-0009 D11 storage rules): every write goes to an owner-only
 * temporary file in the same directory, is forced to disk, and is renamed over the target
 * atomically, so a reader sees either the old or the new content, never a partial one. The
 * parent directory is then forced too, so the rename itself survives a crash: a write that has
 * returned (an issuance record, a paid-nullifier reservation, a key) is durable.
 *
 * <p>Reads fail closed: a file that exists but cannot be parsed, or has the wrong version, is
 * an error, never "no state".
 */
final class DemoFiles {

    static final int VERSION = 1;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> OWNER_ONLY_DIR = PosixFilePermissions.fromString("rwx------");

    private DemoFiles() {}

    static ObjectNode object() {
        ObjectNode node = JSON.createObjectNode();
        node.put("version", VERSION);
        return node;
    }

    /** Creates {@code dir} (owner-only where the file system supports it) if it is missing. */
    static void ensureDirectory(Path dir) {
        try {
            if (!Files.isDirectory(dir)) {
                try {
                    Files.createDirectories(dir, posix(dir) ? new FileAttribute<?>[]{
                            PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIR)} : new FileAttribute<?>[0]);
                } catch (FileAlreadyExistsException ignored) {
                    // created concurrently
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("cannot create the demo data directory " + dir, e);
        }
    }

    /** Writes {@code node} to {@code target} atomically, with owner-only permissions. */
    static void writeAtomic(Path target, JsonNode node) {
        Path dir = target.toAbsolutePath().getParent();
        ensureDirectory(dir);
        Path temp = null;
        try {
            byte[] bytes = JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(node);
            temp = posix(dir)
                    ? Files.createTempFile(dir, "." + target.getFileName(), ".tmp",
                            PosixFilePermissions.asFileAttribute(OWNER_ONLY))
                    : Files.createTempFile(dir, "." + target.getFileName(), ".tmp");
            try (FileChannel channel = FileChannel.open(temp, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            if (!posix(dir)) {
                var file = temp.toFile();
                file.setReadable(false, false);
                file.setWritable(false, false);
                file.setReadable(true, true);
                file.setWritable(true, true);
            }
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            temp = null;
            syncDirectory(dir);
        } catch (IOException e) {
            throw new IllegalStateException("cannot write " + target, e);
        } finally {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                    // best effort
                }
            }
        }
    }

    /**
     * Reads a state file written by {@link #writeAtomic}. Returns {@code null} only when the file
     * does not exist; an unreadable, malformed or wrong-version file throws.
     */
    static JsonNode read(Path file) {
        if (!Files.exists(file)) {
            return null;
        }
        try {
            JsonNode node = JSON.readTree(Files.readString(file, StandardCharsets.UTF_8));
            if (node == null || !node.isObject() || node.path("version").asInt(-1) != VERSION) {
                throw new IllegalStateException(file + " is corrupt or has an unknown version");
            }
            return node;
        } catch (IOException e) {
            throw new IllegalStateException(file + " is unreadable or corrupt", e);
        }
    }

    /** A required text field; a missing or non-text field means the file is corrupt. */
    static String text(JsonNode node, String field, Path file) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.asText().isEmpty()) {
            throw new IllegalStateException(file + " is corrupt: missing " + field);
        }
        return value.asText();
    }

    /**
     * Forces the directory entry (the rename) to disk. On POSIX file systems a failure is an
     * error: the caller must not treat the write as durable. Elsewhere (no directory handles,
     * e.g. Windows) it is skipped.
     */
    private static void syncDirectory(Path dir) throws IOException {
        if (!posix(dir)) {
            return;
        }
        try (FileChannel channel = FileChannel.open(dir, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private static boolean posix(Path dir) {
        return dir.getFileSystem().supportedFileAttributeViews().contains("posix");
    }
}
