package com.bloxbean.cardano.zeroj.usecases.reserves.config;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/** Atomic, owner-only files in the demo data directory (ADR-0009 D11). */
public final class DemoFiles {

    private static final Set<PosixFilePermission> OWNER_RW = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> OWNER_RWX = PosixFilePermissions.fromString("rwx------");

    private DemoFiles() {}

    /**
     * Writes {@code content} to a temporary file created owner-only in the target's directory,
     * forces it to disk, renames it over {@code target} atomically, and forces the directory so
     * the rename itself is durable. A crash leaves either the old file or the new one, never a
     * partial file.
     */
    public static void writeAtomically(Path target, byte[] content) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        createDirectories(dir);
        Path tmp = createOwnerOnly(dir, target.getFileName().toString());
        try {
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buf = ByteBuffer.wrap(content);
                while (buf.hasRemaining()) ch.write(buf);
                ch.force(true);
            }
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            try (FileChannel d = FileChannel.open(dir, StandardOpenOption.READ)) {
                d.force(true);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private static Path createOwnerOnly(Path dir, String name) throws IOException {
        try {
            return Files.createTempFile(dir, "." + name + ".", ".tmp", PosixFilePermissions.asFileAttribute(OWNER_RW));
        } catch (UnsupportedOperationException e) {
            Path tmp = Files.createTempFile(dir, "." + name + ".", ".tmp");
            var file = tmp.toFile();
            if (!(file.setReadable(false, false) && file.setReadable(true, true)
                    && file.setWritable(false, false) && file.setWritable(true, true))) {
                Files.deleteIfExists(tmp);
                throw new IOException("cannot restrict " + tmp + " to its owner");
            }
            return tmp;
        }
    }

    private static void createDirectories(Path dir) throws IOException {
        if (Files.isDirectory(dir)) return;
        try {
            FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(OWNER_RWX);
            Files.createDirectories(dir, attr);
        } catch (UnsupportedOperationException e) {
            Files.createDirectories(dir);
        } catch (FileAlreadyExistsException ignored) {
            // created concurrently
        }
    }
}
