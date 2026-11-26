package io.descoped.secrets.provider.safe;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.function.Consumer;

/**
 * The secrets file, handled in guarded memory only: read with a {@link FileChannel} straight into a {@link Secret},
 * parsed in place, and rewritten from a {@link Secret}. No byte of the file is ever copied to the Java heap, except
 * the keys, which are not secret.
 *
 * <p>The file is parsed as bytes. That is safe for UTF-8, because the bytes of {@code =}, {@code #}, CR, LF and the
 * blanks (space, tab, form feed, vertical tab) never occur inside a multi-byte UTF-8 sequence.
 */
final class SecretsFile {

    private static final byte[] UTF8_BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
    private static final byte[] LF = {'\n'};
    private static final byte[] CRLF = {'\r', '\n'};

    private SecretsFile() {
    }

    /**
     * A line of the file: bytes {@code [start, contentEnd)} without the line ending, {@code [start, end)} with it.
     * For an entry, {@code key} is its key and the value is {@code [valueStart, contentEnd)}; for a blank or comment
     * line, {@code key} is {@code null}.
     */
    record Line(int number, long start, long contentEnd, long end, String key, long valueStart) {

        long valueLength() {
            return contentEnd - valueStart;
        }
    }

    /**
     * Reads the whole of {@code file} into a new secret.
     *
     * @throws SecretManagerException if the file cannot be read, or changes while it is read
     */
    static Secret read(Path file, SecretMemory memory) {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            long size = channel.size();
            if (size > Integer.MAX_VALUE) {
                throw new SecretManagerException("The secrets file " + file + " is too large");
            }
            Secret content = memory.allocate(size, segment -> fill(channel, segment, file));
            if (channel.size() != size) {
                content.close();
                throw changed(file);
            }
            return content;
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read the secrets file " + file, e);
        }
    }

    private static void fill(FileChannel channel, MemorySegment segment, Path file) {
        ByteBuffer buffer = segment.asByteBuffer();
        try {
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) {
                    throw changed(file);
                }
            }
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read the secrets file " + file, e);
        }
    }

    private static SecretManagerException changed(Path file) {
        return new SecretManagerException("The secrets file " + file + " changed while it was read");
    }

    /**
     * Parses the format described in {@link SafeConfigurationClientInitializer}, handing every line to
     * {@code visitor}. Errors name the file and the line, never a value.
     */
    static void parse(MemorySegment content, Path file, Consumer<Line> visitor) {
        long size = content.byteSize();
        long pos = startsWithBom(content) ? UTF8_BOM.length : 0;
        int number = 0;
        while (pos < size) {
            number++;
            long end = indexOf(content, (byte) '\n', pos, size);
            long contentEnd = end > pos && byteAt(content, end - 1) == '\r' ? end - 1 : end;
            long next = end < size ? end + 1 : end;
            visitor.accept(line(content, file, number, pos, contentEnd, next));
            pos = next;
        }
    }

    private static Line line(MemorySegment content, Path file, int number, long start, long contentEnd, long end) {
        long first = start;
        while (first < contentEnd && isBlank(byteAt(content, first))) {
            first++;
        }
        if (first == contentEnd || byteAt(content, first) == '#') {
            return new Line(number, start, contentEnd, end, null, contentEnd);
        }
        long eq = indexOf(content, (byte) '=', first, contentEnd);
        if (eq == contentEnd) {
            throw new SecretManagerException(file + ": line " + number + " has no '='");
        }
        long keyEnd = eq;
        while (keyEnd > first && isBlank(byteAt(content, keyEnd - 1))) {
            keyEnd--;
        }
        if (keyEnd == first) {
            throw new SecretManagerException(file + ": line " + number + " has an empty key");
        }
        // The key is not secret: it may be on the heap.
        String key = new String(content.asSlice(first, keyEnd - first).toArray(ValueLayout.JAVA_BYTE),
                StandardCharsets.UTF_8);
        return new Line(number, start, contentEnd, end, key, eq + 1);
    }

    /**
     * The file {@code content} with the entry {@code key=value}: the first line holding the key is replaced, keeping
     * its line ending, or a line is appended with the line ending the file already uses. Every other byte is kept.
     * Built in a new secret of exactly the right size.
     */
    static Secret withEntry(SecretMemory memory, MemorySegment content, Path file, String key, byte[] keyBytes,
                            MemorySegment value) {
        Line[] found = new Line[1];
        parse(content, file, line -> {
            if (found[0] == null && key.equals(line.key())) {
                found[0] = line;
            }
        });
        long size = content.byteSize();
        long entryLength = keyBytes.length + 1L + value.byteSize();
        Line line = found[0];
        if (line != null) {
            long tail = size - line.contentEnd();
            return memory.allocate(line.start() + entryLength + tail, out -> {
                long pos = put(out, 0, content, 0, line.start());
                pos = putEntry(out, pos, keyBytes, value);
                put(out, pos, content, line.contentEnd(), tail);
            });
        }
        byte[] separator = lineSeparator(content);
        boolean needsBreak = size > 0 && byteAt(content, size - 1) != '\n';
        long length = size + (needsBreak ? separator.length : 0) + entryLength + separator.length;
        return memory.allocate(length, out -> {
            long pos = put(out, 0, content, 0, size);
            if (needsBreak) {
                pos = put(out, pos, separator);
            }
            pos = putEntry(out, pos, keyBytes, value);
            put(out, pos, separator);
        });
    }

    private static long put(MemorySegment out, long pos, MemorySegment from, long offset, long length) {
        MemorySegment.copy(from, offset, out, pos, length);
        return pos + length;
    }

    /** Copies bytes that are not secret (a key, a line ending). */
    private static long put(MemorySegment out, long pos, byte[] bytes) {
        MemorySegment.copy(bytes, 0, out, ValueLayout.JAVA_BYTE, pos, bytes.length);
        return pos + bytes.length;
    }

    private static long putEntry(MemorySegment out, long pos, byte[] keyBytes, MemorySegment value) {
        pos = put(out, pos, keyBytes);
        out.set(ValueLayout.JAVA_BYTE, pos++, (byte) '=');
        return put(out, pos, value, 0, value.byteSize());
    }

    /** The line separator the file already uses (that of its first line), LF if it has none. */
    private static byte[] lineSeparator(MemorySegment content) {
        long lf = indexOf(content, (byte) '\n', 0, content.byteSize());
        if (lf == content.byteSize()) {
            return LF;
        }
        return lf > 0 && byteAt(content, lf - 1) == '\r' ? CRLF : LF;
    }

    /** Whether {@code value} holds CR or LF, which a line cannot hold. */
    static boolean hasLineBreak(MemorySegment value) {
        long size = value.byteSize();
        return indexOf(value, (byte) '\n', 0, size) < size || indexOf(value, (byte) '\r', 0, size) < size;
    }

    /**
     * Replaces {@code target} atomically by a new file holding {@code content}, readable and writable by its owner
     * only (where the file system supports POSIX permissions).
     */
    static void replace(Path target, MemorySegment content) {
        Path dir = target.getParent();
        if (!Files.isWritable(target) || dir == null || !Files.isWritable(dir)) {
            throw new SecretManagerException("The secrets file " + target + " is not writable");
        }
        Path tmp = null;
        try {
            tmp = Files.createTempFile(dir, "." + target.getFileName(), ".tmp", ownerOnly(dir));
            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = content.asByteBuffer();
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            tmp = null;
        } catch (IOException e) {
            throw new SecretManagerException("Cannot write the secrets file " + target, e);
        } finally {
            if (tmp != null) {
                deleteQuietly(tmp);
            }
        }
    }

    private static void deleteQuietly(Path file) {
        try {
            Files.deleteIfExists(file);
        } catch (IOException _) {
            // The write already failed; that is the error reported.
        }
    }

    private static FileAttribute<?>[] ownerOnly(Path dir) {
        if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return new FileAttribute<?>[]{
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))};
        }
        return new FileAttribute<?>[0];
    }

    /** Space, tab, form feed and vertical tab: the blanks around keys and before comments. */
    static boolean isBlank(byte b) {
        return b == ' ' || b == '\t' || b == '\f' || b == 0x0B;
    }

    private static byte byteAt(MemorySegment content, long index) {
        return content.get(ValueLayout.JAVA_BYTE, index);
    }

    /** The index of the first {@code b} in {@code [from, to)}, or {@code to}. */
    private static long indexOf(MemorySegment content, byte b, long from, long to) {
        long i = from;
        while (i < to && byteAt(content, i) != b) {
            i++;
        }
        return i;
    }

    private static boolean startsWithBom(MemorySegment content) {
        if (content.byteSize() < UTF8_BOM.length) {
            return false;
        }
        for (int i = 0; i < UTF8_BOM.length; i++) {
            if (byteAt(content, i) != UTF8_BOM[i]) {
                return false;
            }
        }
        return true;
    }
}
