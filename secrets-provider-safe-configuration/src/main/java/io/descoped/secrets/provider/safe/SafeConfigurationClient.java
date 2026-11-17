package io.descoped.secrets.provider.safe;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Secrets in a local file, one {@code key=value} per line, read once when the client is created. See
 * {@link SafeConfigurationClientInitializer} for the format. Values stay bytes from the file to the caller: they are
 * never decoded to strings, and every copy the client holds is wiped when it is replaced and on {@link #close()}.
 *
 * <p>The file is parsed as bytes. That is safe for UTF-8, because the bytes of {@code =}, {@code #}, CR, LF and the
 * blanks (space, tab, form feed, vertical tab) never occur inside a multi-byte UTF-8 sequence.
 */
final class SafeConfigurationClient implements SecretManagerClient {

    /**
     * The only version this provider has.
     */
    static final String LATEST = "latest";

    private static final byte[] UTF8_BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    private final Path path;
    private final Map<String, byte[]> secrets = new HashMap<>();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private boolean closed;

    SafeConfigurationClient(Path path) {
        this.path = Objects.requireNonNull(path, "path");
        byte[] content = readFile(path);
        try {
            parse(content, (key, value, line) -> {
                if (secrets.containsKey(key)) {
                    Arrays.fill(value, (byte) 0);
                    throw new SecretManagerException(path + ": line " + line + ": duplicate key '" + key + "'");
                }
                secrets.put(key, value);
            });
        } catch (RuntimeException e) {
            wipeAll();
            throw e;
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        Objects.requireNonNull(secretName, "secretName");
        lock.readLock().lock();
        try {
            checkOpen();
            byte[] value = secrets.get(secretName);
            if (value == null || !(secretVersion == null || LATEST.equals(secretVersion))) {
                throw new SecretNotFoundException(secretName, secretVersion);
            }
            return value.clone();
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Writes the value to the file, replacing the line of an existing key in place or appending a line, and returns
     * {@value #LATEST}. The file (the target of a symbolic link) is replaced atomically by a new file that only its
     * owner can read and write (where the file system supports POSIX permissions); comments, blank lines, line
     * endings and the order of the other lines are kept. A file system that cannot move atomically is an error.
     *
     * @throws SecretManagerException if the name is not a valid key, the value contains CR or LF, or the file cannot
     *                                be written
     */
    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        Objects.requireNonNull(secretName, "secretName");
        Objects.requireNonNull(secretValue, "secretValue");
        lock.writeLock().lock();
        byte[] value = null;
        try {
            checkOpen();
            byte[] keyBytes = checkKey(secretName);
            for (byte b : secretValue) {
                if (b == '\n' || b == '\r') {
                    throw new SecretManagerException("The value of secret '" + secretName
                            + "' contains a line break, which this file format cannot hold");
                }
            }
            value = secretValue.clone();
            writeFile(secretName, keyBytes, value);
            byte[] previous = secrets.put(secretName, value);
            if (previous != null) {
                Arrays.fill(previous, (byte) 0);
            }
            return LATEST;
        } catch (RuntimeException e) {
            if (value != null) {
                Arrays.fill(value, (byte) 0);
            }
            throw e;
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            if (!closed) {
                closed = true;
                wipeAll();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("Client is closed");
        }
    }

    private void wipeAll() {
        secrets.values().forEach(v -> Arrays.fill(v, (byte) 0));
        secrets.clear();
    }

    /**
     * Checks that the name can be written as a key that reads back as the same name, and returns it as UTF-8.
     */
    private static byte[] checkKey(String key) {
        byte[] bytes;
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(key));
            bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
        } catch (CharacterCodingException e) {
            throw invalidKey(key);
        }
        if (bytes.length == 0 || isBlank(bytes[0]) || isBlank(bytes[bytes.length - 1]) || bytes[0] == '#') {
            throw invalidKey(key);
        }
        for (byte b : bytes) {
            if (b == '=' || b == '\n' || b == '\r') {
                throw invalidKey(key);
            }
        }
        return bytes;
    }

    private static SecretManagerException invalidKey(String key) {
        return new SecretManagerException("Invalid secret name '" + key + "': it must be non-empty valid UTF-16,"
                + " without surrounding blanks, '=' or line breaks, and not start with '#'");
    }

    /**
     * Space, tab, form feed and vertical tab: the blanks around keys and before comments.
     */
    private static boolean isBlank(byte b) {
        return b == ' ' || b == '\t' || b == '\f' || b == 0x0B;
    }

    private static byte[] readFile(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read the secrets file " + path, e);
        }
    }

    /**
     * Rewrites the file with {@code key=value}: the line holding the key is replaced, keeping its line ending, or a
     * line is appended. Every other byte of the file is copied as is. The new content is built in one array of
     * exactly the right size, so no copy of the file is left behind unwiped.
     */
    private void writeFile(String key, byte[] keyBytes, byte[] value) {
        Path target = resolveTarget();
        byte[] content = readFile(target);
        byte[] result = null;
        try {
            int[] keyLine = {-1, -1, -1};
            parse(content, new LineVisitor() {
                @Override
                public void entry(String k, byte[] v, int line) {
                    Arrays.fill(v, (byte) 0);
                }

                @Override
                public void line(int start, int contentEnd, int end, String k) {
                    if (key.equals(k) && keyLine[0] < 0) {
                        keyLine[0] = start;
                        keyLine[1] = contentEnd;
                        keyLine[2] = end;
                    }
                }
            });
            int entryLength = keyBytes.length + 1 + value.length;
            if (keyLine[0] >= 0) {
                result = new byte[content.length - (keyLine[1] - keyLine[0]) + entryLength];
                int pos = put(result, 0, content, 0, keyLine[0]);
                pos = putEntry(result, pos, keyBytes, value);
                put(result, pos, content, keyLine[1], content.length - keyLine[1]);
            } else {
                byte[] separator = lineSeparator(content);
                boolean needsBreak = content.length > 0 && content[content.length - 1] != '\n';
                result = new byte[content.length + (needsBreak ? separator.length : 0) + entryLength
                        + separator.length];
                int pos = put(result, 0, content, 0, content.length);
                if (needsBreak) {
                    pos = put(result, pos, separator, 0, separator.length);
                }
                pos = putEntry(result, pos, keyBytes, value);
                put(result, pos, separator, 0, separator.length);
            }
            replaceFile(target, result);
        } finally {
            Arrays.fill(content, (byte) 0);
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
        }
    }

    private static int put(byte[] dest, int pos, byte[] src, int from, int length) {
        System.arraycopy(src, from, dest, pos, length);
        return pos + length;
    }

    private static int putEntry(byte[] dest, int pos, byte[] keyBytes, byte[] value) {
        pos = put(dest, pos, keyBytes, 0, keyBytes.length);
        dest[pos++] = '=';
        return put(dest, pos, value, 0, value.length);
    }

    /**
     * The file to replace: the target of a symbolic link, so that the link is kept.
     */
    private Path resolveTarget() {
        try {
            return path.toRealPath();
        } catch (IOException e) {
            throw new SecretManagerException("Cannot resolve the secrets file " + path, e);
        }
    }

    private static void replaceFile(Path target, byte[] content) {
        Path dir = target.getParent();
        if (!Files.isWritable(target) || dir == null || !Files.isWritable(dir)) {
            throw new SecretManagerException("The secrets file " + target + " is not writable");
        }
        Path tmp = null;
        try {
            tmp = Files.createTempFile(dir, "." + target.getFileName(), ".tmp", ownerOnly(dir));
            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(content);
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
                try {
                    Files.deleteIfExists(tmp);
                } catch (IOException ignored) {
                    // The write already failed; that is the error reported.
                }
            }
        }
    }

    private static FileAttribute<?>[] ownerOnly(Path dir) {
        if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return new FileAttribute<?>[]{PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))};
        }
        return new FileAttribute<?>[0];
    }

    /**
     * The line separator the file already uses (that of its first line), LF if it has none.
     */
    private static byte[] lineSeparator(byte[] content) {
        for (int i = 0; i < content.length; i++) {
            if (content[i] == '\n') {
                return i > 0 && content[i - 1] == '\r' ? new byte[]{'\r', '\n'} : new byte[]{'\n'};
            }
        }
        return new byte[]{'\n'};
    }

    /**
     * Receives what {@link #parse(byte[], LineVisitor)} finds.
     */
    interface LineVisitor {

        /**
         * An entry. {@code value} is a new array that the visitor owns.
         */
        void entry(String key, byte[] value, int line);

        /**
         * Every line, with the key it holds or {@code null}: bytes {@code [start, contentEnd)} without the line
         * ending, {@code [start, end)} with it.
         */
        default void line(int start, int contentEnd, int end, String key) {
        }
    }

    /**
     * Parses the format described in {@link SafeConfigurationClientInitializer}. Errors name the file and the line,
     * never a value.
     */
    void parse(byte[] content, LineVisitor visitor) {
        int pos = startsWith(content, UTF8_BOM) ? UTF8_BOM.length : 0;
        int lineNumber = 0;
        while (pos < content.length) {
            lineNumber++;
            int end = indexOf(content, (byte) '\n', pos, content.length);
            int contentEnd = end > pos && content[end - 1] == '\r' ? end - 1 : end;
            int next = end < content.length ? end + 1 : end;
            String key = entry(content, pos, contentEnd, lineNumber, visitor);
            visitor.line(pos, contentEnd, next, key);
            pos = next;
        }
    }

    /**
     * The entry on bytes {@code [start, end)}, line {@code lineNumber}, handed to the visitor. Returns its key, or
     * {@code null} for a blank or comment line.
     */
    private String entry(byte[] content, int start, int end, int lineNumber, LineVisitor visitor) {
        int first = start;
        while (first < end && isBlank(content[first])) {
            first++;
        }
        if (first == end || content[first] == '#') {
            return null;
        }
        int eq = indexOf(content, (byte) '=', first, end);
        if (eq == end) {
            throw new SecretManagerException(path + ": line " + lineNumber + " has no '='");
        }
        int keyEnd = eq;
        while (keyEnd > first && isBlank(content[keyEnd - 1])) {
            keyEnd--;
        }
        if (keyEnd == first) {
            throw new SecretManagerException(path + ": line " + lineNumber + " has an empty key");
        }
        String key = new String(content, first, keyEnd - first, StandardCharsets.UTF_8);
        visitor.entry(key, Arrays.copyOfRange(content, eq + 1, end), lineNumber);
        return key;
    }

    /**
     * The index of the first {@code b} in {@code [from, to)}, or {@code to}.
     */
    private static int indexOf(byte[] content, byte b, int from, int to) {
        int i = from;
        while (i < to && content[i] != b) {
            i++;
        }
        return i;
    }

    private static boolean startsWith(byte[] content, byte[] prefix) {
        return content.length >= prefix.length && Arrays.equals(content, 0, prefix.length, prefix, 0, prefix.length);
    }
}
