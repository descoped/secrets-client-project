package io.descoped.secrets.provider.safe;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
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
 * <p>The file is parsed as bytes. That is safe for UTF-8, because the bytes of {@code =}, {@code #}, CR and LF never
 * occur inside a multi-byte UTF-8 sequence.
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
     * {@value #LATEST}. The file is replaced atomically by a new file that only its owner can read and write (where
     * the file system supports POSIX permissions); comments, blank lines, line endings and the order of the other
     * lines are kept.
     *
     * @throws IllegalArgumentException if the name is not a valid key, or the value contains CR or LF
     */
    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        Objects.requireNonNull(secretName, "secretName");
        Objects.requireNonNull(secretValue, "secretValue");
        checkKey(secretName);
        for (byte b : secretValue) {
            if (b == '\n' || b == '\r') {
                throw new IllegalArgumentException("The value of secret '" + secretName
                        + "' contains a line break, which this file format cannot hold");
            }
        }
        byte[] value = secretValue.clone();
        lock.writeLock().lock();
        try {
            checkOpen();
            writeFile(secretName, value);
            byte[] previous = secrets.put(secretName, value);
            if (previous != null) {
                Arrays.fill(previous, (byte) 0);
            }
            return LATEST;
        } catch (RuntimeException e) {
            Arrays.fill(value, (byte) 0);
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

    private static void checkKey(String key) {
        if (key.isBlank() || !key.equals(key.strip()) || key.startsWith("#")
                || key.indexOf('=') >= 0 || key.indexOf('\n') >= 0 || key.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("Invalid secret name '" + key + "': it must be non-blank, without"
                    + " surrounding whitespace, '=' or line breaks, and not start with '#'");
        }
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
     * line is appended. Every other byte of the file is copied as is.
     */
    private void writeFile(String key, byte[] value) {
        byte[] content = readFile(path);
        ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + key.length() + value.length + 2);
        byte[] result = null;
        try {
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            boolean[] replaced = {false};
            int[] copied = {0};
            parse(content, new LineVisitor() {
                @Override
                public void entry(String k, byte[] v, int line) {
                    Arrays.fill(v, (byte) 0);
                }

                @Override
                public void line(int start, int contentEnd, int end, String k) {
                    if (key.equals(k) && !replaced[0]) {
                        out.write(content, copied[0], start - copied[0]);
                        out.writeBytes(keyBytes);
                        out.write('=');
                        out.writeBytes(value);
                        out.write(content, contentEnd, end - contentEnd);
                        copied[0] = end;
                        replaced[0] = true;
                    }
                }
            });
            out.write(content, copied[0], content.length - copied[0]);
            if (!replaced[0]) {
                if (content.length > 0 && content[content.length - 1] != '\n') {
                    out.writeBytes(lineSeparator(content));
                }
                out.writeBytes(keyBytes);
                out.write('=');
                out.writeBytes(value);
                out.writeBytes(lineSeparator(content));
            }
            result = out.toByteArray();
            replaceFile(result);
        } finally {
            Arrays.fill(content, (byte) 0);
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
            wipe(out);
        }
    }

    private void replaceFile(byte[] content) {
        Path dir = path.toAbsolutePath().getParent();
        if (!Files.isWritable(path) || dir == null || !Files.isWritable(dir)) {
            throw new SecretManagerException("The secrets file " + path + " is not writable");
        }
        Path tmp = null;
        try {
            tmp = Files.createTempFile(dir, "." + path.getFileName(), ".tmp", ownerOnly(dir));
            try (FileChannel channel = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(content);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            try {
                Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
            }
            tmp = null;
        } catch (IOException e) {
            throw new SecretManagerException("Cannot write the secrets file " + path, e);
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

    private static void wipe(ByteArrayOutputStream out) {
        // ByteArrayOutputStream cannot be cleared in place; overwrite what it holds with zeros of the same length.
        int size = out.size();
        out.reset();
        out.writeBytes(new byte[size]);
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
            int end = pos;
            while (end < content.length && content[end] != '\n') {
                end++;
            }
            int contentEnd = end > pos && content[end - 1] == '\r' ? end - 1 : end;
            int next = end < content.length ? end + 1 : end;

            int first = pos;
            while (first < contentEnd && (content[first] == ' ' || content[first] == '\t')) {
                first++;
            }
            String key = null;
            if (first < contentEnd && content[first] != '#') {
                int eq = first;
                while (eq < contentEnd && content[eq] != '=') {
                    eq++;
                }
                if (eq == contentEnd) {
                    throw new SecretManagerException(path + ": line " + lineNumber + " has no '='");
                }
                key = new String(content, first, eq - first, StandardCharsets.UTF_8).strip();
                if (key.isEmpty()) {
                    throw new SecretManagerException(path + ": line " + lineNumber + " has an empty key");
                }
                visitor.entry(key, Arrays.copyOfRange(content, eq + 1, contentEnd), lineNumber);
            }
            visitor.line(pos, contentEnd, next, key);
            pos = next;
        }
    }

    private static boolean startsWith(byte[] content, byte[] prefix) {
        return content.length >= prefix.length && Arrays.equals(content, 0, prefix.length, prefix, 0, prefix.length);
    }
}
