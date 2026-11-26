package io.descoped.secrets.provider.safe;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;

/**
 * Secrets in a local file, one {@code key=value} per line, read once when the client is created. See
 * {@link SafeConfigurationClientInitializer} for the format. The file is read, parsed and rewritten in guarded memory
 * ({@link SecretsFile}), and each value is held in a {@link Secret} of its own: no value is ever on the Java heap,
 * except the copies {@link #readBytes(String, String)} and the array {@code addVersion} return or take, which belong
 * to the caller.
 */
final class SafeConfigurationClient implements SecretManagerClient {

    /**
     * The only version this provider has.
     */
    static final String LATEST = "latest";

    private static final String SECRET_NAME = "secretName";
    private static final String SECRET_VALUE = "secretValue";

    private final Path path;
    private final SecretMemory memory;
    private final Map<String, Secret> secrets = new HashMap<>();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private volatile boolean closed;

    SafeConfigurationClient(Path path, Map<String, String> configuration) {
        this.path = Objects.requireNonNull(path, "path");
        this.memory = SecretMemory.create(configuration);
        try (Secret content = SecretsFile.read(path, memory)) {
            content.withSegment(segment -> {
                SecretsFile.parse(segment, path, line -> load(segment, line));
                return null;
            });
        } catch (RuntimeException e) {
            // Closes every value loaded so far.
            memory.close();
            throw e;
        }
    }

    private void load(MemorySegment content, SecretsFile.Line line) {
        if (line.key() == null) {
            return;
        }
        if (secrets.containsKey(line.key())) {
            throw new SecretManagerException(path + ": line " + line.number() + ": duplicate key '" + line.key()
                    + "'");
        }
        secrets.put(line.key(), memory.allocate(line.valueLength(),
                value -> MemorySegment.copy(content, line.valueStart(), value, 0, line.valueLength())));
    }

    @Override
    public Secret read(String secretName, String secretVersion) {
        return withStored(secretName, secretVersion, stored -> memory.allocate(stored.length(),
                copy -> stored.withSegment(value -> {
                    MemorySegment.copy(value, 0, copy, 0, value.byteSize());
                    return null;
                })));
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        return withStored(secretName, secretVersion,
                stored -> stored.withSegment(value -> value.toArray(ValueLayout.JAVA_BYTE)));
    }

    private <R> R withStored(String secretName, String secretVersion, Function<Secret, R> action) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        lock.readLock().lock();
        try {
            checkOpen();
            Secret stored = secrets.get(secretName);
            if (stored == null || !(secretVersion == null || LATEST.equals(secretVersion))) {
                throw new SecretNotFoundException(secretName, secretVersion);
            }
            return action.apply(stored);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Copies the value into guarded memory, wiping the copy on the heap, and adds it as
     * {@link #addVersion(String, Secret)} does.
     */
    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        Objects.requireNonNull(secretValue, SECRET_VALUE);
        checkOpen();
        try (Secret value = memory.fromBytes(secretValue.clone())) {
            return addVersion(secretName, value);
        }
    }

    /**
     * Writes the value to the file, replacing the line of an existing key in place or appending a line, and returns
     * {@value #LATEST}. The file (the target of a symbolic link) is replaced atomically by a new file that only its
     * owner can read and write (where the file system supports POSIX permissions); comments, blank lines, line
     * endings and the order of the other lines are kept. A file system that cannot move atomically is an error. The
     * file is read and the new one built in guarded memory.
     *
     * @throws SecretManagerException if the name is not a valid key, the value contains CR or LF, or the file cannot
     *                                be written
     */
    @Override
    public String addVersion(String secretName, Secret secretValue) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        Objects.requireNonNull(secretValue, SECRET_VALUE);
        lock.writeLock().lock();
        try {
            checkOpen();
            byte[] keyBytes = checkKey(secretName);
            Secret value = memory.allocate(secretValue.length(), copy -> secretValue.withSegment(from -> {
                if (SecretsFile.hasLineBreak(from)) {
                    throw new SecretManagerException("The value of secret '" + secretName
                            + "' contains a line break, which this file format cannot hold");
                }
                MemorySegment.copy(from, 0, copy, 0, from.byteSize());
                return null;
            }));
            try {
                writeFile(secretName, keyBytes, value);
            } catch (RuntimeException e) {
                value.close();
                throw e;
            }
            Secret previous = secrets.put(secretName, value);
            if (previous != null) {
                previous.close();
            }
            return LATEST;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Rewrites the file with {@code key=value}, read and built in guarded memory; see
     * {@link SecretsFile#withEntry}.
     */
    private void writeFile(String key, byte[] keyBytes, Secret value) {
        Path target = resolveTarget();
        try (Secret content = SecretsFile.read(target, memory);
             Secret updated = content.withSegment(file -> value.withSegment(
                     v -> SecretsFile.withEntry(memory, file, target, key, keyBytes, v)))) {
            updated.withSegment(file -> {
                SecretsFile.replace(target, file);
                return null;
            });
        }
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

    /**
     * Closes the client, every secret it holds and every secret {@link #read(String, String)} returned, and wipes
     * and unmaps their memory, after the callbacks running on those secrets in other threads. Idempotent.
     *
     * <p>The memory is closed outside the client's lock: a callback that calls the client while this waits for it
     * gets {@link IllegalStateException} instead of a deadlock. Inside a callback of one of the secrets, the memory
     * cannot be closed and this throws {@link IllegalStateException}; the client is closed then, and a later
     * {@code close()} wipes the memory.
     */
    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            closed = true;
            secrets.clear();
        } finally {
            lock.writeLock().unlock();
        }
        memory.close();
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("Client is closed");
        }
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
        } catch (CharacterCodingException _) {
            throw invalidKey(key);
        }
        if (bytes.length == 0 || SecretsFile.isBlank(bytes[0]) || SecretsFile.isBlank(bytes[bytes.length - 1])
                || bytes[0] == '#') {
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
}
