package io.descoped.secrets.provider.mounted;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;

/**
 * Secrets mounted as files under a directory, read on every {@link #read(String, String)} straight into guarded
 * memory. See {@link MountedClientInitializer}. The client holds no value between reads: only the secrets it returned,
 * which closing it closes.
 */
final class MountedClient implements SecretManagerClient {

    /** The only version. */
    static final String LATEST = "latest";
    /** The largest file read. */
    static final long MAX_SIZE = 4L * 1024 * 1024;

    private static final Pattern SEGMENT = Pattern.compile("\\w[\\w.-]*");
    private static final String SECRET_NAME = "secretName";
    private static final String SECRET_VALUE = "secretValue";
    private static final long INITIAL = 4096;

    private final Path directory;
    private final SecretMemory memory;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private volatile boolean closed;

    MountedClient(Path directory, Map<String, String> configuration) {
        try {
            this.directory = directory.toRealPath();
        } catch (IOException e) {
            throw new SecretManagerException("Cannot open the mounted secrets directory " + directory, e);
        }
        if (!Files.isDirectory(this.directory)) {
            throw new SecretManagerException("The mounted secrets path " + directory + " is not a directory");
        }
        this.memory = SecretMemory.create(configuration);
    }

    @Override
    public Secret read(String secretName, String secretVersion) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        lock.readLock().lock();
        try {
            checkOpen();
            if (!(secretVersion == null || LATEST.equals(secretVersion)) || !isValidName(secretName)) {
                throw new SecretNotFoundException(secretName, secretVersion);
            }
            try {
                return readFile(secretName, file(secretName, secretVersion));
            } catch (NoSuchFileException _) {
                // Kubernetes swaps its ..data link and then removes the old files: a file resolved during the swap,
                // or just before it, is gone when it is resolved or opened. Resolving again finds the new one.
                try {
                    return readFile(secretName, file(secretName, secretVersion));
                } catch (NoSuchFileException _) {
                    throw new SecretNotFoundException(secretName, secretVersion);
                }
            }
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        try (Secret secret = read(secretName, secretVersion)) {
            return secret.withSegment(value -> value.toArray(ValueLayout.JAVA_BYTE));
        }
    }

    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        Objects.requireNonNull(secretValue, SECRET_VALUE);
        checkOpen();
        throw readOnly();
    }

    @Override
    public String addVersion(String secretName, Secret secretValue) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        Objects.requireNonNull(secretValue, SECRET_VALUE);
        checkOpen();
        throw readOnly();
    }

    /**
     * Closes the client and every secret {@link #read(String, String)} returned, and wipes and unmaps their memory,
     * after the callbacks running on those secrets in other threads. Idempotent. It waits for reads in progress, so a
     * read that blocks (a FIFO without a writer, a mount that hangs) holds it up. As safe-configuration does, the
     * memory is closed outside the client's lock, and inside a callback of one of the secrets this throws
     * {@link IllegalStateException} with the client closed; a later {@code close()} wipes the memory.
     */
    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            closed = true;
        } finally {
            lock.writeLock().unlock();
        }
        memory.close();
    }

    private static UnsupportedOperationException readOnly() {
        return new UnsupportedOperationException("The mounted secrets provider is read-only: the platform owns the"
                + " files");
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("Client is closed");
        }
    }

    static boolean isValidName(String name) {
        if (name.isEmpty() || name.length() > 4096) {
            return false;
        }
        for (String segment : name.split("/", -1)) {
            if (!SEGMENT.matcher(segment).matches()) {
                return false;
            }
        }
        return true;
    }

    /**
     * The real file of a secret: inside the directory, after following symbolic links.
     *
     * @throws NoSuchFileException if there is no such file (now)
     */
    private Path file(String secretName, String secretVersion) throws NoSuchFileException {
        Path real;
        try {
            real = directory.resolve(secretName).toRealPath();
        } catch (NoSuchFileException e) {
            throw e;
        } catch (NotDirectoryException _) {
            throw new SecretNotFoundException(secretName, secretVersion);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read secret '" + secretName + "'", e);
        }
        if (!real.startsWith(directory)) {
            throw new SecretManagerException("Secret '" + secretName + "' links outside the mounted directory");
        }
        if (Files.isDirectory(real)) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        return real;
    }

    /**
     * Reads the file into guarded memory until its end, not trusting its reported size (some mounts report none), and
     * returns it as a secret of its exact size. {@code file} is a real path: it is opened without following a link,
     * so the file opened is the one that was checked to be inside the directory.
     *
     * @throws NoSuchFileException if the file is gone
     */
    private Secret readFile(String secretName, Path file) throws NoSuchFileException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            long capacity = Math.clamp(channel.size() + 1, INITIAL, MAX_SIZE + 1);
            long[] length = {0};
            Secret buffer = memory.allocate(capacity, segment -> length[0] = fill(channel, segment, 0, secretName));
            try {
                while (length[0] == buffer.length()) {
                    if (buffer.length() > MAX_SIZE) {
                        throw new SecretManagerException("Secret '" + secretName + "' is larger than "
                                + MAX_SIZE + " bytes");
                    }
                    Secret old = buffer;
                    long filled = length[0];
                    buffer = memory.allocate(Math.min(old.length() * 2, MAX_SIZE + 1), segment -> old.withSegment(
                            from -> {
                                MemorySegment.copy(from, 0, segment, 0, filled);
                                length[0] = fill(channel, segment, filled, secretName);
                                return null;
                            }));
                    old.close();
                }
                Secret current = buffer;
                long size = length[0];
                return memory.allocate(size, out -> current.withSegment(from -> {
                    MemorySegment.copy(from, 0, out, 0, size);
                    return null;
                }));
            } finally {
                buffer.close();
            }
        } catch (NoSuchFileException e) {
            throw e;
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read secret '" + secretName + "'", e);
        }
    }

    /** Reads into {@code segment} from {@code from} until it is full or the file ends; returns the length filled. */
    private static long fill(FileChannel channel, MemorySegment segment, long from, String secretName) {
        ByteBuffer target = segment.asByteBuffer().position(Math.toIntExact(from));
        try {
            while (target.hasRemaining() && channel.read(target) >= 0) {
                // Read on until full or at the end.
            }
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read secret '" + secretName + "'", e);
        }
        return target.position();
    }
}
