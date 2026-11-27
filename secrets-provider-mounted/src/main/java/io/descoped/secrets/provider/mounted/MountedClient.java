package io.descoped.secrets.provider.mounted;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;

import java.io.IOException;
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
    /** How many times a name is resolved and opened before a file that vanishes in between is reported missing. */
    private static final int ATTEMPTS = 3;

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
            // Kubernetes swaps its ..data link and then removes the old files: a file resolved during the swap, or just
            // before it, is gone when it is resolved or opened. Resolving again finds the new one.
            for (int attempt = 1; ; attempt++) {
                try {
                    return readFile(secretName, file(secretName, secretVersion));
                } catch (NoSuchFileException e) {
                    if (attempt == ATTEMPTS) {
                        throw new SecretNotFoundException(secretName, secretVersion, e);
                    }
                }
            }
        } finally {
            lock.readLock().unlock();
        }
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
     * Reads the file into guarded memory to its end, not trusting its reported size (some mounts report none), through
     * {@link SecretMemory#read}, which also handles mounts the kernel serves by pinning the buffer (Cloud Run's FUSE
     * secret volumes). {@code file} is a real path: it is opened without following a link, so the file opened is the
     * one that was checked to be inside the directory.
     *
     * @throws NoSuchFileException if the file is gone
     */
    private Secret readFile(String secretName, Path file) throws NoSuchFileException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            Secret value = memory.read(channel, MAX_SIZE + 1);
            if (value.length() > MAX_SIZE) {
                value.close();
                throw new SecretManagerException("Secret '" + secretName + "' is larger than " + MAX_SIZE + " bytes");
            }
            return value;
        } catch (NoSuchFileException e) {
            throw e;
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read secret '" + secretName + "'", e);
        }
    }
}
