package io.descoped.secrets.api;

import io.descoped.secrets.api.internal.GuardedSlab;
import io.descoped.secrets.api.internal.Native;
import io.descoped.secrets.api.internal.NativeException;
import io.descoped.secrets.api.internal.PlainSlab;
import io.descoped.secrets.api.internal.Slab;
import io.descoped.secrets.api.internal.Utf8;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Cleaner;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Guarded off-heap memory for {@link Secret}s. Secret values held here are never on the Java heap: the garbage
 * collector never sees, moves or copies them, and they are not in heap dumps.
 *
 * <p>Secrets share slabs of whole pages. Each slab has a guard page before and after it that is never accessible, so
 * reading or writing past either end faults instead of reaching other memory. A slab's pages are
 * <ul>
 *     <li>locked in memory with {@code mlock}, so they are never swapped ({@value #LOCK_KEY});</li>
 *     <li>on Linux, kept out of core dumps ({@code MADV_DONTDUMP}) and zeroed in a forked child
 *     ({@code MADV_WIPEONFORK});</li>
 *     <li>not accessible at all ({@code PROT_NONE}) unless a secret on them is being read, written or wiped;</li>
 *     <li>wiped when a secret is closed, and wiped and unmapped when the memory is closed.</li>
 * </ul>
 *
 * <p>This needs native access: start the JVM with {@code --enable-native-access=io.descoped.secrets.api}, or
 * {@code --enable-native-access=ALL-UNNAMED} when the library is on the class path. Without it, and on platforms other
 * than Linux and macOS on x86_64 or aarch64, {@link #create(Map)} refuses, unless {@value #GUARD_KEY} is {@code off}.
 *
 * <p>Close the memory when its secrets are no longer needed. Memory that becomes unreachable without being closed
 * (which needs all its secrets to be unreachable too) is wiped and unmapped when the garbage collector finds it, and
 * that is logged. Thread-safe.
 */
public final class SecretMemory implements AutoCloseable {

    /**
     * {@code on} (the default) for guarded memory, {@code off} for plain off-heap memory, which is still wiped but has
     * no guard pages, locking or access control and needs no native access. {@code off} is meant for tests.
     */
    public static final String GUARD_KEY = "secrets.memory.guard";

    /**
     * {@code required} (the default): memory that cannot be locked is an error. {@code preferred}: it is used unlocked,
     * and that is logged once. Locking fails when the process is over its locked-memory limit
     * ({@code RLIMIT_MEMLOCK}; {@code ulimit -l}, {@code docker run --ulimit memlock=...}).
     */
    public static final String LOCK_KEY = "secrets.memory.lock";

    /** Frees what was never closed: memory here, and {@link Secret}s. */
    static final Cleaner CLEANER = Cleaner.create();

    private static final System.Logger LOG = System.getLogger(SecretMemory.class.getName());

    private final Pool pool;
    private final Cleaner.Cleanable cleanable;

    private SecretMemory(Pool pool) {
        this.pool = pool;
        this.cleanable = CLEANER.register(this, new Unreachable(pool));
    }

    /** Frees the memory of a {@code SecretMemory} that was never closed. Holds no reference to it. */
    private record Unreachable(Pool pool) implements Runnable {
        @Override
        public void run() {
            if (!pool.closedExplicitly && !pool.closed) {
                LOG.log(System.Logger.Level.WARNING,
                        "Secret memory was not closed; it is wiped and unmapped now that it is unreachable");
            }
            pool.close();
        }
    }

    /**
     * Creates guarded memory as {@code configuration} says ({@value #GUARD_KEY}, {@value #LOCK_KEY}; other keys are
     * ignored). The first slab is mapped and locked here, so a missing permission or limit is reported now.
     *
     * @param configuration the configuration, for example a client's
     * @return new memory, to close when its secrets are no longer needed
     * @throws IllegalArgumentException if a key has a value other than those documented
     * @throws SecretManagerException   if guarded memory is not available: no native access, an unsupported platform,
     *                                  or memory that cannot be mapped or (when required) locked
     * @throws NullPointerException     if {@code configuration} is {@code null}
     */
    public static SecretMemory create(Map<String, String> configuration) {
        Objects.requireNonNull(configuration, "configuration");
        boolean guarded = choice(configuration, GUARD_KEY, "on", "off");
        boolean lockRequired = choice(configuration, LOCK_KEY, "required", "preferred");
        Native os = null;
        if (guarded) {
            if (Native.platform() == Native.Platform.UNSUPPORTED) {
                throw new SecretManagerException("Guarded memory is supported on Linux and macOS (x86_64, aarch64),"
                        + " not on " + System.getProperty("os.name") + " " + System.getProperty("os.arch")
                        + "; " + GUARD_KEY + "=off is for tests only");
            }
            Module module = SecretMemory.class.getModule();
            if (!module.isNativeAccessEnabled()) {
                String name = module.isNamed() ? module.getName() : "ALL-UNNAMED";
                throw new SecretManagerException("Guarded memory needs native access: start the JVM with"
                        + " --enable-native-access=" + name + " (" + GUARD_KEY + "=off is for tests only)");
            }
            os = Native.get();
        }
        Pool pool = new Pool(os, lockRequired);
        pool.start();
        return new SecretMemory(pool);
    }

    private static boolean choice(Map<String, String> configuration, String key, String yes, String no) {
        String value = configuration.get(key);
        if (value == null || value.equals(yes)) {
            return true;
        }
        if (value.equals(no)) {
            return false;
        }
        throw new IllegalArgumentException("Invalid " + key + " '" + value + "': " + yes + " or " + no);
    }

    /**
     * Allocates a secret of {@code length} bytes and lets {@code writer} fill it. The segment {@code writer} gets is
     * writable, starts out zeroed, and is valid only during the call; with guarded memory, using it afterwards or from
     * another thread fails. If {@code writer} throws, the secret is wiped and freed and the exception is passed on.
     *
     * @param length the length of the secret, in bytes
     * @param writer fills the secret
     * @return the secret, to close when it is no longer needed
     * @throws IllegalArgumentException if {@code length} is negative or more than {@link Integer#MAX_VALUE}
     * @throws IllegalStateException    if the memory is closed, also while {@code writer} runs
     * @throws SecretManagerException   if more memory is needed and cannot be mapped or locked
     * @throws NullPointerException     if {@code writer} is {@code null}
     */
    public Secret allocate(long length, Consumer<? super MemorySegment> writer) {
        Objects.requireNonNull(writer, "writer");
        if (length < 0 || length > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Invalid length " + length);
        }
        Block block = pool.take(length);
        Secret secret = new Secret(this, block);
        try {
            block.write(writer);
        } catch (RuntimeException | Error e) {
            try {
                secret.close();
            } catch (RuntimeException suppressed) {
                e.addSuppressed(suppressed);
            }
            throw e;
        }
        return secret;
    }

    /**
     * Copies {@code value} into a new secret, and wipes {@code value}, also when this fails.
     *
     * @param value the value; zeroed on return
     * @return the secret, to close when it is no longer needed
     * @throws IllegalStateException  if the memory is closed
     * @throws SecretManagerException if more memory is needed and cannot be mapped or locked
     * @throws NullPointerException   if {@code value} is {@code null}
     */
    public Secret fromBytes(byte[] value) {
        Objects.requireNonNull(value, "value");
        try {
            return allocate(value.length,
                    segment -> MemorySegment.copy(value, 0, segment, ValueLayout.JAVA_BYTE, 0, value.length));
        } finally {
            Arrays.fill(value, (byte) 0);
        }
    }

    /**
     * Encodes {@code value} as UTF-8 into a new secret, and wipes {@code value}, also when this fails.
     *
     * @param value the value; zeroed on return
     * @return the secret, to close when it is no longer needed
     * @throws IllegalArgumentException if {@code value} has an unpaired surrogate
     * @throws IllegalStateException    if the memory is closed
     * @throws SecretManagerException   if more memory is needed and cannot be mapped or locked
     * @throws NullPointerException     if {@code value} is {@code null}
     */
    public Secret fromChars(char[] value) {
        Objects.requireNonNull(value, "value");
        try {
            long length;
            try {
                length = Utf8.encodedLength(value);
            } catch (Utf8.MalformedException e) {
                throw new IllegalArgumentException("The value is not valid UTF-16: it has an unpaired surrogate");
            }
            return allocate(length, segment -> Utf8.encode(value, segment));
        } finally {
            Arrays.fill(value, '\0');
        }
    }

    /**
     * Whether the memory is guarded ({@value #GUARD_KEY} is {@code on}).
     *
     * @return whether it is guarded
     */
    public boolean isGuarded() {
        return pool.os != null;
    }

    /**
     * Whether all memory mapped so far is locked in memory. Always {@code false} when not guarded.
     *
     * @return whether it is locked
     */
    public boolean isLocked() {
        return pool.isLocked();
    }

    /**
     * Closes every secret still open, waiting for those being read or written, then wipes and unmaps all memory.
     * Idempotent.
     *
     * @throws IllegalStateException if called inside a callback of one of its secrets; nothing is closed then
     */
    @Override
    public void close() {
        pool.checkNotInCallback();
        pool.closedExplicitly = true;
        cleanable.clean();
    }

    @Override
    public String toString() {
        return "SecretMemory[" + (isGuarded() ? "guarded" : "unguarded") + (pool.closed ? ", closed" : "") + "]";
    }

    /**
     * The state of a {@code SecretMemory}: its slabs and open blocks. Separate from it, so that its cleaner can free
     * the memory once the {@code SecretMemory} is unreachable.
     */
    static final class Pool {
        private static final long PLAIN_SLAB_SIZE = 4096;

        private final Native os;
        private final boolean lockRequired;
        private final ReentrantLock lock = new ReentrantLock();
        private final List<Slab> slabs = new ArrayList<>();
        private final Set<Block> live = new LinkedHashSet<>();
        private boolean unlockedLogged;
        private volatile boolean closed;
        private volatile boolean closedExplicitly;

        private Pool(Native os, boolean lockRequired) {
            this.os = os;
            this.lockRequired = lockRequired;
        }

        /** Maps the first slab, so that a missing permission or limit is reported at once. */
        private void start() {
            lock.lock();
            try {
                newSlab(0);
            } finally {
                lock.unlock();
            }
        }

        private boolean isLocked() {
            lock.lock();
            try {
                return !slabs.isEmpty() && slabs.stream().allMatch(Slab::locked);
            } finally {
                lock.unlock();
            }
        }

        private void checkNotInCallback() {
            lock.lock();
            try {
                for (Block block : live) {
                    if (block.heldByCurrentThread()) {
                        throw new IllegalStateException(
                                "Secret memory cannot be closed inside a callback of one of its secrets");
                    }
                }
            } finally {
                lock.unlock();
            }
        }

        private Block take(long length) {
            long size = Slab.blockSize(length);
            lock.lock();
            try {
                if (closed) {
                    throw new IllegalStateException("Secret memory is closed");
                }
                for (Slab slab : slabs) {
                    long offset = slab.allocate(size);
                    if (offset >= 0) {
                        return register(slab, offset, size, length);
                    }
                }
                Slab slab = newSlab(size);
                return register(slab, slab.allocate(size), size, length);
            } finally {
                lock.unlock();
            }
        }

        private Block register(Slab slab, long offset, long size, long length) {
            Block block = new Block(this, slab, offset, size, length);
            live.add(block);
            return block;
        }

        /** A slab with room for at least {@code size} bytes; under {@link #lock}. */
        private Slab newSlab(long size) {
            Slab slab;
            if (os == null) {
                slab = new PlainSlab(Math.max(PLAIN_SLAB_SIZE, size));
            } else {
                try {
                    slab = new GuardedSlab(os, Math.max(os.pageSize(), size), lockRequired);
                } catch (NativeException e) {
                    throw new SecretManagerException(e.call().equals("mlock")
                            ? "Cannot lock secret memory (" + e.getMessage() + "): the process is over its"
                            + " locked-memory limit (RLIMIT_MEMLOCK). Raise it (ulimit -l, docker run --ulimit"
                            + " memlock=...), or set " + LOCK_KEY + "=preferred to use it unlocked"
                            : "Cannot map guarded secret memory: " + e.getMessage(), e);
                }
                if (!slab.locked() && !unlockedLogged) {
                    unlockedLogged = true;
                    LOG.log(System.Logger.Level.WARNING, "Secret memory could not be locked and may be swapped ("
                            + LOCK_KEY + "=preferred); raise the locked-memory limit (RLIMIT_MEMLOCK) to lock it");
                }
            }
            slabs.add(slab);
            return slab;
        }

        private void release(Block block) {
            lock.lock();
            try {
                block.slab.free(block.offset, block.size);
                live.remove(block);
                if (!closed && slabs.size() > 1 && block.slab.isEmpty()) {
                    slabs.remove(block.slab);
                    block.slab.dispose();
                }
            } finally {
                lock.unlock();
            }
        }

        /**
         * Closes every open block, waiting for callbacks in other threads, then wipes and unmaps every slab, even if
         * closing a block or disposing a slab fails. Idempotent.
         */
        private void close() {
            List<Block> open;
            lock.lock();
            try {
                if (closed) {
                    return;
                }
                closed = true;
                open = new ArrayList<>(live);
            } finally {
                lock.unlock();
            }
            RuntimeException failure = null;
            for (Block block : open) {
                try {
                    block.close();
                } catch (RuntimeException e) {
                    failure = add(failure, e);
                }
            }
            lock.lock();
            try {
                for (Slab slab : slabs) {
                    try {
                        slab.dispose();
                    } catch (RuntimeException e) {
                        failure = add(failure, e);
                    }
                }
                slabs.clear();
            } finally {
                lock.unlock();
            }
            if (failure != null) {
                throw failure;
            }
        }

        private static RuntimeException add(RuntimeException first, RuntimeException next) {
            if (first == null) {
                return next;
            }
            first.addSuppressed(next);
            return first;
        }
    }

    /**
     * The memory of one secret. Holds no reference to its {@link Secret} or to the {@code SecretMemory}, so that their
     * cleaners can run.
     */
    static final class Block {
        private final Pool pool;
        private final Slab slab;
        private final long offset;
        private final long size;
        private final long length;
        /** Read lock: a callback (or the writer) is using the block. Write lock: closing it. */
        private final ReentrantReadWriteLock access = new ReentrantReadWriteLock();
        private boolean closed;
        private volatile boolean closedExplicitly;

        private Block(Pool pool, Slab slab, long offset, long size, long length) {
            this.pool = pool;
            this.slab = slab;
            this.offset = offset;
            this.size = size;
            this.length = length;
        }

        private MemorySegment segment() {
            return slab.block(offset, length);
        }

        long length() {
            access.readLock().lock();
            try {
                checkOpen();
                return length;
            } finally {
                access.readLock().unlock();
            }
        }

        /** Lets {@code writer} fill the block, through a writable view that is valid during the call. */
        private void write(Consumer<? super MemorySegment> writer) {
            access.readLock().lock();
            try {
                checkOpen();
                slab.beginWrite();
                try (Arena call = Arena.ofConfined()) {
                    writer.accept(slab.view(segment(), call));
                } finally {
                    slab.endWrite();
                }
            } finally {
                access.readLock().unlock();
            }
        }

        /** Applies {@code action} to a read-only view of the value that is valid during the call. */
        <R> R read(Function<? super MemorySegment, ? extends R> action) {
            access.readLock().lock();
            try {
                checkOpen();
                slab.beginRead();
                try (Arena call = Arena.ofConfined()) {
                    return action.apply(slab.view(segment(), call).asReadOnly());
                } finally {
                    slab.endRead();
                }
            } finally {
                access.readLock().unlock();
            }
        }

        /** Notes that {@link Secret#close()} was called, so the cleaner does not report the secret as leaked. */
        void markClosedExplicitly() {
            closedExplicitly = true;
        }

        boolean closedExplicitly() {
            return closedExplicitly;
        }

        boolean heldByCurrentThread() {
            return access.getReadHoldCount() > 0;
        }

        boolean isClosed() {
            access.readLock().lock();
            try {
                return closed;
            } finally {
                access.readLock().unlock();
            }
        }

        /** Wipes and frees the memory, after any callbacks in progress. Idempotent. */
        void close() {
            if (heldByCurrentThread()) {
                throw new IllegalStateException("A secret cannot be closed inside one of its own callbacks");
            }
            access.writeLock().lock();
            try {
                if (closed) {
                    return;
                }
                closed = true;
                pool.release(this);
            } finally {
                access.writeLock().unlock();
            }
        }

        private void checkOpen() {
            if (closed) {
                throw new IllegalStateException("Secret is closed");
            }
        }
    }
}
