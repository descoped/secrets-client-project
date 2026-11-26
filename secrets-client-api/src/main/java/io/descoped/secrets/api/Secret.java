package io.descoped.secrets.api;

import io.descoped.secrets.api.internal.Utf8;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.ref.Cleaner;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;

/**
 * A secret value in {@link SecretMemory}: off the Java heap, in guarded memory, and wiped on {@link #close()}.
 *
 * <p>The value is reached only inside a callback, and only for the length of the call:
 * <pre>{@code
 * try (Secret password = ...) {
 *     password.withChars(chars -> {
 *         dataSource.setPassword(chars);
 *         return null;
 *     });
 * }
 * }</pre>
 *
 * <ul>
 *     <li>{@link #withSegment(Function)} hands over the value itself, read-only, with no copy at all: for consumers
 *     that take native memory.</li>
 *     <li>{@link #withBytes(Function)} and {@link #withChars(Function)} hand over a copy on the Java heap, the hand-over
 *     copy, which is wiped when the call returns. What the consumer does with it is outside this library's reach:
 *     a consumer that keeps its own copy, or makes a {@code String}, keeps the value on the heap.</li>
 * </ul>
 * The callback must not keep or return the segment or array it gets, nor a {@code String} made from it.
 *
 * <p>Close a secret as soon as it is no longer needed. One that becomes unreachable without being closed is wiped and
 * freed when the garbage collector finds it, and that is logged. Thread-safe: callbacks may run concurrently, and
 * {@link #close()} waits for those in progress.
 */
public final class Secret implements AutoCloseable {

    private static final System.Logger LOG = System.getLogger(Secret.class.getName());

    /** Keeps the memory reachable, so that it is not cleaned while this secret is in use. */
    @SuppressWarnings("unused")
    private final SecretMemory memory;
    private final SecretMemory.Block block;
    private final Cleaner.Cleanable cleanable;

    Secret(SecretMemory memory, SecretMemory.Block block) {
        this.memory = memory;
        this.block = block;
        this.cleanable = SecretMemory.CLEANER.register(this, new Unreachable(block));
    }

    /** Frees the block of a secret that was never closed. Holds no reference to the secret. */
    private record Unreachable(SecretMemory.Block block) implements Runnable {
        @Override
        public void run() {
            if (!block.closedExplicitly() && !block.isClosed()) {
                LOG.log(System.Logger.Level.WARNING, "A secret was not closed; it is wiped now that it is unreachable");
            }
            block.close();
        }
    }

    /**
     * The length of the value, in bytes.
     *
     * @return the length
     * @throws IllegalStateException if the secret is closed
     */
    public long length() {
        return block.length();
    }

    /**
     * Applies {@code action} to the value itself: a read-only segment, valid only during the call. With guarded
     * memory, using it after the call or from another thread fails (and the pages are no longer even readable); with
     * {@code secrets.memory.guard=off} that is not enforced.
     *
     * @param action uses the value
     * @param <R>    what {@code action} returns
     * @return what {@code action} returns, which must not be or contain the value
     * @throws IllegalStateException if the secret is closed
     * @throws NullPointerException  if {@code action} is {@code null}
     */
    public <R> R withSegment(Function<? super MemorySegment, ? extends R> action) {
        Objects.requireNonNull(action, "action");
        return block.read(action);
    }

    /**
     * Applies {@code action} to a copy of the value on the Java heap, which is wiped when the call returns.
     *
     * @param action uses the value
     * @param <R>    what {@code action} returns
     * @return what {@code action} returns, which must not be or contain the value
     * @throws IllegalStateException if the secret is closed
     * @throws NullPointerException  if {@code action} is {@code null}
     */
    public <R> R withBytes(Function<? super byte[], ? extends R> action) {
        Objects.requireNonNull(action, "action");
        return block.read(segment -> {
            byte[] bytes = segment.toArray(ValueLayout.JAVA_BYTE);
            try {
                return action.apply(bytes);
            } finally {
                Arrays.fill(bytes, (byte) 0);
            }
        });
    }

    /**
     * Applies {@code action} to the value decoded from UTF-8 into a {@code char} array on the Java heap, which is
     * wiped when the call returns. The value is decoded straight from the guarded memory, without the JDK's charset
     * decoders (which keep heap buffers of their own).
     *
     * @param action uses the value
     * @param <R>    what {@code action} returns
     * @return what {@code action} returns, which must not be or contain the value
     * @throws SecretManagerException if the value is not valid UTF-8
     * @throws IllegalStateException  if the secret is closed
     * @throws NullPointerException   if {@code action} is {@code null}
     */
    public <R> R withChars(Function<? super char[], ? extends R> action) {
        Objects.requireNonNull(action, "action");
        return block.read(segment -> {
            char[] chars;
            try {
                chars = Utf8.decode(segment);
            } catch (Utf8.MalformedException e) {
                throw new SecretManagerException("The secret is not valid UTF-8");
            }
            try {
                return action.apply(chars);
            } finally {
                Arrays.fill(chars, '\0');
            }
        });
    }

    /**
     * Whether this secret and {@code other} hold the same value, compared in time that depends only on the length.
     *
     * @param other the other secret
     * @return whether the values are equal
     * @throws IllegalStateException if either secret is closed
     * @throws NullPointerException  if {@code other} is {@code null}
     */
    public boolean contentEquals(Secret other) {
        Objects.requireNonNull(other, "other");
        // Always lock the two in the same order, so that a.contentEquals(b) and b.contentEquals(a) cannot deadlock
        // when closes are waiting on both.
        Secret first = System.identityHashCode(this) <= System.identityHashCode(other) ? this : other;
        Secret second = first == this ? other : this;
        return first.withSegment(a -> second.withSegment(b -> {
            if (a.byteSize() != b.byteSize()) {
                return false;
            }
            int difference = 0;
            for (long i = 0; i < a.byteSize(); i++) {
                difference |= a.get(ValueLayout.JAVA_BYTE, i) ^ b.get(ValueLayout.JAVA_BYTE, i);
            }
            return difference == 0;
        }));
    }

    /**
     * Wipes the value and frees its memory, after any callbacks in progress in other threads. Idempotent.
     *
     * @throws IllegalStateException if called inside one of this secret's callbacks
     */
    @Override
    public void close() {
        if (block.heldByCurrentThread()) {
            throw new IllegalStateException("A secret cannot be closed inside one of its own callbacks");
        }
        block.markClosedExplicitly();
        cleanable.clean();
    }

    /** {@code Secret}, or {@code Secret (closed)}; never the value or its length. */
    @Override
    public String toString() {
        return block.isClosed() ? "Secret (closed)" : "Secret";
    }
}
