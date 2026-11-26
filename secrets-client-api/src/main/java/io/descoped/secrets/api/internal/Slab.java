package io.descoped.secrets.api.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A region of off-heap memory that holds several secrets, each in a block of its own. Access is per slab, because
 * page protection is per page: the slab is readable while any secret in it is read, writable while one is written or
 * wiped, and not accessible at all otherwise.
 */
public abstract sealed class Slab permits GuardedSlab, PlainSlab {

    /** Blocks start at multiples of this. */
    static final long ALIGNMENT = 16;

    private final ReentrantLock lock = new ReentrantLock();
    /** Free ranges, offset to length, never adjacent (freeing merges them). */
    private final TreeMap<Long, Long> free = new TreeMap<>();
    private final long capacity;
    private long used;
    private int readers;
    private int writers;
    private int protection = Native.PROT_NONE;

    Slab(long capacity) {
        this.capacity = capacity;
        free.put(0L, capacity);
    }

    /** The data area, bound to the slab's own arena. */
    abstract MemorySegment data();

    /** Sets the access of the data area. */
    abstract void applyProtection(int protection);

    /** Wipes the data area and gives the memory back. The slab must be writable. */
    abstract void release();

    /**
     * A view of {@code block} that is valid until {@code arena} is closed, or the slab is released if that cannot be
     * enforced (unguarded memory).
     */
    public abstract MemorySegment view(MemorySegment block, Arena arena);

    /** Whether the slab's pages are locked in memory. */
    public abstract boolean locked();

    /** Whether the slab's pages are kept out of core dumps. */
    public abstract boolean excludedFromCoreDumps();

    /** The size a block of {@code length} bytes takes. */
    public static long blockSize(long length) {
        return Math.max(ALIGNMENT, (length + ALIGNMENT - 1) / ALIGNMENT * ALIGNMENT);
    }

    /**
     * Takes a block of {@code size} bytes ({@link #blockSize(long)}), first fit.
     *
     * @return its offset, or -1 if the slab has no free range that large
     */
    public long allocate(long size) {
        lock.lock();
        try {
            for (Map.Entry<Long, Long> range : free.entrySet()) {
                if (range.getValue() >= size) {
                    long offset = range.getKey();
                    free.remove(offset);
                    if (range.getValue() > size) {
                        free.put(offset + size, range.getValue() - size);
                    }
                    used += size;
                    return offset;
                }
            }
            return -1;
        } finally {
            lock.unlock();
        }
    }

    /** The block at {@code offset}, of {@code length} bytes, bound to the slab's arena. */
    public MemorySegment block(long offset, long length) {
        return data().asSlice(offset, length);
    }

    /** Wipes the block at {@code offset} and gives it back. */
    public void free(long offset, long size) {
        lock.lock();
        try {
            beginWrite();
            try {
                data().asSlice(offset, size).fill((byte) 0);
            } finally {
                endWrite();
            }
            long start = offset;
            long length = size;
            Map.Entry<Long, Long> before = free.floorEntry(offset);
            if (before != null && before.getKey() + before.getValue() == offset) {
                start = before.getKey();
                length += before.getValue();
                free.remove(before.getKey());
            }
            Long after = free.get(offset + size);
            if (after != null) {
                length += after;
                free.remove(offset + size);
            }
            free.put(start, length);
            used -= size;
        } finally {
            lock.unlock();
        }
    }

    /** Whether no block is taken. */
    public boolean isEmpty() {
        lock.lock();
        try {
            return used == 0;
        } finally {
            lock.unlock();
        }
    }

    /** The size of the data area. */
    public long capacity() {
        return capacity;
    }

    /** Makes the slab readable until the matching {@link #endRead()}. */
    public void beginRead() {
        lock.lock();
        try {
            readers++;
            update();
        } catch (RuntimeException e) {
            readers--;
            throw e;
        } finally {
            lock.unlock();
        }
    }

    /** Ends a {@link #beginRead()}. */
    public void endRead() {
        lock.lock();
        try {
            readers--;
            update();
        } finally {
            lock.unlock();
        }
    }

    /** Makes the slab writable until the matching {@link #endWrite()}. */
    public void beginWrite() {
        lock.lock();
        try {
            writers++;
            update();
        } catch (RuntimeException e) {
            writers--;
            throw e;
        } finally {
            lock.unlock();
        }
    }

    /** Ends a {@link #beginWrite()}. */
    public void endWrite() {
        lock.lock();
        try {
            writers--;
            update();
        } finally {
            lock.unlock();
        }
    }

    /** Wipes the whole slab and gives the memory back. No block may be in use. */
    public void dispose() {
        lock.lock();
        try {
            writers++;
            update();
            release();
        } finally {
            lock.unlock();
        }
    }

    private void update() {
        int wanted = writers > 0 ? Native.PROT_READ_WRITE : readers > 0 ? Native.PROT_READ : Native.PROT_NONE;
        if (wanted != protection) {
            applyProtection(wanted);
            protection = wanted;
        }
    }
}
