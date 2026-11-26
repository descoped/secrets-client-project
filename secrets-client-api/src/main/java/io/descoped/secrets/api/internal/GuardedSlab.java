package io.descoped.secrets.api.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * A slab in pages of its own: a guard page, the data pages, a guard page. The guard pages are never accessible, so
 * reading or writing past either end of the data faults instead of reaching other memory. The data pages are locked
 * in memory (never swapped), kept out of core dumps and zeroed in a forked child (Linux), and accessible only while a
 * secret on them is used.
 */
@SuppressWarnings("restricted")
public final class GuardedSlab extends Slab {

    private final Native os;
    private final long base;
    private final long total;
    private final long dataAddress;
    private final Arena arena;
    private final MemorySegment data;
    private final boolean locked;
    private final boolean excluded;

    /**
     * Maps a slab of at least {@code capacity} bytes, rounded up to whole pages.
     *
     * @param lockRequired whether failing to lock the pages is an error; if not, the slab is just not locked
     * @throws NativeException if the memory cannot be mapped or protected, or locked when that is required
     */
    public GuardedSlab(Native os, long capacity, boolean lockRequired) {
        long page = os.pageSize();
        long length = Math.max(1, (capacity + page - 1) / page) * page;
        super(length);
        this.os = os;
        this.total = length + 2 * page;
        this.base = os.reserve(total);
        this.dataAddress = base + page;
        boolean isLocked = false;
        boolean isExcluded = false;
        try {
            os.protect(dataAddress, length, Native.PROT_READ_WRITE);
            try {
                os.exclude(dataAddress, length);
                isExcluded = os.excludesFromCoreDumps();
            } catch (NativeException e) {
                // A kernel without MADV_DONTDUMP or MADV_WIPEONFORK; reported through excludedFromCoreDumps().
                isExcluded = false;
            }
            try {
                os.lock(dataAddress, length);
                isLocked = true;
            } catch (NativeException e) {
                if (lockRequired) {
                    throw e;
                }
            }
            os.protect(dataAddress, length, Native.PROT_NONE);
        } catch (RuntimeException e) {
            try {
                os.unmap(base, total);
            } catch (RuntimeException suppressed) {
                e.addSuppressed(suppressed);
            }
            throw e;
        }
        this.locked = isLocked;
        this.excluded = isExcluded;
        this.arena = Arena.ofShared();
        this.data = MemorySegment.ofAddress(dataAddress).reinterpret(length, arena, null);
    }

    @Override
    MemorySegment data() {
        return data;
    }

    @Override
    void applyProtection(int protection) {
        os.protect(dataAddress, capacity(), protection);
    }

    @Override
    void release() {
        data.fill((byte) 0);
        arena.close();
        try {
            if (locked) {
                os.unlock(dataAddress, capacity());
            }
        } finally {
            os.unmap(base, total);
        }
    }

    @Override
    public MemorySegment view(MemorySegment block, Arena viewArena) {
        return block.reinterpret(viewArena, null);
    }

    @Override
    public boolean locked() {
        return locked;
    }

    @Override
    public boolean excludedFromCoreDumps() {
        return excluded;
    }
}
