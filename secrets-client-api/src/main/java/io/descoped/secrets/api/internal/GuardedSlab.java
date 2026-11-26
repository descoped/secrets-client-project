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
    private final boolean hidden;

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
        boolean isHidden = false;
        try {
            if (os.secretMemoryAvailable()) {
                isHidden = hide(os, dataAddress, length, lockRequired);
            }
            if (!isHidden) {
                os.protect(dataAddress, length, Native.PROT_READ_WRITE);
            }
            isExcluded = excludeFromCoreDumps(os, dataAddress, length);
            if (isHidden) {
                os.dontFork(dataAddress, length);
            } else {
                wipeOnFork(os, dataAddress, length);
            }
            isLocked = lock(os, dataAddress, length, lockRequired);
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
        this.hidden = isHidden;
        this.arena = Arena.ofShared();
        this.data = MemorySegment.ofAddress(dataAddress).reinterpret(length, arena, null);
    }

    /**
     * Replaces the data pages with {@code memfd_secret} memory, removed from the kernel's direct map. If that fails,
     * puts the reserved anonymous pages back and returns {@code false}, unless the failure is the locked-memory limit
     * and locking is required ({@code memfd_secret} memory is always locked).
     */
    private static boolean hide(Native os, long address, long length, boolean lockRequired) {
        try {
            os.mapSecret(address, length);
            return true;
        } catch (NativeException e) {
            os.reserveAt(address, length);
            if (lockRequired && Native.isOverLimit(e)) {
                throw e;
            }
            return false;
        }
    }

    /** {@code MADV_DONTDUMP}; a kernel without it is reported through {@link #excludedFromCoreDumps()}. */
    private static boolean excludeFromCoreDumps(Native os, long address, long length) {
        try {
            return os.excludeFromCoreDumps(address, length);
        } catch (NativeException _) {
            return false;
        }
    }

    /**
     * {@code MADV_WIPEONFORK}. A kernel before 4.14 lacks it, which matters little: the JVM starts processes with
     * {@code posix_spawn} or {@code vfork}, which do not copy memory.
     */
    private static void wipeOnFork(Native os, long address, long length) {
        try {
            os.wipeOnFork(address, length);
        } catch (NativeException _) {
            // Not available; see above.
        }
    }

    /** Locks the pages; a failure is an error only if locking is required. */
    private static boolean lock(Native os, long address, long length, boolean required) {
        try {
            os.lock(address, length);
            return true;
        } catch (NativeException e) {
            if (required) {
                throw e;
            }
            return false;
        }
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

    @Override
    public boolean hiddenFromKernel() {
        return hidden;
    }
}
