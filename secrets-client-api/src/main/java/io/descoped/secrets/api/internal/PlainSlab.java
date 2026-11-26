package io.descoped.secrets.api.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * A slab of plain off-heap memory, for {@code secrets.memory.guard=off} (tests only): off the Java heap and wiped, but
 * without guard pages, locking or access control, and without native access.
 */
public final class PlainSlab extends Slab {

    private final Arena arena;
    private final MemorySegment data;

    /** Allocates a slab of {@code capacity} bytes. */
    public PlainSlab(long capacity) {
        super(capacity);
        this.arena = Arena.ofShared();
        this.data = arena.allocate(capacity, ALIGNMENT);
    }

    @Override
    MemorySegment data() {
        return data;
    }

    @Override
    void applyProtection(int protection) {
        // No access control without native access.
    }

    @Override
    void release() {
        data.fill((byte) 0);
        arena.close();
    }

    /** The block itself: without native access a view cannot be bound to another arena. */
    @Override
    public MemorySegment view(MemorySegment block, Arena viewArena) {
        return block;
    }

    @Override
    public boolean locked() {
        return false;
    }

    @Override
    public boolean excludedFromCoreDumps() {
        return false;
    }
}
