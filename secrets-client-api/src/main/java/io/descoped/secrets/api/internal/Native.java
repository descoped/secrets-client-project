package io.descoped.secrets.api.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.util.Locale;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * The C library calls guarded memory needs, through the Foreign Function &amp; Memory API: {@code mmap},
 * {@code mprotect}, {@code mlock}, {@code munlock}, {@code munmap}, {@code madvise} and {@code getpagesize}. Linux and
 * macOS on x86_64 and aarch64 only; {@link #platform()} says whether this one is supported.
 *
 * <p>Every call that can fail captures {@code errno}, so a failure is reported with it.
 */
@SuppressWarnings("restricted")
public final class Native {

    /** No access: guard pages, and data pages while nobody reads them. */
    public static final int PROT_NONE = 0;
    /** Read only: data pages while a secret on them is read. */
    public static final int PROT_READ = 1;
    /** Read and write: data pages while a secret on them is written or wiped. */
    public static final int PROT_READ_WRITE = 1 | 2;

    private static final int MAP_PRIVATE = 0x02;
    private static final int MAP_ANONYMOUS_LINUX = 0x20;
    private static final int MAP_ANONYMOUS_MACOS = 0x1000;
    private static final int MADV_DONTDUMP = 16;
    private static final int MADV_WIPEONFORK = 18;

    /** The operating systems guarded memory supports. */
    public enum Platform {
        /** Linux on x86_64 or aarch64. */
        LINUX,
        /** macOS on x86_64 or aarch64. */
        MACOS,
        /** Anything else: no guarded memory. */
        UNSUPPORTED
    }

    private static final Platform PLATFORM = detect();

    private final MethodHandle mmap;
    private final MethodHandle mprotect;
    private final MethodHandle mlock;
    private final MethodHandle munlock;
    private final MethodHandle munmap;
    private final MethodHandle madvise;
    private final StructLayout captureLayout;
    private final VarHandle errno;
    private final long pageSize;

    private static final class Holder {
        static final Native INSTANCE = new Native();
    }

    private Native() {
        if (PLATFORM == Platform.UNSUPPORTED) {
            throw new IllegalStateException("Guarded memory is not supported on " + System.getProperty("os.name")
                    + " " + System.getProperty("os.arch"));
        }
        Linker linker = Linker.nativeLinker();
        SymbolLookup libc = linker.defaultLookup();
        Linker.Option captureErrno = Linker.Option.captureCallState("errno");
        captureLayout = Linker.Option.captureStateLayout();
        errno = captureLayout.varHandle(MemoryLayout.PathElement.groupElement("errno"));

        mmap = downcall(linker, libc, "mmap",
                FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_LONG, JAVA_INT, JAVA_INT, JAVA_INT, JAVA_LONG),
                captureErrno);
        mprotect = downcall(linker, libc, "mprotect",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT), captureErrno);
        mlock = downcall(linker, libc, "mlock", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG), captureErrno);
        munlock = downcall(linker, libc, "munlock", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG),
                captureErrno);
        munmap = downcall(linker, libc, "munmap", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG), captureErrno);
        madvise = downcall(linker, libc, "madvise", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, JAVA_INT),
                captureErrno);
        MethodHandle getpagesize = downcall(linker, libc, "getpagesize", FunctionDescriptor.of(JAVA_INT));
        try {
            pageSize = (int) getpagesize.invokeExact();
        } catch (Throwable e) {
            throw new IllegalStateException("getpagesize failed", e);
        }
    }

    /**
     * The calls, bound on first use. Only call this when {@link #platform()} is supported and native access is
     * enabled for this module.
     */
    public static Native get() {
        return Holder.INSTANCE;
    }

    /** The platform this JVM runs on, as far as guarded memory is concerned. */
    public static Platform platform() {
        return PLATFORM;
    }

    private static Platform detect() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        boolean supportedArch = arch.equals("amd64") || arch.equals("x86_64") || arch.equals("aarch64");
        if (!supportedArch) {
            return Platform.UNSUPPORTED;
        }
        if (os.startsWith("linux")) {
            return Platform.LINUX;
        }
        if (os.startsWith("mac")) {
            return Platform.MACOS;
        }
        return Platform.UNSUPPORTED;
    }

    private static MethodHandle downcall(Linker linker, SymbolLookup libc, String name, FunctionDescriptor descriptor,
                                         Linker.Option... options) {
        MemorySegment symbol = libc.find(name)
                .orElseThrow(() -> new IllegalStateException("The C library has no " + name));
        return linker.downcallHandle(symbol, descriptor, options);
    }

    /** The size of a memory page. */
    public long pageSize() {
        return pageSize;
    }

    /**
     * Maps {@code length} bytes of private anonymous memory with no access, page aligned.
     *
     * @return the address
     * @throws NativeException if {@code mmap} fails
     */
    public long reserve(long length) {
        int anonymous = PLATFORM == Platform.LINUX ? MAP_ANONYMOUS_LINUX : MAP_ANONYMOUS_MACOS;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(captureLayout);
            MemorySegment result = (MemorySegment) mmap.invokeExact(state, MemorySegment.NULL, length, PROT_NONE,
                    MAP_PRIVATE | anonymous, -1, 0L);
            if (result.address() == -1L) {
                throw new NativeException("mmap", errno(state));
            }
            return result.address();
        } catch (NativeException e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("mmap failed", e);
        }
    }

    /**
     * Sets the access of {@code [address, address + length)}.
     *
     * @throws NativeException if {@code mprotect} fails
     */
    public void protect(long address, long length, int protection) {
        call("mprotect", mprotect, address, length, protection);
    }

    /**
     * Locks {@code [address, address + length)} in memory, so it is never swapped.
     *
     * @throws NativeException if {@code mlock} fails, typically over the locked-memory limit ({@code RLIMIT_MEMLOCK})
     */
    public void lock(long address, long length) {
        call("mlock", mlock, address, length);
    }

    /**
     * Unlocks {@code [address, address + length)}.
     *
     * @throws NativeException if {@code munlock} fails
     */
    public void unlock(long address, long length) {
        call("munlock", munlock, address, length);
    }

    /**
     * Unmaps {@code [address, address + length)}.
     *
     * @throws NativeException if {@code munmap} fails
     */
    public void unmap(long address, long length) {
        call("munmap", munmap, address, length);
    }

    /**
     * On Linux, keeps {@code [address, address + length)} out of core dumps and gives a forked child zeros instead of
     * it. Nothing on macOS, which has neither.
     *
     * @throws NativeException if {@code madvise} fails
     */
    public void exclude(long address, long length) {
        if (PLATFORM == Platform.LINUX) {
            call("madvise(MADV_DONTDUMP)", madvise, address, length, MADV_DONTDUMP);
            call("madvise(MADV_WIPEONFORK)", madvise, address, length, MADV_WIPEONFORK);
        }
    }

    /** Whether {@link #exclude(long, long)} does anything on this platform. */
    public boolean excludesFromCoreDumps() {
        return PLATFORM == Platform.LINUX;
    }

    private void call(String name, MethodHandle handle, long address, long length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(captureLayout);
            int result = (int) handle.invokeExact(state, MemorySegment.ofAddress(address), length);
            if (result != 0) {
                throw new NativeException(name, errno(state));
            }
        } catch (NativeException e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException(name + " failed", e);
        }
    }

    private void call(String name, MethodHandle handle, long address, long length, int flag) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(captureLayout);
            int result = (int) handle.invokeExact(state, MemorySegment.ofAddress(address), length, flag);
            if (result != 0) {
                throw new NativeException(name, errno(state));
            }
        } catch (NativeException e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException(name + " failed", e);
        }
    }

    private int errno(MemorySegment state) {
        return (int) errno.get(state, 0L);
    }
}
