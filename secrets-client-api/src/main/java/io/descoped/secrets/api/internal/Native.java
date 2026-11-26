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
    private static final int MADV_DONTFORK = 10;
    private static final int MAP_SHARED = 0x01;
    private static final int MAP_FIXED = 0x10;
    /** {@code memfd_secret}, the same number on x86_64 and aarch64 (the generic syscall table). */
    private static final long SYS_MEMFD_SECRET = 447;
    private static final int EINTR = 4;

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
    private final MethodHandle syscall;
    private final MethodHandle ftruncate;
    private final MethodHandle close;
    /** Linux only: macOS has no getrandom. */
    private final MethodHandle getrandom;
    private volatile Boolean secretMemory;
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
        syscall = downcall(linker, libc, "syscall", FunctionDescriptor.of(JAVA_LONG, JAVA_LONG, JAVA_INT),
                captureErrno, Linker.Option.firstVariadicArg(1));
        ftruncate = downcall(linker, libc, "ftruncate", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG),
                captureErrno);
        close = downcall(linker, libc, "close", FunctionDescriptor.of(JAVA_INT, JAVA_INT));
        getrandom = PLATFORM == Platform.LINUX
                ? downcall(linker, libc, "getrandom", FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_LONG, JAVA_INT),
                captureErrno)
                : null;
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
     * Maps private anonymous memory with no access over {@code [address, address + length)}, replacing what is there.
     *
     * @throws NativeException if {@code mmap} fails
     */
    public void reserveAt(long address, long length) {
        int anonymous = PLATFORM == Platform.LINUX ? MAP_ANONYMOUS_LINUX : MAP_ANONYMOUS_MACOS;
        mapFixed("mmap", address, length, PROT_NONE, MAP_PRIVATE | anonymous | MAP_FIXED, -1);
    }

    /**
     * Whether this kernel offers {@code memfd_secret} (Linux 5.14 and later, enabled by default since 6.5, and not
     * blocked by a seccomp filter). Probed once.
     */
    public boolean secretMemoryAvailable() {
        Boolean available = secretMemory;
        if (available == null) {
            available = false;
            if (PLATFORM == Platform.LINUX) {
                try {
                    closeDescriptor(memfdSecret());
                    available = true;
                } catch (NativeException _) {
                    // ENOSYS, or EPERM from a seccomp filter: not available.
                }
            }
            secretMemory = available;
        }
        return available;
    }

    /**
     * Maps {@code memfd_secret} memory, readable and writable and zeroed, over {@code [address, address + length)},
     * replacing what is there. Its pages are removed from the kernel's direct map, locked, and not in core dumps.
     * Every page is faulted in here, by the kernel, so that a page the kernel cannot provide (some kernels accept the
     * mapping over the locked-memory limit and refuse the pages later) is an error here rather than a fault in Java.
     * Linux only; check {@link #secretMemoryAvailable()} first.
     *
     * @throws NativeException if it cannot be created, mapped or faulted in; the range is then in an unknown state
     *                         and must be mapped again ({@link #reserveAt(long, long)})
     */
    public void mapSecret(long address, long length) {
        int fd = memfdSecret();
        try {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment state = arena.allocate(captureLayout);
                int result = (int) ftruncate.invokeExact(state, fd, length);
                if (result != 0) {
                    throw new NativeException("ftruncate(memfd_secret)", errno(state));
                }
            } catch (NativeException e) {
                throw e;
            } catch (Throwable e) {
                throw new IllegalStateException("ftruncate failed", e);
            }
            mapFixed("mmap(memfd_secret)", address, length, PROT_READ_WRITE, MAP_SHARED | MAP_FIXED, fd);
        } finally {
            closeDescriptor(fd);
        }
        populate(address, length);
        MemorySegment.ofAddress(address).reinterpret(length).fill((byte) 0);
    }

    /**
     * Faults in {@code [address, address + length)} through the kernel: {@code getrandom} writes into it, and returns
     * {@code EFAULT} for a page it cannot get, where a write from Java would fault.
     */
    private void populate(long address, long length) {
        long done = 0;
        while (done < length) {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment state = arena.allocate(captureLayout);
                long n = (long) getrandom.invokeExact(state, MemorySegment.ofAddress(address + done), length - done, 0);
                if (n < 0) {
                    int error = errno(state);
                    if (error != EINTR) {
                        throw new NativeException("getrandom(memfd_secret)", error);
                    }
                } else {
                    done += n;
                }
            } catch (NativeException e) {
                throw e;
            } catch (Throwable e) {
                throw new IllegalStateException("getrandom failed", e);
            }
        }
    }

    /**
     * On Linux, leaves {@code [address, address + length)} out of a forked child altogether ({@code MADV_DONTFORK}),
     * for shared mappings, where {@code MADV_WIPEONFORK} does not apply. Nothing on macOS.
     *
     * @throws NativeException if {@code madvise} fails
     */
    public void dontFork(long address, long length) {
        if (PLATFORM == Platform.LINUX) {
            call("madvise(MADV_DONTFORK)", madvise, address, length, MADV_DONTFORK);
        }
    }

    private int memfdSecret() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(captureLayout);
            long fd = (long) syscall.invokeExact(state, SYS_MEMFD_SECRET, 0);
            if (fd < 0) {
                throw new NativeException("memfd_secret", errno(state));
            }
            return (int) fd;
        } catch (NativeException e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException("memfd_secret failed", e);
        }
    }

    /** Closes {@code fd}; returns whether that worked (a mapping stays valid after its descriptor is closed). */
    private boolean closeDescriptor(int fd) {
        try {
            return (int) close.invokeExact(fd) == 0;
        } catch (Throwable e) {
            throw new IllegalStateException("close failed", e);
        }
    }

    private void mapFixed(String name, long address, long length, int protection, int flags, int fd) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment state = arena.allocate(captureLayout);
            MemorySegment result = (MemorySegment) mmap.invokeExact(state, MemorySegment.ofAddress(address), length,
                    protection, flags, fd, 0L);
            if (result.address() == -1L) {
                throw new NativeException(name, errno(state));
            }
            if (result.address() != address) {
                throw new IllegalStateException(name + " mapped at another address");
            }
        } catch (NativeException e) {
            throw e;
        } catch (Throwable e) {
            throw new IllegalStateException(name + " failed", e);
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
     * On Linux, keeps {@code [address, address + length)} out of core dumps ({@code MADV_DONTDUMP}). Nothing on macOS,
     * which has no such advice.
     *
     * @return whether the range is now excluded
     * @throws NativeException if {@code madvise} fails
     */
    public boolean excludeFromCoreDumps(long address, long length) {
        if (PLATFORM != Platform.LINUX) {
            return false;
        }
        call("madvise(MADV_DONTDUMP)", madvise, address, length, MADV_DONTDUMP);
        return true;
    }

    /**
     * On Linux, gives a forked child zeros instead of {@code [address, address + length)} ({@code MADV_WIPEONFORK},
     * Linux 4.14 and later). Nothing on macOS.
     *
     * @throws NativeException if {@code madvise} fails
     */
    public void wipeOnFork(long address, long length) {
        if (PLATFORM == Platform.LINUX) {
            call("madvise(MADV_WIPEONFORK)", madvise, address, length, MADV_WIPEONFORK);
        }
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
