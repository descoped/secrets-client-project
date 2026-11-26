package io.descoped.secrets.api.internal;

/**
 * A C library call that failed, with its {@code errno}.
 */
public final class NativeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** The call, for example {@code mlock}. */
    private final String call;
    /** The {@code errno} of the call. */
    private final int errno;

    NativeException(String call, int errno) {
        super(call + " failed: " + describe(errno));
        this.call = call;
        this.errno = errno;
    }

    /** The call, for example {@code mlock}. */
    public String call() {
        return call;
    }

    /** The {@code errno} of the call. */
    public int errno() {
        return errno;
    }

    /** The names of the {@code errno} values the calls here return. Only EAGAIN differs between Linux and macOS. */
    private static String describe(int errno) {
        int eagain = Native.platform() == Native.Platform.MACOS ? 35 : 11;
        String name;
        if (errno == eagain) {
            name = "EAGAIN";
        } else {
            name = switch (errno) {
                case 1 -> "EPERM";
                case 12 -> "ENOMEM";
                case 13 -> "EACCES";
                case 22 -> "EINVAL";
                default -> null;
            };
        }
        return name == null ? "errno " + errno : "errno " + errno + " " + name;
    }
}
