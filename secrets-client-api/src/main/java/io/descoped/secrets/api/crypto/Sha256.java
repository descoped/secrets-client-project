package io.descoped.secrets.api.crypto;

import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.internal.OpenSsl;

import java.lang.foreign.MemorySegment;
import java.util.Objects;

import static io.descoped.secrets.api.internal.OpenSsl.call;

/**
 * SHA-256 and HMAC-SHA256 through the system's OpenSSL 3 ({@code libcrypto}), in place on the caller's memory: a key
 * or a message in guarded memory is read where it is, and OpenSSL keeps its working state in native memory that it
 * clears. The JDK's {@code Mac} copies the key into a heap array ({@code SecretKeySpec}), and {@code MessageDigest}
 * buffers the message through heap arrays, so neither is used for secrets.
 *
 * <p>Inputs and outputs may be native or heap segments; secrets belong in native (guarded) memory. Thread-safe.
 */
public final class Sha256 {

    /** The length of a SHA-256 digest and of an HMAC-SHA256, in bytes. */
    public static final int LENGTH = 32;

    private Sha256() {
    }

    /**
     * The SHA-256 of {@code message}.
     *
     * @param message the bytes to hash
     * @param out     where to write the digest, at least {@link #LENGTH} bytes
     * @throws SecretManagerException if OpenSSL 3 is not found, or it fails
     */
    public static void digest(MemorySegment message, MemorySegment out) {
        Objects.requireNonNull(message, "message");
        checkOut(out);
        OpenSsl ssl = OpenSsl.get();
        ssl.clearErrors();
        MemorySegment md = call(() -> (MemorySegment) ssl.evpSha256.invokeExact());
        long length = message.byteSize();
        int ok = call(() -> (int) ssl.evpDigest.invokeExact(message, length, out, MemorySegment.NULL, md,
                MemorySegment.NULL));
        if (ok != 1) {
            throw new SecretManagerException("SHA-256 failed: " + ssl.errors());
        }
    }

    /**
     * The HMAC-SHA256 of {@code message} with {@code key}.
     *
     * @param key     the key, typically in guarded memory
     * @param message the bytes to authenticate
     * @param out     where to write the result, at least {@link #LENGTH} bytes
     * @throws SecretManagerException if OpenSSL 3 is not found, or it fails
     */
    public static void hmac(MemorySegment key, MemorySegment message, MemorySegment out) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(message, "message");
        checkOut(out);
        int keyLength = Math.toIntExact(key.byteSize());
        OpenSsl ssl = OpenSsl.get();
        ssl.clearErrors();
        MemorySegment md = call(() -> (MemorySegment) ssl.evpSha256.invokeExact());
        long length = message.byteSize();
        MemorySegment result = call(() -> (MemorySegment) ssl.hmac.invokeExact(md, key, keyLength, message, length,
                out, MemorySegment.NULL));
        if (result.equals(MemorySegment.NULL)) {
            throw new SecretManagerException("HMAC-SHA256 failed: " + ssl.errors());
        }
    }

    private static void checkOut(MemorySegment out) {
        Objects.requireNonNull(out, "out");
        if (out.byteSize() < LENGTH) {
            throw new IllegalArgumentException("The output needs " + LENGTH + " bytes, not " + out.byteSize());
        }
        if (out.isReadOnly()) {
            throw new IllegalArgumentException("The output is read-only");
        }
    }
}
