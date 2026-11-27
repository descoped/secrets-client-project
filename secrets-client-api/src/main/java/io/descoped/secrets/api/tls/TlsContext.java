package io.descoped.secrets.api.tls;

import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.internal.OpenSsl;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static io.descoped.secrets.api.internal.OpenSsl.call;

/**
 * The TLS settings of one client, for {@link TlsSession}s through the system's OpenSSL 3, so that what is sent and
 * received is never on the Java heap: the JDK's {@code SSLEngine} copies plaintext through heap arrays.
 *
 * <ul>
 *     <li>TLS 1.3 or 1.2, with AES-GCM or ChaCha20-Poly1305 and ECDHE only; no renegotiation, no compression.
 *     OpenSSL clears decrypted data from its buffers once it is handed over ({@code SSL_OP_CLEANSE_PLAINTEXT}).</li>
 *     <li>The server's certificate must chain to a trusted root: the system's (OpenSSL's default locations) or, if a
 *     CA file is given, only the certificates in that PEM file. Its name must match the host, or its IP address the
 *     IP literal; SNI is sent for host names.</li>
 * </ul>
 *
 * <p>Thread-safe. Sessions opened from a context stay usable after it is closed.
 */
public final class TlsContext implements AutoCloseable {

    private static final String TLS13_SUITES = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
            + ":TLS_CHACHA20_POLY1305_SHA256";
    private static final String TLS12_CIPHERS = "ECDHE+AESGCM:ECDHE+CHACHA20";

    private final OpenSsl ssl;
    private final MemorySegment ctx;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private boolean closed;

    private TlsContext(OpenSsl ssl, MemorySegment ctx) {
        this.ssl = ssl;
        this.ctx = ctx;
    }

    /**
     * Creates a context.
     *
     * @param caFile a PEM file of the only certificates to trust, or {@code null} for the system's
     * @return the context, to close when the client closes
     * @throws SecretManagerException if OpenSSL 3 is not found, or the settings or the CA file cannot be applied
     */
    public static TlsContext create(Path caFile) {
        OpenSsl ssl = OpenSsl.get();
        ssl.clearErrors();
        MemorySegment method = call(() -> (MemorySegment) ssl.tlsClientMethod.invokeExact());
        MemorySegment ctx = call(() -> (MemorySegment) ssl.ctxNew.invokeExact(method));
        if (ctx.equals(MemorySegment.NULL)) {
            throw new SecretManagerException("Cannot create a TLS context: " + ssl.errors());
        }
        TlsContext context = new TlsContext(ssl, ctx);
        try (Arena arena = Arena.ofConfined()) {
            context.check(ctrl(ssl, ctx, OpenSsl.SSL_CTRL_SET_MIN_PROTO_VERSION, OpenSsl.TLS1_2_VERSION) == 1,
                    "the minimum TLS version");
            context.check(ctrl(ssl, ctx, OpenSsl.SSL_CTRL_SET_MAX_PROTO_VERSION, OpenSsl.TLS1_3_VERSION) == 1,
                    "the maximum TLS version");
            long options = OpenSsl.SSL_OP_CLEANSE_PLAINTEXT | OpenSsl.SSL_OP_NO_COMPRESSION
                    | OpenSsl.SSL_OP_NO_RENEGOTIATION;
            call(() -> (long) ssl.ctxSetOptions.invokeExact(ctx, options));
            MemorySegment suites = arena.allocateFrom(TLS13_SUITES);
            context.check(call(() -> (int) ssl.ctxSetCiphersuites.invokeExact(ctx, suites)) == 1,
                    "the TLS 1.3 cipher suites");
            MemorySegment ciphers = arena.allocateFrom(TLS12_CIPHERS);
            context.check(call(() -> (int) ssl.ctxSetCipherList.invokeExact(ctx, ciphers)) == 1,
                    "the TLS 1.2 ciphers");
            call(() -> {
                ssl.ctxSetVerify.invokeExact(ctx, OpenSsl.SSL_VERIFY_PEER, MemorySegment.NULL);
                return null;
            });
            if (caFile == null) {
                context.check(call(() -> (int) ssl.ctxSetDefaultVerifyPaths.invokeExact(ctx)) == 1,
                        "the system's trusted certificates");
            } else {
                MemorySegment file = arena.allocateFrom(caFile.toAbsolutePath().toString());
                context.check(call(() -> (int) ssl.ctxLoadVerifyLocations.invokeExact(ctx, file, MemorySegment.NULL))
                        == 1, "the CA file " + caFile);
            }
            return context;
        } catch (RuntimeException e) {
            context.close();
            throw e;
        }
    }

    private static long ctrl(OpenSsl ssl, MemorySegment ctx, int command, long argument) {
        return call(() -> (long) ssl.ctxCtrl.invokeExact(ctx, command, argument, MemorySegment.NULL));
    }

    private void check(boolean ok, String what) {
        if (!ok) {
            throw new SecretManagerException("Cannot set " + what + " for TLS: " + ssl.errors());
        }
    }

    /**
     * Starts a client session with {@code host}, a host name or an IP literal (without brackets), whose certificate
     * must match it.
     *
     * @param host the server's name or IP address
     * @return the session, to close when the connection closes
     * @throws IllegalStateException  if this context is closed
     * @throws SecretManagerException if OpenSSL cannot create the session
     */
    public TlsSession open(String host) {
        Objects.requireNonNull(host, "host");
        lock.readLock().lock();
        try {
            if (closed) {
                throw new IllegalStateException("TLS context is closed");
            }
            return newSession(host);
        } finally {
            lock.readLock().unlock();
        }
    }

    /** A session the caller owns and closes. */
    private TlsSession newSession(String host) {
        return new TlsSession(ssl, ctx, host);
    }

    /** Frees the context; sessions already open keep their own reference to it. Idempotent. */
    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            if (!closed) {
                closed = true;
                call(() -> {
                    ssl.ctxFree.invokeExact(ctx);
                    return null;
                });
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
}
