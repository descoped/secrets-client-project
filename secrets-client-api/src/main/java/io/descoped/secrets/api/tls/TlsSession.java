package io.descoped.secrets.api.tls;

import io.descoped.secrets.api.SecretManagerException;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

import static io.descoped.secrets.api.tls.OpenSsl.call;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

/**
 * One TLS client connection on memory buffers: the caller moves ciphertext between the network and the session
 * ({@link #feed}, {@link #drain}), and plaintext in and out of it ({@link #write}, {@link #read}). Plaintext goes
 * straight between the caller's buffer and OpenSSL, never through the Java heap: pass buffers of guarded memory.
 *
 * <p>Every buffer must be direct. Not thread-safe: one connection, one thread at a time.
 */
@SuppressWarnings("restricted")
public final class TlsSession implements AutoCloseable {

    /** What {@link #handshake()} needs next. */
    public enum Handshake {
        /** Done: the server is verified and data can be sent. */
        DONE,
        /** More data from the server is needed: {@link #drain} what is to be sent, then {@link #feed} the reply. */
        WANT_READ
    }

    private final OpenSsl ssl;
    private final Arena arena = Arena.ofShared();
    private final MemorySegment session;
    private final MemorySegment rbio;
    private final MemorySegment wbio;
    private final MemorySegment size;
    private boolean closed;

    TlsSession(OpenSsl ssl, MemorySegment ctx, String host) {
        this.ssl = ssl;
        this.size = arena.allocate(JAVA_LONG);
        ssl.clearErrors();
        session = call(() -> (MemorySegment) ssl.sslNew.invokeExact(ctx));
        if (session.equals(MemorySegment.NULL)) {
            arena.close();
            throw new SecretManagerException("Cannot create a TLS session: " + ssl.errors());
        }
        try {
            MemorySegment memoryBio = call(() -> (MemorySegment) ssl.bioSMem.invokeExact());
            rbio = call(() -> (MemorySegment) ssl.bioNew.invokeExact(memoryBio));
            wbio = call(() -> (MemorySegment) ssl.bioNew.invokeExact(memoryBio));
            if (rbio.equals(MemorySegment.NULL) || wbio.equals(MemorySegment.NULL)) {
                throw new SecretManagerException("Cannot create TLS buffers: " + ssl.errors());
            }
            // The session owns the buffers from here, and frees them with itself.
            call(() -> {
                ssl.sslSetBio.invokeExact(session, rbio, wbio);
                return null;
            });
            // Free the record buffers while idle, so plaintext does not stay in them longer than needed.
            call(() -> (long) ssl.sslCtrl.invokeExact(session, OpenSsl.SSL_CTRL_MODE,
                    OpenSsl.SSL_MODE_RELEASE_BUFFERS, MemorySegment.NULL));
            MemorySegment name = arena.allocateFrom(host);
            if (isIpLiteral(host)) {
                MemorySegment param = call(() -> (MemorySegment) ssl.sslGet0Param.invokeExact(session));
                check(call(() -> (int) ssl.paramSet1IpAsc.invokeExact(param, name)) == 1, "the IP address " + host);
            } else {
                check(call(() -> (int) ssl.sslSet1Host.invokeExact(session, name)) == 1, "the host name " + host);
                check(call(() -> (long) ssl.sslCtrl.invokeExact(session, OpenSsl.SSL_CTRL_SET_TLSEXT_HOSTNAME,
                        OpenSsl.TLSEXT_NAMETYPE_HOST_NAME, name)) == 1, "the server name " + host);
            }
            call(() -> {
                ssl.sslSetConnectState.invokeExact(session);
                return null;
            });
        } catch (RuntimeException e) {
            close();
            throw e;
        }
    }

    private void check(boolean ok, String what) {
        if (!ok) {
            throw new SecretManagerException("Cannot set " + what + " for TLS: " + ssl.errors());
        }
    }

    /** Whether {@code host} is an IP address: IPv6 has a colon, IPv4 is digits and dots only. */
    static boolean isIpLiteral(String host) {
        return host.indexOf(':') >= 0 || !host.isEmpty() && host.chars().allMatch(c -> c == '.' || c >= '0' && c <= '9');
    }

    /**
     * Advances the handshake as far as the data fed so far allows. When it is done, the server's certificate has
     * been verified against the trusted roots and the host.
     *
     * @return {@link Handshake#DONE}, or {@link Handshake#WANT_READ} for more data from the server
     * @throws SSLHandshakeException if the handshake fails, the certificate among the reasons
     */
    public Handshake handshake() throws SSLHandshakeException {
        checkOpen();
        ssl.clearErrors();
        int result = call(() -> (int) ssl.sslDoHandshake.invokeExact(session));
        if (result == 1) {
            verified();
            return Handshake.DONE;
        }
        int error = error(result);
        if (error == OpenSsl.SSL_ERROR_WANT_READ || error == OpenSsl.SSL_ERROR_WANT_WRITE) {
            return Handshake.WANT_READ;
        }
        long verify = call(() -> (long) ssl.sslGetVerifyResult.invokeExact(session));
        if (verify != OpenSsl.X509_V_OK) {
            throw new SSLHandshakeException("The server's certificate is not accepted: " + verifyError(verify));
        }
        throw new SSLHandshakeException("The TLS handshake failed: " + ssl.errors());
    }

    /** Checks, once more, what OpenSSL checked during the handshake: a certificate, verified. */
    private void verified() throws SSLHandshakeException {
        MemorySegment certificate = call(() -> (MemorySegment) ssl.sslGet0PeerCertificate.invokeExact(session));
        if (certificate.equals(MemorySegment.NULL)) {
            throw new SSLHandshakeException("The server sent no certificate");
        }
        long verify = call(() -> (long) ssl.sslGetVerifyResult.invokeExact(session));
        if (verify != OpenSsl.X509_V_OK) {
            throw new SSLHandshakeException("The server's certificate is not accepted: " + verifyError(verify));
        }
    }

    private String verifyError(long code) {
        MemorySegment text = call(() -> (MemorySegment) ssl.verifyErrorString.invokeExact(code));
        return text.equals(MemorySegment.NULL) ? "error " + code : text.reinterpret(1024).getString(0);
    }

    private int error(int result) {
        return call(() -> (int) ssl.sslGetError.invokeExact(session, result));
    }

    /**
     * Gives the session what arrived from the server, all of {@code src}'s remaining bytes.
     *
     * @param src ciphertext, in a direct buffer
     * @throws SSLException if OpenSSL cannot buffer it
     */
    public void feed(ByteBuffer src) throws SSLException {
        checkOpen();
        while (src.hasRemaining()) {
            MemorySegment from = segment(src);
            int length = src.remaining();
            int n = call(() -> (int) ssl.bioWrite.invokeExact(rbio, from, length));
            if (n <= 0) {
                throw new SSLException("Cannot buffer TLS data: " + ssl.errors());
            }
            src.position(src.position() + n);
        }
    }

    /**
     * Whether the session has data to send to the server.
     *
     * @return {@code true} if {@link #drain} gives something
     */
    public boolean hasOutput() {
        checkOpen();
        return call(() -> (long) ssl.bioCtrlPending.invokeExact(wbio)) > 0;
    }

    /**
     * Moves what is to be sent to the server into {@code dst}, as much as fits.
     *
     * @param dst a direct buffer for ciphertext
     * @return the number of bytes moved
     */
    public int drain(ByteBuffer dst) {
        checkOpen();
        long pending = call(() -> (long) ssl.bioCtrlPending.invokeExact(wbio));
        if (pending <= 0 || !dst.hasRemaining()) {
            return 0;
        }
        MemorySegment to = segment(dst);
        int length = (int) Math.min(dst.remaining(), pending);
        int n = call(() -> (int) ssl.bioRead.invokeExact(wbio, to, length));
        if (n <= 0) {
            return 0;
        }
        dst.position(dst.position() + n);
        return n;
    }

    /**
     * Encrypts all of {@code src}'s remaining bytes for the server; {@link #drain} gives the ciphertext.
     *
     * @param src plaintext, in a direct buffer (guarded memory)
     * @throws SSLException if OpenSSL refuses
     */
    public void write(ByteBuffer src) throws SSLException {
        checkOpen();
        while (src.hasRemaining()) {
            MemorySegment from = segment(src);
            long length = src.remaining();
            ssl.clearErrors();
            int result = call(() -> (int) ssl.sslWriteEx.invokeExact(session, from, length, size));
            if (result != 1) {
                throw new SSLException("TLS write failed: " + ssl.errors());
            }
            src.position(src.position() + (int) size.get(JAVA_LONG, 0));
        }
    }

    /**
     * Decrypts what has been fed into {@code dst}, as much as fits.
     *
     * @param dst a direct buffer (guarded memory) for plaintext
     * @return the number of bytes, 0 if more data from the server is needed, or -1 once the server closed TLS
     * @throws SSLException if the data is not valid TLS
     */
    public int read(ByteBuffer dst) throws SSLException {
        checkOpen();
        if (!dst.hasRemaining()) {
            return 0;
        }
        MemorySegment to = segment(dst);
        long length = dst.remaining();
        ssl.clearErrors();
        int result = call(() -> (int) ssl.sslReadEx.invokeExact(session, to, length, size));
        if (result == 1) {
            int n = (int) size.get(JAVA_LONG, 0);
            dst.position(dst.position() + n);
            return n;
        }
        int error = error(result);
        if (error == OpenSsl.SSL_ERROR_WANT_READ || error == OpenSsl.SSL_ERROR_WANT_WRITE) {
            return 0;
        }
        if (error == OpenSsl.SSL_ERROR_ZERO_RETURN) {
            return -1;
        }
        throw new SSLException("TLS read failed: " + ssl.errors());
    }

    /**
     * The number of decrypted bytes buffered in the session, which {@link #read} gives without more data.
     *
     * @return the number of bytes
     */
    public int pending() {
        checkOpen();
        return call(() -> (int) ssl.sslPending.invokeExact(session));
    }

    /** Queues a close_notify for the server, which {@link #drain} gives; failures are of no consequence. */
    public void shutdown() {
        if (!closed) {
            ssl.clearErrors();
            call(() -> (int) ssl.sslShutdown.invokeExact(session));
            ssl.clearErrors();
        }
    }

    /** Frees the session and its buffers. Idempotent. */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            if (!session.equals(MemorySegment.NULL)) {
                call(() -> {
                    ssl.sslFree.invokeExact(session);
                    return null;
                });
            }
        } finally {
            arena.close();
        }
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("TLS session is closed");
        }
    }

    private static MemorySegment segment(ByteBuffer buffer) {
        if (!buffer.isDirect()) {
            throw new IllegalArgumentException("TLS buffers must be direct");
        }
        return MemorySegment.ofBuffer(buffer);
    }
}
