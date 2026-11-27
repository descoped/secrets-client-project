package io.descoped.secrets.provider.google;

import io.descoped.secrets.api.tls.TlsContext;
import io.descoped.secrets.api.tls.TlsSession;

import javax.net.ssl.SSLException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * One connection to a server, plain or TLS, over a non-blocking {@link SocketChannel} so that every wait has a
 * deadline. Waiting ({@link #awaitData(long)}) is separate from reading ({@link #readAvailable(ByteBuffer)}): a caller
 * waits with no guarded memory open, then reads what has arrived into guarded memory without blocking. The
 * connection's own buffers hold only TLS records (ciphertext).
 */
abstract sealed class Connection implements AutoCloseable {

    private final SocketChannel channel;
    private final Selector selector;
    private final SelectionKey key;
    private boolean eof;

    private Connection() throws IOException {
        SocketChannel opened = SocketChannel.open();
        Selector waiter = null;
        try {
            opened.configureBlocking(false);
            waiter = Selector.open();
            this.key = opened.register(waiter, 0);
        } catch (IOException e) {
            closeQuietly(opened, waiter);
            throw e;
        }
        this.channel = opened;
        this.selector = waiter;
    }

    /**
     * Connects to {@code host:port} (the name looked up, and the connection made, within {@code connectTimeout} and
     * before {@code deadline}, both {@link System#nanoTime()}), and for TLS completes the handshake.
     */
    static Connection open(String host, int port, TlsContext tls, long connectTimeoutNanos, long deadline)
            throws IOException {
        long connectDeadline = Math.min(deadline, System.nanoTime() + connectTimeoutNanos);
        InetSocketAddress address = new InetSocketAddress(resolve(host, connectDeadline), port);
        Connection connection = tls == null ? new Plain() : new Tls(tls, host);
        try {
            connection.connect(address, connectDeadline);
            connection.start(deadline);
            return connection;
        } catch (IOException | RuntimeException e) {
            connection.close();
            throw e;
        }
    }

    /** Looks {@code host} up within the deadline: the JDK's resolver has no timeout of its own. */
    private static InetAddress resolve(String host, long deadline) throws IOException {
        AtomicReference<Object> result = new AtomicReference<>();
        Thread lookup = Thread.ofVirtual().start(() -> {
            try {
                result.set(InetAddress.getByName(host));
            } catch (UnknownHostException e) {
                result.set(e);
            }
        });
        try {
            if (!lookup.join(java.time.Duration.ofNanos(Math.max(1, deadline - System.nanoTime())))) {
                throw new SocketTimeoutException("Timed out looking up " + host);
            }
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("Interrupted looking up " + host);
        }
        if (result.get() instanceof InetAddress address) {
            return address;
        }
        throw (UnknownHostException) result.get();
    }

    static void closeQuietly(SocketChannel channel, Selector selector) {
        try {
            channel.close();
        } catch (IOException _) {
            // Nothing to do about it; a failure being thrown is what is reported.
        }
        if (selector != null) {
            try {
                selector.close();
            } catch (IOException _) {
                // As above.
            }
        }
    }

    private void connect(InetSocketAddress address, long deadline) throws IOException {
        if (!channel.connect(address)) {
            while (!channel.finishConnect()) {
                await(SelectionKey.OP_CONNECT, deadline);
            }
        }
    }

    /** Called once connected: the TLS handshake. */
    abstract void start(long deadline) throws IOException;

    /** Writes all of {@code src}. */
    abstract void write(ByteBuffer src, long deadline) throws IOException;

    /**
     * Waits until {@link #readAvailable} has something to give, or the stream has ended. Holds no application data.
     */
    abstract void awaitData(long deadline) throws IOException;

    /**
     * Reads the application data that has arrived into {@code dst}, which has at least {@link #minReadSpace()} bytes
     * free, without waiting; returns the number of bytes, 0 if none has arrived, or -1 at the end of the stream.
     */
    abstract int readAvailable(ByteBuffer dst) throws IOException;

    /** The room {@link #readAvailable} needs in its buffer. */
    abstract int minReadSpace();

    /** Waits until the channel is ready for {@code ops}, or fails at the deadline or on an interrupt. */
    final void await(int ops, long deadline) throws IOException {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw new SocketTimeoutException("Timed out");
        }
        key.interestOps(ops);
        selector.select(Math.max(1, TimeUnit.NANOSECONDS.toMillis(remaining)));
        selector.selectedKeys().clear();
        key.interestOps(0);
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("Interrupted");
        }
    }

    final void writeFully(ByteBuffer src, long deadline) throws IOException {
        while (src.hasRemaining()) {
            if (channel.write(src) == 0) {
                await(SelectionKey.OP_WRITE, deadline);
            }
        }
    }

    /** Reads what the socket has into {@code dst} without waiting: the bytes read, 0 if none, -1 at the end. */
    final int readSocket(ByteBuffer dst) throws IOException {
        if (eof) {
            return -1;
        }
        int n = channel.read(dst);
        if (n < 0) {
            eof = true;
        }
        return n;
    }

    final boolean ended() {
        return eof;
    }

    /** Closes the connection; a failure to close is of no consequence and not reported. */
    @Override
    public void close() {
        closeQuietly(channel, selector);
    }

    /** Plain TCP: the metadata server, and loopback test servers. */
    static final class Plain extends Connection {

        private Plain() throws IOException {
            super();
        }

        @Override
        void start(long deadline) {
            // Nothing to set up.
        }

        @Override
        void write(ByteBuffer src, long deadline) throws IOException {
            writeFully(src, deadline);
        }

        @Override
        void awaitData(long deadline) throws IOException {
            if (!ended()) {
                await(SelectionKey.OP_READ, deadline);
            }
        }

        @Override
        int readAvailable(ByteBuffer dst) throws IOException {
            int total = 0;
            while (dst.hasRemaining()) {
                int n = readSocket(dst);
                if (n <= 0) {
                    return total == 0 && n < 0 ? -1 : total;
                }
                total += n;
            }
            return total;
        }

        @Override
        int minReadSpace() {
            return 1;
        }
    }

    /**
     * TLS through OpenSSL ({@link TlsSession}), with the context's trust, host name verification and SNI.
     * {@link #awaitData} buffers whole records (ciphertext); {@link #readAvailable} hands them to OpenSSL and decrypts
     * them straight into the caller's buffer, so plaintext is never on the Java heap.
     */
    static final class Tls extends Connection {

        private static final int HEADER = 5;
        /** The largest TLS record with its header, and room to spare. */
        private static final int RECORD = 18 * 1024;

        private final TlsSession session;
        /** Records received and not yet given to OpenSSL; kept in write mode (position is the end of the data). */
        private ByteBuffer netIn = ByteBuffer.allocateDirect(RECORD);
        private final ByteBuffer netOut = ByteBuffer.allocateDirect(RECORD);
        private boolean closed;

        private Tls(TlsContext context, String host) throws IOException {
            super();
            try {
                session = context.open(host);
            } catch (RuntimeException e) {
                super.close();
                throw e;
            }
        }

        @Override
        void start(long deadline) throws IOException {
            while (session.handshake() == TlsSession.Handshake.WANT_READ) {
                flush(deadline);
                awaitData(deadline);
                if (!hasRecord()) {
                    throw new SSLException("The server closed the connection during the handshake");
                }
                feedRecords();
            }
            // The last flight (Finished) is sent with the request.
            flush(deadline);
        }

        /** Sends what OpenSSL has to send. */
        private void flush(long deadline) throws IOException {
            while (session.hasOutput()) {
                netOut.clear();
                session.drain(netOut);
                netOut.flip();
                writeFully(netOut, deadline);
            }
        }

        /** Whether {@link #netIn} holds a whole record. */
        private boolean hasRecord() {
            if (netIn.position() < HEADER) {
                return false;
            }
            int length = (netIn.get(3) & 0xFF) << 8 | netIn.get(4) & 0xFF;
            return netIn.position() >= HEADER + length;
        }

        /** Gives OpenSSL every whole record in {@link #netIn}. */
        private void feedRecords() throws SSLException {
            netIn.flip();
            int end = 0;
            while (netIn.remaining() - end >= HEADER) {
                int at = netIn.position() + end;
                int length = (netIn.get(at + 3) & 0xFF) << 8 | netIn.get(at + 4) & 0xFF;
                if (netIn.remaining() - end < HEADER + length) {
                    break;
                }
                end += HEADER + length;
            }
            ByteBuffer records = netIn.slice(netIn.position(), end);
            session.feed(records);
            netIn.position(netIn.position() + end);
            netIn.compact();
        }

        @Override
        void write(ByteBuffer src, long deadline) throws IOException {
            session.write(src);
            flush(deadline);
        }

        @Override
        void awaitData(long deadline) throws IOException {
            if (session.hasBuffered()) {
                return;
            }
            while (!hasRecord() && !ended()) {
                if (!netIn.hasRemaining()) {
                    ByteBuffer larger = ByteBuffer.allocateDirect(netIn.capacity() * 2);
                    netIn.flip();
                    larger.put(netIn);
                    netIn = larger;
                }
                if (readSocket(netIn) == 0) {
                    await(SelectionKey.OP_READ, deadline);
                }
            }
        }

        @Override
        int readAvailable(ByteBuffer dst) throws IOException {
            if (closed) {
                return -1;
            }
            if (hasRecord()) {
                feedRecords();
            }
            int total = 0;
            int n = 1;
            while (n > 0 && dst.hasRemaining()) {
                n = session.read(dst);
                if (n > 0) {
                    total += n;
                }
            }
            closed = n < 0;
            if (total == 0 && (closed || ended() && !hasRecord() && !session.hasBuffered())) {
                return -1;
            }
            return total;
        }

        @Override
        int minReadSpace() {
            return 1;
        }

        @Override
        public void close() {
            try {
                session.close();
            } finally {
                super.close();
            }
        }
    }
}
