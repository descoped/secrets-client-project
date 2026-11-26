package io.descoped.secrets.provider.google;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
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
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * One connection to a server, plain or TLS, over a non-blocking {@link SocketChannel} so that every wait has a
 * deadline. Waiting ({@link #awaitData(long)}) is separate from reading ({@link #readAvailable(ByteBuffer)}): a caller
 * waits with no guarded memory open, then reads what has arrived into guarded memory without blocking. The
 * connection's own buffers hold only TLS records (ciphertext).
 */
abstract sealed class Connection implements AutoCloseable {

    private static final Pattern IP_LITERAL = Pattern.compile("[0-9.]+|.*:.*");

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
    static Connection open(String host, int port, SSLContext tls, long connectTimeoutNanos, long deadline)
            throws IOException {
        long connectDeadline = Math.min(deadline, System.nanoTime() + connectTimeoutNanos);
        InetSocketAddress address = new InetSocketAddress(resolve(host, connectDeadline), port);
        Connection connection = tls == null ? new Plain() : new Tls(tls, host, port);
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
        } catch (InterruptedException e) {
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
     * TLS 1.3 or 1.2 through {@link SSLEngine}, with the context's trust store, host name verification and SNI.
     * {@link #awaitData} buffers whole records (ciphertext); {@link #readAvailable} decrypts the buffered ones.
     */
    static final class Tls extends Connection {

        private static final ByteBuffer EMPTY = ByteBuffer.allocateDirect(0);
        private static final int HEADER = 5;

        private final SSLEngine engine;
        /** Records received and not yet unwrapped; kept in write mode (position is the end of the data). */
        private ByteBuffer netIn;
        private final ByteBuffer netOut;
        private boolean closed;

        private Tls(SSLContext context, String host, int port) throws IOException {
            super();
            engine = context.createSSLEngine(host, port);
            engine.setUseClientMode(true);
            SSLParameters parameters = engine.getSSLParameters();
            parameters.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            // SNI carries host names only, never an IP address.
            if (!IP_LITERAL.matcher(host).matches()) {
                parameters.setServerNames(List.of(new SNIHostName(host)));
            }
            engine.setSSLParameters(parameters);
            int packet = engine.getSession().getPacketBufferSize();
            netIn = ByteBuffer.allocateDirect(packet);
            netOut = ByteBuffer.allocateDirect(packet);
        }

        @Override
        void start(long deadline) throws IOException {
            engine.beginHandshake();
            // No application data is expected before the request is sent; this buffer only receives handshake output.
            ByteBuffer scratch = ByteBuffer.allocateDirect(engine.getSession().getApplicationBufferSize());
            while (true) {
                SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
                switch (status) {
                    case NEED_WRAP -> wrap(EMPTY, deadline);
                    case NEED_TASK -> runTasks();
                    case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                        awaitData(deadline);
                        if (!hasRecord() || unwrap(scratch) < 0) {
                            throw new SSLException("The server closed the connection during the handshake");
                        }
                    }
                    default -> {
                        if (scratch.position() > 0) {
                            throw new SSLException("The server sent data before the request");
                        }
                        return;
                    }
                }
            }
        }

        private void runTasks() {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
        }

        private void wrap(ByteBuffer src, long deadline) throws IOException {
            netOut.clear();
            SSLEngineResult result = engine.wrap(src, netOut);
            if (result.getStatus() != SSLEngineResult.Status.OK
                    && result.getStatus() != SSLEngineResult.Status.CLOSED) {
                throw new SSLException("Cannot wrap: " + result.getStatus());
            }
            netOut.flip();
            writeFully(netOut, deadline);
        }

        /** Whether {@link #netIn} holds a whole record. */
        private boolean hasRecord() {
            if (netIn.position() < HEADER) {
                return false;
            }
            int length = (netIn.get(3) & 0xFF) << 8 | netIn.get(4) & 0xFF;
            return netIn.position() >= HEADER + length;
        }

        @Override
        void awaitData(long deadline) throws IOException {
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

        /** Unwraps one buffered record into {@code dst}: the bytes produced, or -1 once the peer closed TLS. */
        private int unwrap(ByteBuffer dst) throws IOException {
            netIn.flip();
            SSLEngineResult result;
            try {
                result = engine.unwrap(netIn, dst);
            } finally {
                netIn.compact();
            }
            return switch (result.getStatus()) {
                case OK -> result.bytesProduced();
                case CLOSED -> {
                    closed = true;
                    yield -1;
                }
                default -> throw new SSLException("Cannot unwrap: " + result.getStatus());
            };
        }

        @Override
        void write(ByteBuffer src, long deadline) throws IOException {
            while (src.hasRemaining()) {
                wrap(src, deadline);
            }
        }

        @Override
        int readAvailable(ByteBuffer dst) throws IOException {
            int total = 0;
            while (!closed && hasRecord() && dst.remaining() >= minReadSpace()) {
                int n = unwrap(dst);
                if (n > 0) {
                    total += n;
                }
                // A record without data (a session ticket, a key update) may ask for a task or a reply.
                if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    runTasks();
                }
            }
            if (total == 0 && (closed || ended() && !hasRecord())) {
                return -1;
            }
            return total;
        }

        @Override
        int minReadSpace() {
            return engine.getSession().getApplicationBufferSize();
        }

        @Override
        public void close() {
            try {
                engine.closeOutbound();
            } finally {
                super.close();
            }
        }
    }
}
