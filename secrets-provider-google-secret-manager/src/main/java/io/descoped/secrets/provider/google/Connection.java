package io.descoped.secrets.provider.google;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.channels.UnresolvedAddressException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * One connection to a server, plain or TLS, over a non-blocking {@link SocketChannel} so that every wait has a
 * deadline. Application data is read into and written from the caller's buffers, which are views of guarded memory;
 * the connection's own buffers hold only TLS records (ciphertext).
 */
abstract sealed class Connection implements AutoCloseable {

    private final SocketChannel channel;
    private final Selector selector;
    private final SelectionKey key;

    private Connection(SocketChannel channel, Selector selector) throws IOException {
        this.channel = channel;
        this.selector = selector;
        this.key = channel.register(selector, 0);
    }

    /**
     * Connects to {@code host:port}, within {@code connectTimeout} and before {@code deadline} ({@link System#nanoTime()}),
     * and for TLS completes the handshake.
     */
    static Connection open(String host, int port, boolean tls, long connectTimeoutNanos, long deadline)
            throws IOException {
        SocketChannel channel = SocketChannel.open();
        Selector selector = null;
        try {
            channel.configureBlocking(false);
            selector = Selector.open();
            Connection connection = tls ? new Tls(channel, selector, host, port) : new Plain(channel, selector);
            try {
                connection.connect(new InetSocketAddress(host, port),
                        Math.min(deadline, System.nanoTime() + connectTimeoutNanos));
                connection.start(deadline);
                return connection;
            } catch (IOException | RuntimeException e) {
                connection.close();
                throw e;
            }
        } catch (UnresolvedAddressException e) {
            closeQuietly(channel, selector);
            throw new IOException("Cannot resolve " + host, e);
        } catch (IOException | RuntimeException e) {
            closeQuietly(channel, selector);
            throw e;
        }
    }

    private static void closeQuietly(SocketChannel channel, Selector selector) {
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
     * Reads application data into {@code dst}, which has at least {@link #minReadSpace()} bytes free; returns the
     * number of bytes read, at least 1, or -1 at the end of the stream.
     */
    abstract int read(ByteBuffer dst, long deadline) throws IOException;

    /** The room {@link #read} needs in its buffer. */
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

    /** Reads at least one byte into {@code dst}, which must have room, or returns -1 at the end of the stream. */
    final int readSome(ByteBuffer dst, long deadline) throws IOException {
        while (true) {
            int n = channel.read(dst);
            if (n != 0) {
                return n;
            }
            await(SelectionKey.OP_READ, deadline);
        }
    }

    /** Closes the connection; a failure to close is of no consequence and not reported. */
    @Override
    public void close() {
        closeQuietly(channel, selector);
    }

    /** Plain TCP: the metadata server, and loopback test servers. */
    static final class Plain extends Connection {

        private Plain(SocketChannel channel, Selector selector) throws IOException {
            super(channel, selector);
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
        int read(ByteBuffer dst, long deadline) throws IOException {
            return readSome(dst, deadline);
        }

        @Override
        int minReadSpace() {
            return 1;
        }
    }

    /**
     * TLS 1.3 or 1.2 through {@link SSLEngine}, with the JDK's default trust store, host name verification and SNI.
     */
    static final class Tls extends Connection {

        private static final ByteBuffer EMPTY = ByteBuffer.allocateDirect(0);

        private final SSLEngine engine;
        /** Records received and not yet unwrapped; kept in write mode (position is the end of the data). */
        private ByteBuffer netIn;
        private final ByteBuffer netOut;

        private Tls(SocketChannel channel, Selector selector, String host, int port) throws IOException {
            super(channel, selector);
            try {
                engine = SSLContext.getDefault().createSSLEngine(host, port);
            } catch (NoSuchAlgorithmException e) {
                throw new SSLException("No TLS", e);
            }
            engine.setUseClientMode(true);
            SSLParameters parameters = engine.getSSLParameters();
            parameters.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            // SNI carries host names only, never an IP address.
            if (!host.matches("[0-9.]+") && host.indexOf(':') < 0) {
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
                switch (engine.getHandshakeStatus()) {
                    case NEED_WRAP -> wrap(EMPTY, deadline);
                    case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                        if (unwrap(scratch, deadline) < 0) {
                            throw new SSLException("The server closed the connection during the handshake");
                        }
                    }
                    case NEED_TASK -> runTasks();
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

        /**
         * Unwraps one record into {@code dst}, reading from the network as needed; returns the bytes produced (0 for
         * a record without application data), or -1 at the end of the stream.
         */
        private int unwrap(ByteBuffer dst, long deadline) throws IOException {
            while (true) {
                netIn.flip();
                SSLEngineResult result = engine.unwrap(netIn, dst);
                netIn.compact();
                switch (result.getStatus()) {
                    case OK -> {
                        return result.bytesProduced();
                    }
                    case CLOSED -> {
                        return -1;
                    }
                    case BUFFER_UNDERFLOW -> {
                        if (!netIn.hasRemaining()) {
                            ByteBuffer larger = ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize()
                                    + netIn.position());
                            netIn.flip();
                            larger.put(netIn);
                            netIn = larger;
                        }
                        if (readSome(netIn, deadline) < 0) {
                            return -1;
                        }
                    }
                    default -> throw new SSLException("No room for a TLS record");
                }
            }
        }

        @Override
        void write(ByteBuffer src, long deadline) throws IOException {
            while (src.hasRemaining()) {
                wrap(src, deadline);
            }
        }

        @Override
        int read(ByteBuffer dst, long deadline) throws IOException {
            while (true) {
                int n = unwrap(dst, deadline);
                if (n != 0) {
                    return n;
                }
                // A record without data (a session ticket, a key update): finish what it asks for, then go on.
                switch (engine.getHandshakeStatus()) {
                    case NEED_TASK -> runTasks();
                    case NEED_WRAP -> wrap(EMPTY, deadline);
                    default -> {
                        // Read the next record.
                    }
                }
            }
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
