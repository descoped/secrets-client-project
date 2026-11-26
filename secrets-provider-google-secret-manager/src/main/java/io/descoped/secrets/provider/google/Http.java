package io.descoped.secrets.provider.google;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretMemory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.ProtocolException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;

/**
 * The HTTP/1.1 this provider needs, on guarded memory: a request is built in a {@link Secret} (it may carry the access
 * token and a value), written from there, and the response is read into guarded memory and handed back as a
 * {@link Secret} body. One connection per request ({@code Connection: close}); bodies with {@code Content-Length},
 * chunked, or up to the end of the stream.
 */
final class Http {

    /** The largest response read: Secret Manager values are at most 64 KiB, about 88 KiB as Base64 in JSON. */
    static final long MAX_RESPONSE = 4L * 1024 * 1024;

    private static final long INITIAL = 32 * 1024;
    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] AUTHORIZATION = "Authorization: Bearer ".getBytes(StandardCharsets.US_ASCII);

    private Http() {
    }

    /**
     * Where requests go.
     *
     * @param tls  whether to use TLS
     * @param host the host, an IPv6 address without brackets
     * @param port the port
     * @param path the base path, without a trailing {@code /}
     */
    record Target(boolean tls, String host, int port, String path) {

        /** The target of an http or https URI. */
        static Target of(URI uri) {
            boolean tls = "https".equalsIgnoreCase(uri.getScheme());
            String host = uri.getHost();
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            int port = uri.getPort() >= 0 ? uri.getPort() : tls ? 443 : 80;
            String path = uri.getRawPath() == null ? "" : uri.getRawPath();
            while (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            return new Target(tls, host, port, path);
        }

        String hostHeader() {
            String name = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
            return port == (tls ? 443 : 80) ? name : name + ":" + port;
        }
    }

    /** How long to wait: for the connection, and for the whole exchange. */
    record Timeouts(Duration connect, Duration request) {
    }

    /** A response; its body is in guarded memory. */
    record Response(int status, Secret body) implements AutoCloseable {
        @Override
        public void close() {
            body.close();
        }
    }

    /**
     * Builds a request in guarded memory.
     *
     * @param path    the path and query, from the target's base path on; not secret
     * @param headers further header lines, without line endings; not secret
     * @param bearer  the access token for {@code Authorization: Bearer}, or {@code null}
     * @param body    the body, or {@code null} for none
     */
    static Secret request(SecretMemory memory, Target target, String method, String path, List<String> headers,
                          MemorySegment bearer, MemorySegment body) {
        StringBuilder head = new StringBuilder()
                .append(method).append(' ').append(target.path()).append(path).append(" HTTP/1.1\r\n")
                .append("Host: ").append(target.hostHeader()).append("\r\n")
                .append("User-Agent: descoped-secrets-client\r\n")
                .append("Accept: application/json\r\n")
                .append("Connection: close\r\n");
        for (String header : headers) {
            head.append(header).append("\r\n");
        }
        if (body != null) {
            head.append("Content-Length: ").append(body.byteSize()).append("\r\n");
        }
        byte[] start = head.toString().getBytes(StandardCharsets.US_ASCII);
        long length = start.length + (bearer == null ? 0 : AUTHORIZATION.length + bearer.byteSize() + CRLF.length)
                + CRLF.length + (body == null ? 0 : body.byteSize());
        return memory.allocate(length, out -> {
            long pos = Codec.putBytes(out, 0, start);
            if (bearer != null) {
                pos = Codec.putBytes(out, pos, AUTHORIZATION);
                pos = Codec.putSegment(out, pos, bearer);
                pos = Codec.putBytes(out, pos, CRLF);
            }
            pos = Codec.putBytes(out, pos, CRLF);
            if (body != null) {
                Codec.putSegment(out, pos, body);
            }
        });
    }

    /**
     * Sends {@code request} to {@code target} and reads the response into {@code memory}.
     *
     * @throws IOException if the exchange fails or times out, or the response is not HTTP/1.1 this reader accepts
     */
    static Response exchange(Target target, Secret request, Timeouts timeouts, SecretMemory memory)
            throws IOException {
        long deadline = System.nanoTime() + timeouts.request().toNanos();
        try (Connection connection = Connection.open(target.host(), target.port(), target.tls(),
                timeouts.connect().toNanos(), deadline)) {
            request.withSegment(segment -> {
                try {
                    connection.write(segment.asByteBuffer(), deadline);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                return null;
            });
            return new Reader(connection, deadline).read(memory);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    /** Reads one response into guarded memory, growing it as needed. */
    private static final class Reader {
        private final Connection connection;
        private final long deadline;
        private long filled;
        private boolean eof;
        private boolean complete;
        private long searched;
        private long headerEnd = -1;
        private int status;
        private long contentLength = -1;
        private boolean chunked;

        Reader(Connection connection, long deadline) {
            this.connection = connection;
            this.deadline = deadline;
        }

        Response read(SecretMemory memory) throws IOException {
            Secret buffer = null;
            try {
                long capacity = Math.max(INITIAL, 2L * connection.minReadSpace());
                while (true) {
                    Secret previous = buffer;
                    long copied = filled;
                    buffer = memory.allocate(capacity, segment -> {
                        if (previous != null) {
                            previous.withSegment(p -> {
                                MemorySegment.copy(p, 0, segment, 0, copied);
                                return null;
                            });
                        }
                        try {
                            fill(segment);
                        } catch (IOException e) {
                            throw new UncheckedIOException(e);
                        }
                    });
                    if (previous != null) {
                        previous.close();
                    }
                    if (complete || eof) {
                        return response(buffer, memory);
                    }
                    if (capacity >= MAX_RESPONSE + INITIAL) {
                        throw new ProtocolException("The response is too large");
                    }
                    capacity = Math.min(capacity * 2, MAX_RESPONSE + INITIAL);
                }
            } finally {
                if (buffer != null) {
                    buffer.close();
                }
            }
        }

        private void fill(MemorySegment segment) throws IOException {
            ByteBuffer buffer = segment.asByteBuffer().position(Math.toIntExact(filled));
            while (!complete) {
                if (buffer.remaining() < connection.minReadSpace()) {
                    return;
                }
                int n = connection.read(buffer, deadline);
                if (n < 0) {
                    eof = true;
                    return;
                }
                filled = buffer.position();
                update(segment);
            }
        }

        private void update(MemorySegment segment) throws ProtocolException {
            if (headerEnd < 0) {
                long end = indexOf(segment, Math.max(0, searched - 3), filled, "\r\n\r\n");
                if (end < 0) {
                    searched = filled;
                    return;
                }
                headerEnd = end + 4;
                head(segment);
            }
            if (status == 204 || status == 304 || status / 100 == 1) {
                complete = true;
            } else if (chunked) {
                complete = chunks(segment, headerEnd, filled, null) >= 0;
            } else if (contentLength >= 0) {
                complete = filled >= headerEnd + contentLength;
            }
        }

        /** The status line and the headers that frame the body; the other headers are not read. */
        private void head(MemorySegment segment) throws ProtocolException {
            long lineEnd = indexOf(segment, 0, headerEnd, "\r\n");
            String statusLine = ascii(segment, 0, lineEnd);
            if (!statusLine.matches("HTTP/1\\.[01] [1-5]\\d\\d( .*)?")) {
                throw new ProtocolException("Not an HTTP/1.1 response");
            }
            status = Integer.parseInt(statusLine.substring(9, 12));
            if (status / 100 == 1) {
                throw new ProtocolException("Unexpected interim response " + status);
            }
            long pos = lineEnd + 2;
            while (pos < headerEnd - 2) {
                long end = indexOf(segment, pos, headerEnd, "\r\n");
                long colon = indexOf(segment, pos, end, ":");
                if (colon > pos) {
                    header(segment, pos, colon, end);
                }
                pos = end + 2;
            }
        }

        private void header(MemorySegment segment, long start, long colon, long end) throws ProtocolException {
            String name = ascii(segment, start, colon).toLowerCase(Locale.ROOT);
            if (name.equals("content-length")) {
                String value = ascii(segment, colon + 1, end).strip();
                if (!value.matches("\\d{1,10}")) {
                    throw new ProtocolException("Invalid Content-Length");
                }
                long length = Long.parseLong(value);
                if (contentLength >= 0 && contentLength != length || length > MAX_RESPONSE) {
                    throw new ProtocolException(length > MAX_RESPONSE ? "The response is too large"
                            : "Conflicting Content-Length");
                }
                contentLength = length;
            } else if (name.equals("transfer-encoding")) {
                String value = ascii(segment, colon + 1, end).strip().toLowerCase(Locale.ROOT);
                chunked = value.endsWith("chunked");
            }
        }

        private Response response(Secret buffer, SecretMemory memory) throws ProtocolException {
            if (headerEnd < 0 || !complete && (chunked || contentLength >= 0)) {
                throw new ProtocolException("The connection closed before the response was complete");
            }
            long start = headerEnd;
            long end = filled;
            long length;
            if (status == 204 || status == 304) {
                length = 0;
            } else if (chunked) {
                length = buffer.withSegment(segment -> chunksUnchecked(segment, start, end, null));
            } else if (contentLength >= 0) {
                length = contentLength;
            } else {
                length = end - start;
            }
            Secret body = memory.allocate(length, out -> buffer.withSegment(segment -> {
                if (chunked) {
                    chunksUnchecked(segment, start, end, out);
                } else {
                    MemorySegment.copy(segment, start, out, 0, length);
                }
                return null;
            }));
            return new Response(status, body);
        }
    }

    private static long chunksUnchecked(MemorySegment segment, long from, long to, MemorySegment out) {
        try {
            return chunks(segment, from, to, out);
        } catch (ProtocolException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Walks a chunked body at {@code [from, to)}: returns the length of its data once it is complete (and copies the
     * data into {@code out} if not {@code null}), or -1 if more is needed.
     */
    static long chunks(MemorySegment segment, long from, long to, MemorySegment out) throws ProtocolException {
        long pos = from;
        long total = 0;
        while (true) {
            long lineEnd = indexOf(segment, pos, to, "\r\n");
            if (lineEnd < 0) {
                return -1;
            }
            long size = chunkSize(segment, pos, lineEnd);
            pos = lineEnd + 2;
            if (size == 0) {
                // Trailer lines up to an empty line.
                while (true) {
                    long end = indexOf(segment, pos, to, "\r\n");
                    if (end < 0) {
                        return -1;
                    }
                    if (end == pos) {
                        return total;
                    }
                    pos = end + 2;
                }
            }
            if (total + size > MAX_RESPONSE) {
                throw new ProtocolException("The response is too large");
            }
            if (pos + size + 2 > to) {
                return -1;
            }
            if (out != null) {
                MemorySegment.copy(segment, pos, out, total, size);
            }
            total += size;
            pos += size;
            if (byteAt(segment, pos) != '\r' || byteAt(segment, pos + 1) != '\n') {
                throw new ProtocolException("Malformed chunk");
            }
            pos += 2;
        }
    }

    private static long chunkSize(MemorySegment segment, long start, long end) throws ProtocolException {
        long size = 0;
        long pos = start;
        while (pos < end) {
            int digit = Character.digit(byteAt(segment, pos), 16);
            if (digit < 0) {
                break;
            }
            size = size << 4 | digit;
            if (size > MAX_RESPONSE) {
                throw new ProtocolException("The response is too large");
            }
            pos++;
        }
        if (pos == start || pos < end && byteAt(segment, pos) != ';' && byteAt(segment, pos) != ' '
                && byteAt(segment, pos) != '\t') {
            throw new ProtocolException("Malformed chunk size");
        }
        return size;
    }

    private static byte byteAt(MemorySegment segment, long index) {
        return segment.get(ValueLayout.JAVA_BYTE, index);
    }

    /** The first index of {@code text} (ASCII) in {@code [from, to)}, or -1. */
    private static long indexOf(MemorySegment segment, long from, long to, String text) {
        int n = text.length();
        outer:
        for (long i = from; i + n <= to; i++) {
            for (int k = 0; k < n; k++) {
                if (byteAt(segment, i + k) != text.charAt(k)) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /** Header text, which is not secret. */
    private static String ascii(MemorySegment segment, long from, long to) {
        return new String(segment.asSlice(from, to - from).toArray(ValueLayout.JAVA_BYTE),
                StandardCharsets.ISO_8859_1);
    }
}
