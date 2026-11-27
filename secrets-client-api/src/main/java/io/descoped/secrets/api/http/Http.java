package io.descoped.secrets.api.http;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.tls.TlsContext;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.ProtocolException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The HTTP/1.1 the providers need, on guarded memory: a request is built in a {@link Secret} (it may carry the access
 * token and a value), written from there, and the response is read into guarded memory and handed back as a
 * {@link Secret} body. One connection per request ({@code Connection: close}); bodies framed by
 * {@code Content-Length} or chunked encoding.
 *
 * <p>Guarded memory is open for writing only to move bytes that have already arrived: the wait for the server
 * happens with none open ({@link Connection#awaitData(long)}).
 */
public final class Http {

    /** The largest response read: provider values are at most 64 KiB, about 88 KiB as Base64 in JSON. */
    static final long MAX_RESPONSE = 4L * 1024 * 1024;

    private static final long CHUNK = 32L * 1024;
    private static final int MAX_HEAD = 64 * 1024;
    private static final byte[] CRLF = {'\r', '\n'};
    private static final String BEARER = "Bearer ";
    private static final Pattern STATUS_LINE = Pattern.compile("HTTP/1\\.[01] ([1-5]\\d\\d)( .*)?");

    private Http() {
    }

    /**
     * Where requests go.
     *
     * @param tls  the TLS context, or {@code null} for plain http
     * @param host the host, an IPv6 address without brackets
     * @param port the port
     * @param path the base path, without a trailing {@code /}
     */
    public record Target(TlsContext tls, String host, int port, String path) {

        /**
         * The target of an http or https URI.
         *
         * @param uri the URI
         * @param tls the TLS context, used for https only
         * @return the target
         */
        public static Target of(URI uri, TlsContext tls) {
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            String host = uri.getHost();
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            int port = uri.getPort();
            if (port < 0) {
                port = secure ? 443 : 80;
            }
            String path = uri.getRawPath() == null ? "" : uri.getRawPath();
            while (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            return new Target(secure ? tls : null, host, port, path);
        }

        /**
         * The {@code Host} header's value: the host, and the port unless it is the scheme's default.
         *
         * @return the value
         */
        public String hostHeader() {
            String name = host.indexOf(':') >= 0 ? "[" + host + "]" : host;
            int defaultPort = tls == null ? 80 : 443;
            return port == defaultPort ? name : name + ":" + port;
        }
    }

    /**
     * How long to wait: for the connection, and for the whole exchange.
     *
     * @param connect for the connection, including the host name lookup
     * @param request for the whole exchange
     */
    public record Timeouts(Duration connect, Duration request) {
    }

    /**
     * A response; its body is in guarded memory.
     *
     * @param status the HTTP status code
     * @param body   the body, decoded from chunks if it came in chunks; closed with the response
     */
    public record Response(int status, Secret body) implements AutoCloseable {
        @Override
        public void close() {
            body.close();
        }
    }

    /**
     * Builds a request in guarded memory.
     *
     * @param memory  where to build it
     * @param target  the server
     * @param method  the HTTP method
     * @param path    the path and query, from the target's base path on; not secret
     * @param headers further header lines, without line endings; not secret
     * @param bearer  the access token for {@code Authorization: Bearer}, or {@code null}
     * @param body    the body, or {@code null} for none
     * @return the request, for {@link #exchange}; the caller closes it
     */
    public static Secret request(SecretMemory memory, Target target, String method, String path, List<String> headers,
                          MemorySegment bearer, MemorySegment body) {
        List<SecretHeader> secret = bearer == null ? List.of() : List.of(new SecretHeader("Authorization", BEARER,
                bearer));
        return request(memory, target, method, path, headers, secret, body);
    }

    /**
     * A header whose value is secret: {@code name: prefix value}, written into the request from guarded memory.
     *
     * @param name   the header's name, not secret
     * @param prefix text before the value, not secret ({@code ""} for none)
     * @param value  the secret part of the value
     */
    public record SecretHeader(String name, String prefix, MemorySegment value) {
    }

    /**
     * Builds a request in guarded memory, with headers whose values are secret.
     *
     * @param memory        where to build it
     * @param target        the server
     * @param method        the HTTP method
     * @param path          the path and query, from the target's base path on; not secret
     * @param headers       further header lines, without line endings; not secret
     * @param secretHeaders headers whose values are secret, written after the others
     * @param body          the body, or {@code null} for none
     * @return the request, for {@link #exchange}; the caller closes it
     * @throws IllegalArgumentException if a secret header's value has a control character, such as CR or LF, which
     *                                  would end the header and start another
     */
    public static Secret request(SecretMemory memory, Target target, String method, String path, List<String> headers,
                                 List<SecretHeader> secretHeaders, MemorySegment body) {
        for (SecretHeader header : secretHeaders) {
            if (hasControl(header.value())) {
                // The name only: the value is secret.
                throw new IllegalArgumentException("The value of the header " + header.name()
                        + " has a control character");
            }
        }
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
        List<byte[]> names = secretHeaders.stream()
                .map(h -> (h.name() + ": " + h.prefix()).getBytes(StandardCharsets.US_ASCII))
                .toList();
        long length = start.length + CRLF.length + (body == null ? 0 : body.byteSize());
        for (int i = 0; i < names.size(); i++) {
            length += names.get(i).length + secretHeaders.get(i).value().byteSize() + CRLF.length;
        }
        return memory.allocate(length, out -> {
            long pos = Codec.putBytes(out, 0, start);
            for (int i = 0; i < names.size(); i++) {
                pos = Codec.putBytes(out, pos, names.get(i));
                pos = Codec.putSegment(out, pos, secretHeaders.get(i).value());
                pos = Codec.putBytes(out, pos, CRLF);
            }
            pos = Codec.putBytes(out, pos, CRLF);
            if (body != null) {
                Codec.putSegment(out, pos, body);
            }
        });
    }

    /** Whether {@code value} has a byte that a header value may not: a control character other than tab (RFC 9110). */
    private static boolean hasControl(MemorySegment value) {
        for (long i = 0; i < value.byteSize(); i++) {
            byte b = value.get(ValueLayout.JAVA_BYTE, i);
            if (b >= 0 && b < 0x20 && b != '\t' || b == 0x7F) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sends {@code request} to {@code target} and reads the response into {@code memory}.
     *
     * @param target   the server
     * @param request  the request, as {@link #request} built it
     * @param timeouts how long to wait
     * @param memory   where to read the response
     * @return the response, which the caller closes
     * @throws IOException if the exchange fails or times out, or the response is not HTTP/1.1 this reader accepts
     */
    public static Response exchange(Target target, Secret request, Timeouts timeouts, SecretMemory memory)
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
            return read(connection, deadline, memory);
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    /**
     * Reads the response: each burst of data into a chunk of guarded memory, opened only once the data has arrived,
     * then the body from the chunks into one secret.
     */
    private static Response read(Connection connection, long deadline, SecretMemory memory) throws IOException {
        Framing framing = new Framing();
        long total = 0;
        try (Chunks received = new Chunks()) {
            List<Secret> chunks = received.secrets;
            List<Long> lengths = received.lengths;
            boolean ended = false;
            while (!framing.complete() && !ended) {
                connection.awaitData(deadline);
                long[] read = {0};
                boolean[] end = {false};
                try (Secret burst = memory.allocate(Math.max(CHUNK, 2L * connection.minReadSpace()), segment -> {
                    try {
                        read[0] = fill(connection, segment, end);
                        framing.feed(segment, read[0]);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                })) {
                    // Kept at its exact size, so that a response arriving in many small bursts holds no more locked
                    // memory than its own size.
                    long length = read[0];
                    chunks.add(memory.allocate(length, out -> burst.withSegment(in -> {
                        MemorySegment.copy(in, 0, out, 0, length);
                        return null;
                    })));
                }
                lengths.add(read[0]);
                ended = end[0];
                total += read[0];
                if (total > MAX_RESPONSE + MAX_HEAD) {
                    throw new ProtocolException("The response is too large");
                }
            }
            if (!framing.complete()) {
                throw new ProtocolException("The connection closed before the response was complete");
            }
            Framing copy = new Framing();
            Secret body = memory.allocate(framing.bodyLength(), out -> {
                copy.output(out);
                for (int i = 0; i < chunks.size(); i++) {
                    long length = lengths.get(i);
                    chunks.get(i).withSegment(segment -> {
                        copy.feedUnchecked(segment, length);
                        return null;
                    });
                }
            });
            return new Response(framing.status(), body);
        }
    }

    /** The parts of a response as they arrived, closed once the body is assembled. */
    private static final class Chunks implements AutoCloseable {
        private final List<Secret> secrets = new ArrayList<>();
        private final List<Long> lengths = new ArrayList<>();

        @Override
        public void close() {
            secrets.forEach(Secret::close);
        }
    }

    /** Reads what has arrived into {@code segment} without waiting; notes the end of the stream in {@code end}. */
    private static long fill(Connection connection, MemorySegment segment, boolean[] end) throws IOException {
        ByteBuffer buffer = segment.asByteBuffer();
        int n = 1;
        while (n > 0 && buffer.remaining() >= connection.minReadSpace()) {
            n = connection.readAvailable(buffer);
        }
        end[0] = n < 0;
        return buffer.position();
    }

    /**
     * The framing of a response, fed its bytes in order: the head (status line and headers, which are not secret and
     * are collected on the heap), then a body framed by {@code Content-Length} or chunked encoding. Given an output
     * segment, it also copies the body's data there.
     */
    private static final class Framing {

        private enum State { HEAD, BODY, SIZE, SIZE_END, DATA, DATA_CR, DATA_LF, TRAILER, TRAILER_LINE, DONE }

        private final ByteArrayOutputStream head = new ByteArrayOutputStream();
        private MemorySegment out;
        private int tail;
        private State state = State.HEAD;
        private int status;
        private long contentLength = -1;
        private boolean chunked;
        private long remaining;
        private long size;
        private boolean sizeDigits;
        private long bodyLength;
        private long written;

        void output(MemorySegment segment) {
            this.out = segment;
        }

        boolean complete() {
            return state == State.DONE;
        }

        int status() {
            return status;
        }

        long bodyLength() {
            return bodyLength;
        }

        void feedUnchecked(MemorySegment segment, long length) {
            try {
                feed(segment, length);
            } catch (ProtocolException e) {
                throw new UncheckedIOException(e);
            }
        }

        /** Takes the bytes {@code [0, length)} of {@code segment}. */
        void feed(MemorySegment segment, long length) throws ProtocolException {
            long pos = 0;
            while (pos < length && state != State.DONE) {
                if (state == State.BODY || state == State.DATA) {
                    long n = Math.min(remaining, length - pos);
                    data(segment, pos, n);
                    pos += n;
                    remaining -= n;
                    if (remaining == 0) {
                        state = state == State.BODY ? State.DONE : State.DATA_CR;
                    }
                } else {
                    step(segment.get(ValueLayout.JAVA_BYTE, pos++));
                }
            }
            if (pos < length) {
                throw new ProtocolException("Data after the response");
            }
        }

        private void data(MemorySegment segment, long from, long n) {
            if (out != null) {
                MemorySegment.copy(segment, from, out, written, n);
            }
            written += n;
        }

        private void step(byte b) throws ProtocolException {
            switch (state) {
                case HEAD -> head(b);
                case SIZE -> size(b);
                case SIZE_END -> extension(b);
                case DATA_CR -> expect(b, '\r', State.DATA_LF);
                case DATA_LF -> expect(b, '\n', State.SIZE);
                case TRAILER -> trailer(b);
                case TRAILER_LINE -> trailerLine(b);
                default -> throw new ProtocolException("Unexpected framing state");
            }
        }

        private void expect(byte b, char wanted, State next) throws ProtocolException {
            if (b != wanted) {
                throw new ProtocolException("Malformed chunk");
            }
            state = next;
        }

        private void head(byte b) throws ProtocolException {
            head.write(b);
            if (head.size() > MAX_HEAD) {
                throw new ProtocolException("The response head is too large");
            }
            tail = tail << 8 | b & 0xFF;
            if (tail == 0x0D0A0D0A) {
                parseHead(head.toString(StandardCharsets.ISO_8859_1));
            }
        }

        private void parseHead(String text) throws ProtocolException {
            String[] lines = text.split("\r\n");
            java.util.regex.Matcher statusLine = STATUS_LINE.matcher(lines[0]);
            if (!statusLine.matches()) {
                throw new ProtocolException("Not an HTTP/1.1 response");
            }
            status = Integer.parseInt(statusLine.group(1));
            if (status / 100 == 1) {
                throw new ProtocolException("Unexpected interim response " + status);
            }
            for (int i = 1; i < lines.length; i++) {
                int colon = lines[i].indexOf(':');
                if (colon > 0) {
                    header(lines[i].substring(0, colon).strip().toLowerCase(Locale.ROOT),
                            lines[i].substring(colon + 1).strip());
                }
            }
            if (status == 204 || status == 304) {
                state = State.DONE;
            } else if (chunked) {
                state = State.SIZE;
            } else if (contentLength >= 0) {
                bodyLength = contentLength;
                remaining = contentLength;
                state = contentLength == 0 ? State.DONE : State.BODY;
            } else {
                throw new ProtocolException("The response has neither Content-Length nor chunked encoding");
            }
        }

        private void header(String name, String value) throws ProtocolException {
            if (name.equals("content-length")) {
                if (!value.matches("\\d{1,10}")) {
                    throw new ProtocolException("Invalid Content-Length");
                }
                long length = Long.parseLong(value);
                if (length > MAX_RESPONSE) {
                    throw new ProtocolException("The response is too large");
                }
                if (contentLength >= 0 && contentLength != length) {
                    throw new ProtocolException("Conflicting Content-Length");
                }
                contentLength = length;
            } else if (name.equals("transfer-encoding")) {
                chunked = value.toLowerCase(Locale.ROOT).endsWith("chunked");
            }
        }

        private void size(byte b) throws ProtocolException {
            int digit = Character.digit(b, 16);
            if (digit >= 0) {
                size = size << 4 | digit;
                sizeDigits = true;
                if (bodyLength + size > MAX_RESPONSE) {
                    throw new ProtocolException("The response is too large");
                }
            } else if (!sizeDigits) {
                throw new ProtocolException("Malformed chunk size");
            } else if (b == '\n') {
                endOfSize();
            } else {
                state = State.SIZE_END;
            }
        }

        private void endOfSize() {
            if (size == 0) {
                state = State.TRAILER;
            } else {
                bodyLength += size;
                remaining = size;
                state = State.DATA;
            }
            size = 0;
            sizeDigits = false;
        }

        /** A chunk extension, ignored, up to the line feed. */
        private void extension(byte b) {
            if (b == '\n') {
                endOfSize();
            }
        }

        /** Inside a trailer line, ignored, up to the line feed. */
        private void trailerLine(byte b) {
            if (b == '\n') {
                state = State.TRAILER;
            }
        }

        /** At the start of a trailer line: an empty line ends the body, any other is skipped. */
        private void trailer(byte b) {
            if (b == '\n') {
                state = State.DONE;
            } else if (b != '\r') {
                state = State.TRAILER_LINE;
            }
        }
    }
}
