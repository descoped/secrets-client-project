package io.descoped.secrets.api.test;

import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.tls.TlsContext;
import io.descoped.secrets.api.tls.TlsSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link TlsSession} (OpenSSL) as a client against the JDK's {@link SSLEngine} as a server, in memory: the test moves
 * the records between them. Certificates are made by keytool; the client trusts them through a CA file.
 */
class TlsSessionTest {

    private static final String PASSWORD = "changeit";

    @TempDir
    static Path keys;

    /** A server for 127.0.0.1 and localhost, trusted. */
    private static SSLContext server;
    /** A server whose certificate is not in the CA file. */
    private static SSLContext untrusted;
    private static Path trusted;

    @BeforeAll
    static void certificates() throws IOException, InterruptedException, GeneralSecurityException {
        trusted = keys.resolve("trusted.pem");
        server = server("server", "SAN=ip:127.0.0.1,dns:localhost", true);
        untrusted = server("untrusted", "SAN=ip:127.0.0.1", false);
    }

    private static SSLContext server(String alias, String san, boolean trust)
            throws IOException, InterruptedException, GeneralSecurityException {
        Path store = keys.resolve(alias + ".p12");
        Path certificate = keys.resolve(alias + ".pem");
        keytool("-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + alias,
                "-ext", san, "-validity", "2", "-keystore", store.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD);
        keytool("-exportcert", "-rfc", "-alias", alias, "-keystore", store.toString(), "-storepass", PASSWORD,
                "-file", certificate.toString());
        if (trust) {
            Files.writeString(trusted, Files.readString(certificate, StandardCharsets.US_ASCII),
                    StandardCharsets.US_ASCII, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(KeyStore.getInstance(store.toFile(), PASSWORD.toCharArray()), PASSWORD.toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), null, null);
        return context;
    }

    private static void keytool(String... arguments) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "keytool finishes");
        assertEquals(0, process.exitValue(), output);
    }

    /** A connected pair: an OpenSSL client and a JDK server. */
    private static final class Pair {
        final TlsSession client;
        final SSLEngine engine;
        final ByteBuffer serverApp = ByteBuffer.allocate(256 * 1024);

        Pair(TlsSession client, SSLContext serverContext) {
            this.client = client;
            this.engine = serverContext.createSSLEngine();
            engine.setUseClientMode(false);
        }

        /** Moves what the client has to send into the server. */
        void toServer() throws IOException {
            ByteBuffer records = ByteBuffer.allocateDirect(256 * 1024);
            while (client.hasOutput()) {
                client.drain(records);
            }
            records.flip();
            while (records.hasRemaining()) {
                SSLEngineResult result = engine.unwrap(records, serverApp);
                tasks();
                if (result.getStatus() != SSLEngineResult.Status.OK) {
                    break;
                }
            }
        }

        /** Moves what the server has to send (handshake messages, then {@code data}) into the client. */
        void toClient(ByteBuffer data) throws IOException {
            ByteBuffer records = ByteBuffer.allocateDirect(512 * 1024);
            do {
                engine.wrap(data, records);
                tasks();
            } while (data.hasRemaining()
                    || engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP);
            records.flip();
            client.feed(records);
        }

        private void tasks() {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
        }

        /** Runs the handshake to its end on both sides. */
        void handshake() throws IOException {
            for (int round = 0; round < 10; round++) {
                TlsSession.Handshake state = client.handshake();
                toServer();
                toClient(ByteBuffer.allocate(0));
                if (state == TlsSession.Handshake.DONE
                        && engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    return;
                }
            }
            throw new AssertionError("The handshake did not finish");
        }

        /** Reads everything the client has into a heap array, through a direct buffer of {@code chunk} bytes. */
        byte[] readAll(int chunk) throws IOException {
            ByteBuffer out = ByteBuffer.allocateDirect(chunk);
            java.io.ByteArrayOutputStream all = new java.io.ByteArrayOutputStream();
            int n;
            do {
                out.clear();
                n = client.read(out);
                out.flip();
                byte[] part = new byte[out.remaining()];
                out.get(part);
                all.writeBytes(part);
            } while (n > 0 || client.hasBuffered());
            return all.toByteArray();
        }
    }

    private static ByteBuffer direct(byte[] bytes) {
        return ByteBuffer.allocateDirect(bytes.length).put(bytes).flip();
    }

    @Test
    void aClientHandshakesAndExchangesDataWithAnIpAddress() throws IOException {
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open("127.0.0.1")) {
            Pair pair = new Pair(client, server);
            pair.handshake();

            client.write(direct("hello".getBytes(StandardCharsets.US_ASCII)));
            pair.toServer();
            pair.serverApp.flip();
            assertEquals("hello", StandardCharsets.US_ASCII.decode(pair.serverApp).toString());

            pair.toClient(ByteBuffer.wrap("world".getBytes(StandardCharsets.US_ASCII)));
            assertTrue(client.hasBuffered(), "records fed, not yet read");
            assertArrayEquals("world".getBytes(StandardCharsets.US_ASCII), pair.readAll(1024));
            assertFalse(client.hasBuffered());
        }
    }

    @Test
    void aHostNameIsVerified() {
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open("localhost")) {
            assertDoesNotThrow(new Pair(client, server)::handshake);
        }
    }

    /** More than fits a record or the buffer: the rest stays buffered in the session until it is read. */
    @Test
    void aLargeResponseIsReadInPieces() throws IOException {
        byte[] large = new byte[100_000];
        new Random(42).nextBytes(large);
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open("127.0.0.1")) {
            Pair pair = new Pair(client, server);
            pair.handshake();
            pair.toClient(ByteBuffer.wrap(large));
            assertArrayEquals(large, pair.readAll(1000));
        }
    }

    @Test
    void theServersCloseNotifyEndsTheStream() throws IOException {
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open("127.0.0.1")) {
            Pair pair = new Pair(client, server);
            pair.handshake();
            pair.engine.closeOutbound();
            pair.toClient(ByteBuffer.allocate(0));
            ByteBuffer out = ByteBuffer.allocateDirect(100);
            int n;
            do {
                n = client.read(out);
            } while (n == 0 && client.hasBuffered());
            assertEquals(-1, n);
        }
    }

    @Test
    void shutdownSendsCloseNotify() throws IOException {
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open("127.0.0.1")) {
            Pair pair = new Pair(client, server);
            pair.handshake();
            client.shutdown();
            assertTrue(client.hasOutput());
            pair.toServer();
            assertTrue(pair.engine.isInboundDone(), "the server saw close_notify");
        }
    }

    @Test
    void anotherNameIsRefused() {
        refused("elsewhere.example", server, "hostname mismatch");
    }

    @Test
    void anotherIpAddressIsRefused() {
        refused("127.0.0.2", server, "ip address mismatch");
    }

    @Test
    void anUntrustedCertificateIsRefused() {
        refused("127.0.0.1", untrusted, "self");
    }

    private static void refused(String host, SSLContext serverContext, String reason) {
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open(host)) {
            Pair pair = new Pair(client, serverContext);
            SSLHandshakeException e = assertThrows(SSLHandshakeException.class, pair::handshake);
            assertTrue(e.getMessage().toLowerCase(Locale.ROOT).contains(reason), e.getMessage());
        }
    }

    @Test
    void anInvalidIpAddressIsRefusedWhenTheSessionOpens() {
        try (TlsContext context = TlsContext.create(trusted)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> context.open("1.2.3.999"));
            assertTrue(e.getMessage().contains("1.2.3.999"), e.getMessage());
        }
    }

    @Test
    void anIpv6AddressIsVerifiedAsAnAddress() throws IOException {
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open("::1")) {
            Pair pair = new Pair(client, server);
            SSLHandshakeException e = assertThrows(SSLHandshakeException.class, pair::handshake);
            assertTrue(e.getMessage().toLowerCase(Locale.ROOT).contains("ip address mismatch"), e.getMessage());
        }
    }

    @Test
    void garbageInsteadOfAHandshakeIsRefused() throws IOException {
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open("127.0.0.1")) {
            assertEquals(TlsSession.Handshake.WANT_READ, client.handshake());
            client.feed(direct("HTTP/1.1 400 Bad Request\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));
            SSLHandshakeException e = assertThrows(SSLHandshakeException.class, client::handshake);
            assertTrue(e.getMessage().startsWith("The TLS handshake failed"), e.getMessage());
        }
    }

    @Test
    void garbageAfterTheHandshakeFailsTheRead() throws IOException {
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open("127.0.0.1")) {
            Pair pair = new Pair(client, server);
            pair.handshake();
            byte[] record = {23, 3, 3, 0, 32, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
            client.feed(direct(record));
            ByteBuffer out = ByteBuffer.allocateDirect(100);
            javax.net.ssl.SSLException e = assertThrows(javax.net.ssl.SSLException.class, () -> client.read(out));
            assertTrue(e.getMessage().startsWith("TLS read failed"), e.getMessage());
        }
    }

    @Test
    void emptyBuffersAndAnEarlyWrite() throws IOException {
        try (TlsContext context = TlsContext.create(trusted); TlsSession client = context.open("127.0.0.1")) {
            assertEquals(0, client.read(ByteBuffer.allocateDirect(0)), "no room, nothing read");
            client.handshake();
            assertTrue(client.hasOutput(), "the client hello");
            assertEquals(0, client.drain(ByteBuffer.allocateDirect(0)), "no room, nothing drained");
            ByteBuffer early = direct("too early".getBytes(StandardCharsets.US_ASCII));
            assertThrows(javax.net.ssl.SSLException.class, () -> client.write(early),
                    "no write before the handshake is done");
        }
    }

    @Test
    void theSystemsTrustedCertificatesLoad() {
        try (TlsContext context = TlsContext.create(null); TlsSession session = context.open("example.com")) {
            assertFalse(session.hasBuffered());
        }
    }

    @Test
    void misuseIsReported() {
        Path absent = keys.resolve("missing.pem");
        SecretManagerException missing = assertThrows(SecretManagerException.class, () -> TlsContext.create(absent));
        assertTrue(missing.getMessage().contains("missing.pem"), missing.getMessage());

        TlsContext context = TlsContext.create(trusted);
        TlsSession session = context.open("127.0.0.1");
        ByteBuffer heap = ByteBuffer.allocate(10);
        assertThrows(IllegalArgumentException.class, () -> session.read(heap));
        assertEquals(0, session.drain(ByteBuffer.allocateDirect(10)), "nothing to send before the handshake");
        session.close();
        session.close();
        assertThrows(IllegalStateException.class, session::handshake);
        context.close();
        context.close();
        assertThrows(IllegalStateException.class, () -> context.open("127.0.0.1"));
    }
}
