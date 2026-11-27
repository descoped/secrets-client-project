package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.provider.google.test.FakeGoogle.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Locale;
import java.util.Map;
import java.util.zip.CRC32C;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The provider over TLS (OpenSSL), against FakeGoogle on https with certificates made by keytool and trusted through
 * {@code secrets.tls.ca-file}, as an application would trust a private CA. Every refusal happens before a request
 * reaches the server.
 */
class GoogleSecretManagerTlsTest {

    private static final String SECRETS = "/v1/projects/test-project/secrets";

    @TempDir
    static Path keys;
    @TempDir
    Path dir;

    /** A certificate for 127.0.0.1, which the fake listens on. */
    private static SSLContext matching;
    /** A certificate for the name localhost. */
    private static SSLContext named;
    /** A trusted certificate for another name only. */
    private static SSLContext otherName;
    /** A trusted certificate for another IP address only. */
    private static SSLContext otherAddress;
    /** A certificate for 127.0.0.1 that is not in the trusted file. */
    private static SSLContext untrusted;
    /** A trusted certificate for 127.0.0.1 that expired yesterday. */
    private static SSLContext expired;

    @BeforeAll
    static void certificates() throws IOException, InterruptedException, GeneralSecurityException {
        matching = TestCertificates.server(keys, "matching", "SAN=ip:127.0.0.1");
        named = TestCertificates.server(keys, "named", "SAN=dns:localhost");
        otherName = TestCertificates.server(keys, "other", "SAN=dns:elsewhere.example");
        otherAddress = TestCertificates.server(keys, "other-address", "SAN=ip:127.0.0.2");
        untrusted = TestCertificates.server(keys, "untrusted", "SAN=ip:127.0.0.1", false);
        expired = TestCertificates.server(keys, "expired", "SAN=ip:127.0.0.1", true,
                "-startdate", "-3d", "-validity", "2");
    }

    private SecretManagerClient open(FakeGoogle google, String endpoint) throws IOException {
        return SecretManagerClient.create(Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", "test-project",
                "secrets.credentials-path", google.credentialsFile(dir).toString(),
                "secrets.token-endpoint", google.tokenEndpoint(),
                "secrets.endpoint", endpoint,
                "secrets.tls.ca-file", TestCertificates.trusted(keys).toString()));
    }

    private static long crc(byte[] data) {
        CRC32C crc = new CRC32C();
        crc.update(data);
        return crc.getValue();
    }

    private static void serveValue(FakeGoogle google) {
        byte[] value = "blåbær".getBytes(StandardCharsets.UTF_8);
        google.on("GET", SECRETS + "/a/versions/latest:access",
                new Response(200, FakeGoogle.accessResponse(value, crc(value))).asChunks());
        google.on("POST", SECRETS + "/a:addVersion",
                new Response(200, "{\"name\":\"projects/1/secrets/a/versions/2\"}"));
    }

    @Test
    void readsAndWritesOverTls() throws IOException {
        try (FakeGoogle google = new FakeGoogle(matching)) {
            serveValue(google);
            try (SecretManagerClient client = open(google, google.endpoint())) {
                assertEquals("blåbær", Values.text(client, "a"));
                assertEquals("2", Values.add(client, "a", "v"));
            }
            assertEquals("Bearer token-1", google.requests.get(0).authorization());
        }
    }

    /** A host name, not an IP address: the certificate's name is checked, and SNI is sent. */
    @Test
    void aHostNameIsVerifiedAgainstTheCertificatesName() throws IOException {
        try (FakeGoogle google = new FakeGoogle(named)) {
            serveValue(google);
            String byName = google.endpoint().replace("127.0.0.1", "localhost");
            try (SecretManagerClient client = SecretManagerClient.create(Map.of(
                    "secrets.provider", "google-secret-manager",
                    "secrets.project-id", "test-project",
                    "secrets.credentials-path", google.credentialsFile(dir).toString(),
                    "secrets.token-endpoint", byName + "/token",
                    "secrets.endpoint", byName,
                    "secrets.tls.ca-file", TestCertificates.trusted(keys).toString()))) {
                assertEquals("blåbær", Values.text(client, "a"));
            }
        }
    }

    @Test
    void theHostNameIsVerified() throws IOException {
        refused(otherName, "a certificate for another name", "hostname mismatch", true);
    }

    @Test
    void theIpAddressIsVerified() throws IOException {
        refused(otherAddress, "a certificate for another IP address", "ip address mismatch", false);
    }

    @Test
    void anUntrustedCertificateIsRefused() throws IOException {
        refused(untrusted, "a certificate no trusted root signed", "self", false);
    }

    @Test
    void anExpiredCertificateIsRefused() throws IOException {
        refused(expired, "an expired certificate", "expired", false);
    }

    /**
     * {@code impostor} must be refused during the handshake, before it receives anything, for the reason OpenSSL
     * names ({@code reason}, in lower case). Reached as {@code localhost} if {@code byName}, else as 127.0.0.1.
     */
    private void refused(SSLContext impostor, String what, String reason, boolean byName) throws IOException {
        try (FakeGoogle google = new FakeGoogle(matching); FakeGoogle server = new FakeGoogle(impostor)) {
            String endpoint = byName ? server.endpoint().replace("127.0.0.1", "localhost") : server.endpoint();
            try (SecretManagerClient client = open(google, endpoint)) {
                SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.text(client, "a"),
                        what);
                assertInstanceOf(SSLHandshakeException.class, e.getCause(), e.toString());
                String message = e.getCause().getMessage().toLowerCase(Locale.ROOT);
                assertTrue(message.contains(reason), what + ": " + message);
            }
            assertTrue(server.requests.isEmpty(), "nothing is sent to a server with " + what);
        }
    }

    @Test
    void aMissingCaFileIsReportedWhenTheClientIsCreated() {
        Map<String, String> configuration = Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", "test-project",
                "secrets.credentials", "metadata",
                "secrets.metadata-endpoint", "http://127.0.0.1:1",
                "secrets.tls.ca-file", dir.resolve("missing.pem").toString());
        SecretManagerException e = assertThrows(SecretManagerException.class,
                () -> SecretManagerClient.create(configuration));
        assertTrue(e.getMessage().contains("missing.pem"), e.getMessage());
    }
}
