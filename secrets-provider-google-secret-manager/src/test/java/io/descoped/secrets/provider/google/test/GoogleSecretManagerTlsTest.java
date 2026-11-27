package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.provider.google.test.FakeGoogle.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.zip.CRC32C;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The provider over TLS ({@code SSLEngine}), against FakeGoogle on https with certificates made by keytool and trusted
 * through {@code javax.net.ssl.trustStore}, as an application would add a private CA. The properties are read when a
 * client is created, so the order of test classes does not matter; they are cleared afterwards.
 */
class GoogleSecretManagerTlsTest {

    private static final String SECRETS = "/v1/projects/test-project/secrets";

    @TempDir
    static Path keys;
    @TempDir
    Path dir;

    /** A certificate for 127.0.0.1, which the fake listens on. */
    private static SSLContext matching;
    /** A trusted certificate for another name only. */
    private static SSLContext otherName;

    /** Back to the JDK's own trust store, for whatever runs after this class in the same JVM. */
    @AfterAll
    static void forgetTheTestTrustStore() {
        TestCertificates.forget();
    }

    @BeforeAll
    static void certificates() throws IOException, InterruptedException, GeneralSecurityException {
        matching = TestCertificates.server(keys, "matching", "SAN=ip:127.0.0.1");
        otherName = TestCertificates.server(keys, "other", "SAN=dns:elsewhere.example");
        // Read when a client is created: each has a TLS context of its own.
        TestCertificates.trust(TestCertificates.trustStore(keys));
    }

    private SecretManagerClient open(FakeGoogle google, String endpoint) throws IOException {
        return SecretManagerClient.create(Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", "test-project",
                "secrets.credentials-path", google.credentialsFile(dir).toString(),
                "secrets.token-endpoint", google.tokenEndpoint(),
                "secrets.endpoint", endpoint));
    }

    private static long crc(byte[] data) {
        CRC32C crc = new CRC32C();
        crc.update(data);
        return crc.getValue();
    }

    @Test
    void readsAndWritesOverTls() throws IOException {
        try (FakeGoogle google = new FakeGoogle(matching)) {
            byte[] value = "blåbær".getBytes(StandardCharsets.UTF_8);
            google.on("GET", SECRETS + "/a/versions/latest:access",
                    new Response(200, FakeGoogle.accessResponse(value, crc(value))).asChunks());
            google.on("POST", SECRETS + "/a:addVersion",
                    new Response(200, "{\"name\":\"projects/1/secrets/a/versions/2\"}"));
            try (SecretManagerClient client = open(google, google.endpoint())) {
                assertEquals("blåbær", Values.text(client, "a"));
                assertEquals("2", Values.add(client, "a", "v"));
            }
            assertEquals("Bearer token-1", google.requests.get(0).authorization());
        }
    }

    @Test
    void theHostNameIsVerified() throws IOException {
        try (FakeGoogle google = new FakeGoogle(matching); FakeGoogle impostor = new FakeGoogle(otherName)) {
            try (SecretManagerClient client = open(google, impostor.endpoint())) {
                SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.text(client, "a"));
                assertInstanceOf(SSLHandshakeException.class, e.getCause(), e.toString());
            }
            assertTrue(impostor.requests.isEmpty(), "nothing is sent to a server that is not who it claims to be");
        }
    }
}
