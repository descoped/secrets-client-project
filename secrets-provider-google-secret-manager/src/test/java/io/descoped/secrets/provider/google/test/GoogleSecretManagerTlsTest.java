package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.provider.google.test.FakeGoogle.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.zip.CRC32C;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The provider over TLS ({@code SSLEngine}), against FakeGoogle on https with certificates made by keytool and trusted
 * through {@code javax.net.ssl.trustStore}, as an application would add a private CA.
 */
class GoogleSecretManagerTlsTest {

    private static final String PASSWORD = "changeit";
    private static final String SECRETS = "/v1/projects/test-project/secrets";

    @TempDir
    static Path keys;
    @TempDir
    Path dir;

    /** A certificate for 127.0.0.1, which the fake listens on. */
    private static SSLContext matching;
    /** A trusted certificate for another name only. */
    private static SSLContext otherName;

    @BeforeAll
    static void certificates() throws IOException, InterruptedException, GeneralSecurityException {
        Path trust = keys.resolve("trust.p12");
        matching = server("matching", "SAN=ip:127.0.0.1", trust);
        otherName = server("other", "SAN=dns:elsewhere.example", trust);
        // Read once, when the JDK's default SSLContext is first made; nothing in this JVM uses TLS before.
        System.setProperty("javax.net.ssl.trustStore", trust.toString());
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);
        System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
    }

    private static SSLContext server(String alias, String san, Path trust)
            throws IOException, InterruptedException, GeneralSecurityException {
        Path store = keys.resolve(alias + ".p12");
        Path certificate = keys.resolve(alias + ".pem");
        keytool("-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=" + alias,
                "-ext", san, "-validity", "2", "-keystore", store.toString(), "-storetype", "PKCS12",
                "-storepass", PASSWORD);
        keytool("-exportcert", "-rfc", "-alias", alias, "-keystore", store.toString(), "-storepass", PASSWORD,
                "-file", certificate.toString());
        keytool("-importcert", "-noprompt", "-alias", alias, "-file", certificate.toString(),
                "-keystore", trust.toString(), "-storetype", "PKCS12", "-storepass", PASSWORD);
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
                assertEquals("blåbær", client.readString("a"));
                assertEquals("2", client.addVersion("a", "v"));
            }
            assertEquals("Bearer token-1", google.requests.get(0).authorization());
        }
    }

    @Test
    void theHostNameIsVerified() throws IOException {
        try (FakeGoogle google = new FakeGoogle(matching); FakeGoogle impostor = new FakeGoogle(otherName)) {
            try (SecretManagerClient client = open(google, impostor.endpoint())) {
                SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.readString("a"));
                assertInstanceOf(SSLHandshakeException.class, e.getCause(), e.toString());
            }
            assertTrue(impostor.requests.isEmpty(), "nothing is sent to a server that is not who it claims to be");
        }
    }
}
