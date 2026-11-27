package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.provider.google.test.FakeGoogle.Response;
import io.descoped.secrets.test.support.HeapCanary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32C;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The canary gate for Google Secret Manager: the refresh token, the access token, a value read and a value written
 * stay off the Java heap. Each test runs {@link CanaryClient} in a child JVM against FakeGoogle and searches its heap
 * dump for the canary, which is all three at once. Over http on loopback, and over TLS: there the JDK's
 * {@code SSLEngine} encrypts the refresh token and the value written, and decrypts the access token and the value
 * read.
 */
class GoogleSecretManagerCanaryTest {

    private static final String SUBJECT = "io.descoped.secrets.provider.google.test/"
            + "io.descoped.secrets.provider.google.test.CanaryClient";
    private static final String BEFORE = "{\"type\":\"authorized_user\",\"client_id\":\"" + FakeGoogle.CLIENT_ID
            + "\",\"client_secret\":\"client secret&=\",\"refresh_token\":\"";
    private static final String SECRETS = "/v1/projects/test-project/secrets";

    @TempDir
    Path dir;
    @TempDir
    Path keys;

    private void run(String mode, SSLContext tls) throws Exception {
        HeapCanary canary = HeapCanary.create(dir, BEFORE, "\"}\n");
        String content = Files.readString(canary.file(), StandardCharsets.UTF_8);
        String value = content.substring(BEFORE.length(), BEFORE.length() + HeapCanary.LENGTH);
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        CRC32C crc = new CRC32C();
        crc.update(bytes);
        try (FakeGoogle google = tls == null ? new FakeGoogle() : new FakeGoogle(tls)) {
            google.refreshToken = value;
            google.accessToken = value;
            google.on("GET", SECRETS + "/canary/versions/latest:access",
                    new Response(200, FakeGoogle.accessResponse(bytes, crc.getValue())).asChunks());
            google.on("POST", SECRETS + "/copy:addVersion",
                    new Response(200, "{\"name\":\"projects/1/secrets/copy/versions/1\"}"));
            List<String> args = new ArrayList<>(List.of(mode, google.endpoint()));
            if (tls != null) {
                args.add(TestCertificates.trustStore(keys).toString());
            }
            canary.run(SUBJECT, args.toArray(String[]::new)).assertClean();
            assertEquals("Bearer " + value, google.requests.get(0).authorization(), "the canary was the token");
            assertTrue(google.requests("POST", SECRETS + "/copy:addVersion").getFirst().bodyText()
                    .contains("\"dataCrc32c\":\"" + crc.getValue() + "\""), "the canary was written back");
        }
    }

    @Test
    void aRefreshTokenFileLeavesTheHeapClean() throws Exception {
        run("user", null);
    }

    @Test
    void theMetadataServerLeavesTheHeapClean() throws Exception {
        run("metadata", null);
    }

    /** Every exchange over TLS: the token grant, the read and the write. */
    @Test
    void tlsLeavesTheHeapClean() throws Exception {
        run("user", TestCertificates.server(keys, "fake-google", "SAN=ip:127.0.0.1"));
    }
}
