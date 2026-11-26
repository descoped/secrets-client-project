package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.provider.google.test.FakeGoogle.Response;
import io.descoped.secrets.test.support.HeapCanary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.CRC32C;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The canary gate for Google Secret Manager: the refresh token, the access token, a value read and a value written
 * stay off the Java heap. Each test runs {@link CanaryClient} in a child JVM against FakeGoogle over http on loopback
 * (TLS is phase 5's question) and searches its heap dump for the canary, which is all three at once.
 */
class GoogleSecretManagerCanaryTest {

    private static final String SUBJECT = "io.descoped.secrets.provider.google.test/"
            + "io.descoped.secrets.provider.google.test.CanaryClient";
    private static final String BEFORE = "{\"type\":\"authorized_user\",\"client_id\":\"" + FakeGoogle.CLIENT_ID
            + "\",\"client_secret\":\"client secret&=\",\"refresh_token\":\"";
    private static final String SECRETS = "/v1/projects/test-project/secrets";

    @TempDir
    Path dir;

    private void run(String mode) throws IOException, InterruptedException {
        HeapCanary canary = HeapCanary.create(dir, BEFORE, "\"}\n");
        String content = Files.readString(canary.file(), StandardCharsets.UTF_8);
        String value = content.substring(BEFORE.length(), BEFORE.length() + HeapCanary.LENGTH);
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        CRC32C crc = new CRC32C();
        crc.update(bytes);
        try (FakeGoogle google = new FakeGoogle()) {
            google.refreshToken = value;
            google.accessToken = value;
            google.on("GET", SECRETS + "/canary/versions/latest:access",
                    new Response(200, FakeGoogle.accessResponse(bytes, crc.getValue())).asChunks());
            google.on("POST", SECRETS + "/copy:addVersion",
                    new Response(200, "{\"name\":\"projects/1/secrets/copy/versions/1\"}"));
            canary.run(SUBJECT, mode, google.endpoint()).assertClean();
            assertEquals("Bearer " + value, google.requests.get(0).authorization(), "the canary was the token");
            assertTrue(google.requests("POST", SECRETS + "/copy:addVersion").getFirst().bodyText()
                    .contains("\"dataCrc32c\":\"" + crc.getValue() + "\""), "the canary was written back");
        }
    }

    @Test
    void aRefreshTokenFileLeavesTheHeapClean() throws Exception {
        run("user");
    }

    @Test
    void theMetadataServerLeavesTheHeapClean() throws Exception {
        run("metadata");
    }
}
