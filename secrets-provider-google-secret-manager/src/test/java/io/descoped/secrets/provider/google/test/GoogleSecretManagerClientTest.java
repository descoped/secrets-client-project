package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;
import io.descoped.secrets.provider.google.test.FakeGoogle.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32C;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GoogleSecretManagerClientTest {

    private static final String SECRETS = "/v1/projects/test-project/secrets";

    @TempDir
    Path dir;

    private FakeGoogle google;

    @BeforeEach
    void start() throws IOException {
        google = new FakeGoogle();
    }

    @AfterEach
    void stop() {
        google.close();
    }

    private SecretManagerClient open(Map<String, String> extra) throws IOException {
        Map<String, String> configuration = new HashMap<>(Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", "test-project",
                "secrets.service-account-key-path", google.serviceAccountKey(dir).toString(),
                "secrets.endpoint", google.endpoint()));
        configuration.putAll(extra);
        return SecretManagerClient.create(configuration);
    }

    private SecretManagerClient open() throws IOException {
        return open(Map.of());
    }

    private static long crc(byte[] data) {
        CRC32C crc = new CRC32C();
        crc.update(data);
        return crc.getValue();
    }

    private static Response access(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return new Response(200, FakeGoogle.accessResponse(bytes, crc(bytes)));
    }

    @Test
    void readsTheLatestVersionAndASpecificOne() throws IOException {
        google.on("GET", SECRETS + "/db-password/versions/latest:access", access("blåbær"));
        google.on("GET", SECRETS + "/db-password/versions/3:access", access("old"));
        try (SecretManagerClient client = open()) {
            assertEquals("blåbær", client.readString("db-password"));
            assertEquals("old", client.readString("db-password", "3"));
            assertEquals("blåbær", client.readString("db-password", "latest"));
        }
        assertTrue(google.requests.stream().allMatch(r -> "Bearer token-1".equals(r.authorization())),
                "every request carries the service account's token");
    }

    @Test
    void readsBinaryValues() throws IOException {
        byte[] binary = {0, (byte) 0xFF, 0x10, (byte) 0x80};
        google.on("GET", SECRETS + "/key/versions/latest:access",
                new Response(200, FakeGoogle.accessResponse(binary, crc(binary))));
        try (SecretManagerClient client = open()) {
            assertArrayEquals(binary, client.readBytes("key"));
        }
    }

    @Test
    void anExpiringTokenIsRefreshed() throws IOException {
        google.tokenLifetimeSeconds = 1;
        google.on("GET", SECRETS + "/a/versions/latest:access", access("1"));
        try (SecretManagerClient client = open()) {
            client.readString("a");
            client.readString("a");
        }
        assertTrue(google.tokens.get() >= 2, "a token about to expire is replaced: " + google.tokens.get());
        List<String> used = google.requests.stream().map(FakeGoogle.Request::authorization).toList();
        assertEquals(2, used.stream().distinct().count(), used.toString());
    }

    @Test
    void aMissingSecretOrVersionIsNotFound() throws IOException {
        google.on("GET", SECRETS + "/missing/versions/latest:access",
                FakeGoogle.error(404, "NOT_FOUND", "Secret [missing] not found or has no versions."));
        try (SecretManagerClient client = open()) {
            SecretNotFoundException e = assertThrows(SecretNotFoundException.class, () -> client.readString("missing"));
            assertEquals("missing", e.secretName());
            assertThrows(SecretNotFoundException.class, () -> client.readString("a", "0"));
            assertThrows(SecretNotFoundException.class, () -> client.readString("a", "../x"));
        }
        assertEquals(1, google.requests.size(), "invalid versions are not sent");
    }

    @Test
    void errorsNameStatusAndGoogleMessageButNeverTheBody() throws IOException {
        google.on("GET", SECRETS + "/a/versions/latest:access",
                FakeGoogle.error(403, "PERMISSION_DENIED", "Permission denied on secret"));
        google.on("GET", SECRETS + "/b/versions/latest:access", new Response(500, "hunter2 internal"));
        try (SecretManagerClient client = open()) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.readString("a"));
            assertEquals("Google Secret Manager returned HTTP 403 PERMISSION_DENIED when reading secret 'a':"
                    + " Permission denied on secret", e.getMessage());
            e = assertThrows(SecretManagerException.class, () -> client.readString("b"));
            assertEquals("Google Secret Manager returned HTTP 500 when reading secret 'b'", e.getMessage());
        }
    }

    @Test
    void aResponseWithoutDataOrWithTheWrongChecksumFailsWithoutTheValue() throws IOException {
        google.on("GET", SECRETS + "/a/versions/latest:access",
                new Response(200, "{\"payload\":{\"hint\":\"hunter2\"}}"));
        byte[] value = "hunter2".getBytes(StandardCharsets.UTF_8);
        google.on("GET", SECRETS + "/b/versions/latest:access",
                new Response(200, FakeGoogle.accessResponse(value, crc(value) + 1)));
        try (SecretManagerClient client = open()) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.readString("a"));
            assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
            e = assertThrows(SecretManagerException.class, () -> client.readString("b"));
            assertTrue(e.getMessage().startsWith("Checksum mismatch"), e.getMessage());
            assertFalse(e.getMessage().contains("hunter2"));
        }
    }

    @Test
    void invalidNamesAreRejectedBeforeAnyRequest() throws IOException {
        try (SecretManagerClient client = open()) {
            for (String name : List.of("", "a/b", "../a", "a b", "a%2Fb", "x".repeat(256))) {
                assertThrows(SecretManagerException.class, () -> client.readString(name), name);
                assertThrows(SecretManagerException.class, () -> client.addVersion(name, "1"), name);
            }
        }
        assertTrue(google.requests.isEmpty());
    }

    @Test
    void addVersionToAnExistingSecret() throws IOException {
        google.on("POST", SECRETS + "/api-key:addVersion",
                new Response(200, "{\"name\":\"projects/123/secrets/api-key/versions/7\",\"state\":\"ENABLED\"}"));
        byte[] value = "s3cret".getBytes(StandardCharsets.UTF_8);
        try (SecretManagerClient client = open()) {
            assertEquals("7", client.addVersion("api-key", value));
        }
        assertEquals(1, google.requests.size());
        String body = google.requests.get(0).bodyText();
        assertEquals("{\"payload\":{\"data\":\"" + Base64.getEncoder().encodeToString(value)
                + "\",\"dataCrc32c\":\"" + crc(value) + "\"}}", body);
    }

    @Test
    void addVersionCreatesAMissingSecretWithAutomaticReplication() throws IOException {
        google.on("POST", SECRETS + "/new:addVersion",
                FakeGoogle.error(404, "NOT_FOUND", "Secret [new] not found."),
                new Response(200, "{\"name\":\"projects/123/secrets/new/versions/1\"}"));
        google.on("POST", SECRETS + "?secretId=new", new Response(200, "{\"name\":\"projects/123/secrets/new\"}"));
        try (SecretManagerClient client = open()) {
            assertEquals("1", client.addVersion("new", "v"));
        }
        assertEquals("{\"replication\":{\"automatic\":{}}}",
                google.requests("POST", SECRETS + "?secretId=new").get(0).bodyText());
        assertEquals(2, google.requests("POST", SECRETS + "/new:addVersion").size());
    }

    @Test
    void addVersionCreatesWithTheConfiguredLocationsAndToleratesARace() throws IOException {
        google.on("POST", SECRETS + "/new:addVersion",
                FakeGoogle.error(404, "NOT_FOUND", "Secret [new] not found."),
                new Response(200, "{\"name\":\"projects/123/secrets/new/versions/1\"}"));
        google.on("POST", SECRETS + "?secretId=new", FakeGoogle.error(409, "ALREADY_EXISTS", "exists"));
        try (SecretManagerClient client = open(Map.of("secrets.replication-locations", "europe-north1, europe-west1"))) {
            assertEquals("1", client.addVersion("new", "v"));
        }
        assertEquals("{\"replication\":{\"userManaged\":{\"replicas\":[{\"location\":\"europe-north1\"},"
                        + "{\"location\":\"europe-west1\"}]}}}",
                google.requests("POST", SECRETS + "?secretId=new").get(0).bodyText());
    }

    @Test
    void addVersionFailuresAreSecretManagerExceptions() throws IOException {
        google.on("POST", SECRETS + "/a:addVersion",
                FakeGoogle.error(400, "FAILED_PRECONDITION", "Secret is disabled"));
        try (SecretManagerClient client = open()) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.addVersion("a", "v"));
            assertTrue(e.getMessage().contains("400 FAILED_PRECONDITION when adding a version to secret 'a'"),
                    e.getMessage());
        }
    }

    @Test
    void aClosedClientRefusesEverythingAndCloseIsIdempotent() throws IOException {
        SecretManagerClient client = open();
        client.close();
        client.close();
        assertThrows(IllegalStateException.class, () -> client.readBytes("a"));
        assertThrows(IllegalStateException.class, () -> client.addVersion("a", "v"));
        assertTrue(google.requests.isEmpty());
    }

    @Test
    void configurationIsChecked() throws IOException {
        Path key = google.serviceAccountKey(dir);
        Map<String, String> base = Map.of("secrets.provider", "google-secret-manager",
                "secrets.service-account-key-path", key.toString());
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(base), "project id is required");
        Map<String, String> badProject = new HashMap<>(base);
        badProject.put("secrets.project-id", "../other");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(badProject));
        Map<String, String> badTimeout = new HashMap<>(base);
        badTimeout.put("secrets.project-id", "p");
        badTimeout.put("secrets.request-timeout", "30");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(badTimeout));
        Map<String, String> missingKey = new HashMap<>(base);
        missingKey.put("secrets.project-id", "p");
        missingKey.put("secrets.service-account-key-path", dir.resolve("missing.json").toString());
        assertThrows(SecretManagerException.class, () -> SecretManagerClient.create(missingKey));
    }
}
