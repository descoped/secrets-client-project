package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.Secret;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
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
        return SecretManagerClient.create(configuration(extra));
    }

    /** The configuration of a client of the fake, with {@code extra} on top. */
    private Map<String, String> configuration(Map<String, String> extra) throws IOException {
        Map<String, String> configuration = new HashMap<>(Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", "test-project",
                "secrets.credentials-path", google.credentialsFile(dir).toString(),
                "secrets.token-endpoint", google.tokenEndpoint(),
                "secrets.endpoint", google.endpoint()));
        configuration.putAll(extra);
        return configuration;
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
            assertEquals("blåbær", Values.text(client, "db-password"));
            assertEquals("old", Values.text(client, "db-password", "3"));
            assertEquals("blåbær", Values.text(client, "db-password", "latest"));
        }
        assertTrue(google.requests.stream().allMatch(r -> "Bearer token-1".equals(r.authorization())),
                "every request carries the service account's token");
    }

    @Test
    void readCopiesTheValueIntoGuardedMemoryAndCloseClosesIt() throws IOException {
        google.on("GET", SECRETS + "/db-password/versions/latest:access", access("blåbær"));
        Secret secret;
        try (SecretManagerClient client = open()) {
            secret = client.read("db-password");
            assertEquals("blåbær", secret.withChars(String::new));
        }
        assertEquals("Secret (closed)", secret.toString());
    }

    @Test
    void readsBinaryValues() throws IOException {
        byte[] binary = {0, (byte) 0xFF, 0x10, (byte) 0x80};
        google.on("GET", SECRETS + "/key/versions/latest:access",
                new Response(200, FakeGoogle.accessResponse(binary, crc(binary))));
        try (SecretManagerClient client = open()) {
            assertArrayEquals(binary, Values.bytes(client, "key"));
        }
    }

    @Test
    void anExpiringTokenIsRefreshed() throws IOException {
        google.tokenLifetimeSeconds = 1;
        google.on("GET", SECRETS + "/a/versions/latest:access", access("1"));
        try (SecretManagerClient client = open()) {
            Values.text(client, "a");
            Values.text(client, "a");
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
            SecretNotFoundException e = assertThrows(SecretNotFoundException.class, () -> Values.text(client, "missing"));
            assertEquals("missing", e.secretName());
            assertThrows(SecretNotFoundException.class, () -> Values.text(client, "a", "0"));
            assertThrows(SecretNotFoundException.class, () -> Values.text(client, "a", "../x"));
        }
        assertEquals(1, google.requests.size(), "invalid versions are not sent");
    }

    @Test
    void errorsNameStatusAndGoogleMessageButNeverTheBody() throws IOException {
        google.on("GET", SECRETS + "/a/versions/latest:access",
                FakeGoogle.error(403, "PERMISSION_DENIED", "Permission denied on secret"));
        google.on("GET", SECRETS + "/b/versions/latest:access", new Response(500, "hunter2 internal"));
        google.on("GET", SECRETS + "/c/versions/latest:access", new Response(503,
                "{\"error\":{\"status\":{\"code\":[1]},\"details\":[{}],\"message\":\"Try again\"}}"));
        try (SecretManagerClient client = open()) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.text(client, "a"));
            assertEquals("Google Secret Manager returned HTTP 403 PERMISSION_DENIED when reading secret 'a':"
                    + " Permission denied on secret", e.getMessage());
            e = assertThrows(SecretManagerException.class, () -> Values.text(client, "b"));
            assertEquals("Google Secret Manager returned HTTP 500 when reading secret 'b'", e.getMessage());
            // A malformed error object: the unexpected structures are skipped and the message is still found.
            e = assertThrows(SecretManagerException.class, () -> Values.text(client, "c"));
            assertEquals("Google Secret Manager returned HTTP 503 when reading secret 'c': Try again", e.getMessage());
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
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.text(client, "a"));
            assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
            e = assertThrows(SecretManagerException.class, () -> Values.text(client, "b"));
            assertTrue(e.getMessage().startsWith("Checksum mismatch"), e.getMessage());
            assertFalse(e.getMessage().contains("hunter2"));
        }
    }

    @Test
    void malformedJsonFailsWithoutTheBody() throws IOException {
        google.on("GET", SECRETS + "/a/versions/latest:access", new Response(200, "{\"payload\":{\"data\":hunter2}}"));
        google.on("GET", SECRETS + "/b/versions/latest:access", new Response(200, "{\"payload\":{\"data\":"));
        google.on("POST", SECRETS + "/c:addVersion", new Response(200, "{\"name\":\"projects/1/secrets/c/versions/"));
        try (SecretManagerClient client = open()) {
            for (String name : List.of("a", "b")) {
                SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.text(client, name));
                assertTrue(e.getMessage().startsWith("Cannot parse the response for secret '" + name + "'"),
                        e.getMessage());
                for (Throwable t = e; t != null; t = t.getCause()) {
                    assertFalse(String.valueOf(t.getMessage()).contains("hunter2"), t.toString());
                }
            }
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.add(client, "c", "v"));
            assertTrue(e.getMessage().startsWith("Cannot parse the response for secret 'c'"), e.getMessage());
        }
    }

    @Test
    void invalidNamesAreRejectedBeforeAnyRequest() throws IOException {
        try (SecretManagerClient client = open()) {
            for (String name : List.of("", "a/b", "../a", "a b", "a%2Fb", "db.password", "x".repeat(256))) {
                assertThrows(SecretNotFoundException.class, () -> Values.text(client, name), name);
                SecretManagerException e = assertThrows(SecretManagerException.class,
                        () -> Values.add(client, name, "1"), name);
                assertFalse(e instanceof SecretNotFoundException, name);
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
            assertEquals("7", Values.add(client, "api-key", value));
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
            assertEquals("1", Values.add(client, "new", "v"));
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
            assertEquals("1", Values.add(client, "new", "v"));
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
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.add(client, "a", "v"));
            assertTrue(e.getMessage().contains("400 FAILED_PRECONDITION when adding a version to secret 'a'"),
                    e.getMessage());
        }
    }

    @Test
    void aClosedClientRefusesEverythingAndCloseIsIdempotent() throws IOException {
        SecretManagerClient client = open();
        client.close();
        client.close();
        assertThrows(IllegalStateException.class, () -> Values.bytes(client, "a"));
        assertThrows(IllegalStateException.class, () -> client.read("a"));
        assertThrows(IllegalStateException.class, () -> Values.add(client, "a", "v"));
        assertTrue(google.requests.isEmpty());
    }

    @Test
    void theEndpointMustUseHttpsExceptOnLoopback() throws IOException {
        for (String endpoint : List.of("http://secretmanager.googleapis.com", "http://10.0.0.1:8080", "ftp://host",
                "http://localhost.evil.example", "https://")) {
            Map<String, String> configuration = configuration(Map.of("secrets.endpoint", endpoint));
            assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(configuration), endpoint);
        }
        for (String endpoint : List.of("https://europe-north1-secretmanager.googleapis.com", "http://localhost:1",
                "http://127.0.0.1:1", "http://[::1]:1")) {
            open(Map.of("secrets.endpoint", endpoint)).close();
        }
    }

    @Test
    void onlyAuthorizedUserCredentialsAreAccepted() throws IOException {
        Map<String, String> types = Map.of(
                "service_account", "{\"type\":\"service_account\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\"}",
                "external_account", "{\"type\":\"external_account\",\"credential_source\":{\"executable\":"
                        + "{\"command\":\"/bin/echo\"}}}",
                "no known type", "{\"type\":\"hunter2 hunter2\"}");
        for (Map.Entry<String, String> type : types.entrySet()) {
            Path file = dir.resolve(type.getKey().replace(' ', '-') + ".json");
            Files.writeString(file, type.getValue());
            Map<String, String> configuration = configuration(Map.of("secrets.credentials-path", file.toString()));
            SecretManagerException e = assertThrows(SecretManagerException.class,
                    () -> SecretManagerClient.create(configuration), type.getKey());
            assertTrue(e.getMessage().contains(type.getKey()), e.getMessage());
            assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
        }
        Path incomplete = dir.resolve("incomplete.json");
        Files.writeString(incomplete, "{\"type\":\"authorized_user\",\"client_id\":\"c\",\"client_secret\":\"s\"}");
        Map<String, String> withIncomplete = configuration(Map.of("secrets.credentials-path", incomplete.toString()));
        SecretManagerException e = assertThrows(SecretManagerException.class,
                () -> SecretManagerClient.create(withIncomplete));
        assertTrue(e.getMessage().endsWith("has no refresh_token"), e.getMessage());
        Path broken = dir.resolve("broken.json");
        Files.writeString(broken, "{\"type\":\"authorized_user\",\"refresh_token\":\"hunter2");
        Map<String, String> withBroken = configuration(Map.of("secrets.credentials-path", broken.toString()));
        e = assertThrows(SecretManagerException.class, () -> SecretManagerClient.create(withBroken));
        assertTrue(e.getMessage().endsWith("is not valid JSON"), e.getMessage());
        assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
        Path missing = dir.resolve("missing.json");
        Map<String, String> withMissing = configuration(Map.of("secrets.credentials-path", missing.toString()));
        assertThrows(SecretManagerException.class, () -> SecretManagerClient.create(withMissing));
        Map<String, String> withRemovedKey = configuration(Map.of("secrets.service-account-key-path",
                missing.toString()));
        IllegalArgumentException removed = assertThrows(IllegalArgumentException.class,
                () -> SecretManagerClient.create(withRemovedKey));
        assertTrue(removed.getMessage().contains("no longer supported"), removed.getMessage());
    }

    @Test
    void theRefreshTokenIsExchangedForAnAccessToken() throws IOException {
        google.on("GET", SECRETS + "/a/versions/latest:access", access("1"));
        try (SecretManagerClient client = open()) {
            assertEquals("1", Values.text(client, "a"));
        }
        assertEquals(Map.of("grant_type", "refresh_token", "client_id", FakeGoogle.CLIENT_ID,
                "client_secret", FakeGoogle.CLIENT_SECRET, "refresh_token", FakeGoogle.REFRESH_TOKEN),
                google.tokenRequests.get(0));
        assertEquals("Bearer token-1", google.requests.get(0).authorization());
    }

    @Test
    void aRefusedRefreshTokenIsReportedWithTheOAuthError() throws IOException {
        try (SecretManagerClient client = open()) {
            // The file was read with the old token; the token is first exchanged on the first request.
            google.refreshToken = "another";
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.text(client, "a"));
            assertTrue(e.getMessage().startsWith("Cannot get an access token from the OAuth endpoint 127.0.0.1:"),
                    e.getMessage());
            assertTrue(e.getMessage().endsWith(": HTTP 400 invalid_grant"), e.getMessage());
        }
        assertTrue(google.requests.isEmpty());
    }

    @Test
    void theMetadataServerGivesTheTokenOnGoogleCloud() {
        google.on("GET", SECRETS + "/a/versions/latest:access", access("1"));
        Map<String, String> metadata = Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", "test-project",
                "secrets.credentials", "metadata",
                "secrets.metadata-endpoint", google.endpoint(),
                "secrets.endpoint", google.endpoint());
        try (SecretManagerClient client = SecretManagerClient.create(metadata)) {
            assertEquals("1", Values.text(client, "a"));
            assertEquals("1", Values.text(client, "a"));
        }
        assertEquals(List.of("Google"), google.metadataFlavors, "one token, asked for with the header");
        assertEquals("Bearer token-1", google.requests.get(1).authorization());
        assertTrue(google.tokenRequests.isEmpty());
    }

    @Test
    void largeValuesChunkedResponsesAndEscapesAreRead() throws IOException {
        byte[] large = new byte[64 * 1024];
        new java.util.Random(7).nextBytes(large);
        google.on("GET", SECRETS + "/large/versions/latest:access",
                new Response(200, FakeGoogle.accessResponse(large, crc(large))));
        google.on("GET", SECRETS + "/chunked/versions/latest:access",
                new Response(200, FakeGoogle.accessResponse(large, crc(large))).asChunks());
        byte[] slashes = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        String escaped = FakeGoogle.accessResponse(slashes, crc(slashes)).replace("/", "\\/")
                .replace("\"name\"", "\"n\\u0061me\"");
        google.on("GET", SECRETS + "/escaped/versions/latest:access", new Response(200, escaped));
        byte[] empty = new byte[0];
        google.on("GET", SECRETS + "/empty/versions/latest:access",
                new Response(200, "{\"payload\":{\"data\":\"\"}}").asChunks());
        try (SecretManagerClient client = open()) {
            assertArrayEquals(large, Values.bytes(client, "large"));
            assertArrayEquals(large, Values.bytes(client, "chunked"));
            assertArrayEquals(slashes, Values.bytes(client, "escaped"));
            assertArrayEquals(empty, Values.bytes(client, "empty"));
        }
    }

    @Test
    void anyValidJsonAroundThePayloadAndUnpaddedBase64AreRead() throws IOException {
        byte[] hi = "hi".getBytes(StandardCharsets.UTF_8);
        String valid = """
                 { "name" : "projects/1/secrets/a/versions/1",
                   "k": 0, "extra": [1, -2.5e+3, 0.5E-1, true, false, null, {"a": []}, [], {}],
                   "u": "\\u00e5\\ud83d\\ude00\\"\\\\\\b\\f\\n\\r\\t",
                   "payload": {"data": "aGk", "dataCrc32c": "%d"} }
                """.formatted(crc(hi));
        google.on("GET", SECRETS + "/a/versions/latest:access", new Response(200, valid));
        byte[] hello = "hello".getBytes(StandardCharsets.UTF_8);
        google.on("GET", SECRETS + "/b/versions/latest:access",
                new Response(200, "{\"payload\":{\"data\":\"aGVsbG8\"}}"));
        try (SecretManagerClient client = open()) {
            assertArrayEquals(hi, Values.bytes(client, "a"));
            assertArrayEquals(hello, Values.bytes(client, "b"));
        }
    }

    @Test
    void malformedJsonAndBase64FailWithoutTheValue() throws IOException {
        List<String> bodies = List.of(
                "{\"payload\":{\"data\":\"a$==\"}}",
                "{\"payload\":{\"data\":\"aGk=x\"}}",
                "{\"payload\":{\"data\":\"aGVsb\"}}",
                "{\"payload\":{\"data\":\"\\x41\"}}",
                "{\"payload\":{\"data\":\"\\ud800\"}}",
                "{\"payload\":{\"data\":\"\\udc00\"}}",
                "{\"payload\":{\"data\":\"\\ud800\\u0041\"}}",
                "{\"payload\":{\"data\":\"\\u12\"}}",
                "{\"payload\":{\"data\":\"\\uzzzz\"}}",
                "{\"payload\":{\"data\":\"a\tb\"}}",
                "{\"payload\":{\"data\":\"aGk=\",\"data\":\"aGk=\"}}",
                "{\"payload\":{\"data\":\"aGk=\"}} x",
                "[".repeat(40) + "]".repeat(40),
                "{\"payload\":{\"data\":\"aGk=\",\"dataCrc32c\":\"x\"}}",
                "{\"payload\":{\"data\":\"aGk=\"},\"n\":-}",
                "{\"payload\":{\"data\":\"aGk=\"},\"n\":1.}",
                "{\"payload\":{\"data\":\"aGk=\"},\"n\":tru}",
                "{\"payload\" {}}",
                "{\"payload\":{\"data\":\"aGk=\"},}");
        for (int i = 0; i < bodies.size(); i++) {
            google.on("GET", SECRETS + "/m" + i + "/versions/latest:access", new Response(200, bodies.get(i)));
        }
        try (SecretManagerClient client = open()) {
            for (int i = 0; i < bodies.size(); i++) {
                String name = "m" + i;
                SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.bytes(client, name),
                        bodies.get(i));
                assertTrue(e.getMessage().startsWith("Cannot parse the response for secret '" + name + "'")
                        || e.getMessage().startsWith("No payload.data"), bodies.get(i) + ": " + e.getMessage());
            }
        }
    }

    @Test
    void aSlowServerTimesOutAndAnAbsentOneFails() throws IOException {
        google.on("GET", SECRETS + "/slow/versions/latest:access", access("1").delayed(3000));
        try (SecretManagerClient client = open(Map.of("secrets.request-timeout", "PT0.5S"))) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.text(client, "slow"));
            assertEquals("Timed out reading secret 'slow'", e.getMessage());
        }
        try (SecretManagerClient client = open(Map.of("secrets.endpoint", "http://127.0.0.1:1"))) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.text(client, "a"));
            assertTrue(e.getMessage().startsWith("Failed reading secret 'a': "), e.getMessage());
        }
    }

    @Test
    void configurationIsChecked() throws IOException {
        Path key = google.credentialsFile(dir);
        Map<String, String> base = Map.of("secrets.provider", "google-secret-manager",
                "secrets.credentials-path", key.toString());
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(base), "project id is required");
        Map<String, String> badProject = new HashMap<>(base);
        badProject.put("secrets.project-id", "../other");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(badProject));
        Map<String, String> badTimeout = new HashMap<>(base);
        badTimeout.put("secrets.project-id", "p");
        badTimeout.put("secrets.request-timeout", "30");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(badTimeout));
        badTimeout.put("secrets.request-timeout", "PT0S");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(badTimeout));
        badTimeout.put("secrets.request-timeout", "-PT1S");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(badTimeout));
        Map<String, String> valid = new HashMap<>(base);
        valid.put("secrets.project-id", "p");
        for (Map.Entry<String, String> invalid : Map.of(
                "secrets.credentials", "service-account",
                "secrets.token-endpoint", "http://oauth2.googleapis.com/token",
                "secrets.metadata-endpoint", "http://10.0.0.1",
                "secrets.replication-locations", "europe-north1,\"x\"").entrySet()) {
            Map<String, String> configuration = new HashMap<>(valid);
            configuration.put(invalid.getKey(), invalid.getValue());
            assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(configuration),
                    invalid.toString());
        }
        Map<String, String> both = new HashMap<>(valid);
        both.put("secrets.credentials", "metadata");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(both),
                "a credentials file and the metadata server exclude each other");
        for (String metadata : List.of("http://metadata.google.internal", "http://169.254.169.254",
                "http://[::1]:8080")) {
            SecretManagerClient.create(Map.of("secrets.provider", "google-secret-manager", "secrets.project-id", "p",
                    "secrets.credentials", "metadata", "secrets.metadata-endpoint", metadata)).close();
        }
    }

    @Test
    void concurrentReadsAndWritesShareOneClient() throws Exception {
        google.on("GET", SECRETS + "/a/versions/latest:access", access("value-a"));
        google.on("GET", SECRETS + "/b/versions/latest:access", access("value-b"));
        google.on("POST", SECRETS + "/c:addVersion",
                new Response(200, "{\"name\":\"projects/1/secrets/c/versions/7\"}"));
        try (SecretManagerClient client = open()) {
            ExecutorService executor = Executors.newFixedThreadPool(8);
            try {
                List<Future<?>> futures = new ArrayList<>();
                for (int i = 0; i < 100; i++) {
                    futures.add(executor.submit(() -> assertEquals("value-a", Values.text(client, "a"))));
                    futures.add(executor.submit(() -> assertEquals("value-b", Values.text(client, "b"))));
                    futures.add(executor.submit(() -> assertEquals("7", Values.add(client, "c", "v"))));
                }
                for (Future<?> future : futures) {
                    future.get(30, TimeUnit.SECONDS);
                }
            } finally {
                executor.shutdownNow();
            }
        }
        assertEquals(300, google.requests.size());
        assertTrue(google.requests.stream().allMatch(r -> r.authorization() != null), "every request is signed");
    }

    @Test
    void callsInFlightWhenTheClientIsClosedFinishOrSeeAClosedClient() throws Exception {
        google.on("GET", SECRETS + "/a/versions/latest:access", access("value-a"));
        SecretManagerClient client = open();
        callsRaceWithClose(client, () -> assertEquals("value-a", Values.text(client, "a")));
    }

    /**
     * Runs {@code call} on 8 threads until the client is closed under them. Every call must either succeed or, once
     * the close has begun, throw {@link IllegalStateException}; anything else, an {@code IllegalStateException}
     * before the close included, fails the test.
     */
    private static void callsRaceWithClose(SecretManagerClient client, Runnable call) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(8);
        CountDownLatch running = new CountDownLatch(8);
        AtomicBoolean closing = new AtomicBoolean();
        try {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                futures.add(executor.submit(() -> {
                    int calls = 0;
                    while (true) {
                        try {
                            call.run();
                        } catch (IllegalStateException e) {
                            if (!closing.get()) {
                                throw e;
                            }
                            return calls;
                        }
                        if (++calls == 20) {
                            running.countDown();
                        }
                    }
                }));
            }
            assertTrue(running.await(30, TimeUnit.SECONDS), "every thread made 20 calls before the close");
            closing.set(true);
            client.close();
            for (Future<Integer> future : futures) {
                assertTrue(future.get(30, TimeUnit.SECONDS) >= 20);
            }
        } finally {
            // On a failure too: closing ends every loop, which an interrupt alone would not.
            closing.set(true);
            client.close();
            executor.shutdownNow();
        }
        assertThrows(IllegalStateException.class, call::run);
    }
}
