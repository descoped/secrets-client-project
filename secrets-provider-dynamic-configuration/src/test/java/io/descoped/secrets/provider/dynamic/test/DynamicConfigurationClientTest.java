package io.descoped.secrets.provider.dynamic.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamicConfigurationClientTest {

    @TempDir
    Path dir;

    private static SecretManagerClient open(Map<String, String> configuration) {
        Map<String, String> all = new HashMap<>(configuration);
        all.put("secrets.provider", "dynamic-configuration");
        return SecretManagerClient.create(all);
    }

    @Test
    void readsAPropertiesFile() throws IOException {
        Path file = dir.resolve("secrets.properties");
        Files.writeString(file, "answer=42\nurl=https\\://x\\:8080\nref=${answer}!\nunicode=blåbær\n");
        try (SecretManagerClient client = open(Map.of("secrets.property-resource-path", file.toString()))) {
            assertEquals("42", client.readString("answer"));
            assertEquals("https://x:8080", client.readString("url"), "Properties escapes apply");
            assertEquals("42!", client.readString("ref"), "references between values are resolved");
            assertEquals("blåbær", client.readString("unicode"));
        }
    }

    @Test
    void readsADirectoryOfSecretFilesLiterally() throws IOException {
        Path secrets = Files.createDirectory(dir.resolve("secrets"));
        Files.writeString(secrets.resolve("db.password"), "p@ss=${not-a-reference}\n");
        try (SecretManagerClient client = open(Map.of("secrets.directory", secrets.toString()))) {
            assertEquals("p@ss=${not-a-reference}", client.readString("db.password"));
        }
    }

    @Test
    void laterSourcesOverrideEarlierOnes() throws IOException {
        Path file = dir.resolve("secrets.properties");
        Files.writeString(file, "a=file\nb=file\nc=file\n");
        Path secrets = Files.createDirectory(dir.resolve("secrets"));
        Files.writeString(secrets.resolve("b"), "directory");
        Files.writeString(secrets.resolve("c"), "directory");
        try (SecretManagerClient client = open(Map.of(
                "secrets.property-resource-path", file.toString(),
                "secrets.directory", secrets.toString(),
                "secrets.values.c", "inline"))) {
            assertEquals("file", client.readString("a"));
            assertEquals("directory", client.readString("b"));
            assertEquals("inline", client.readString("c"));
        }
    }

    @Test
    void inlineValuesAreTheOnlyKeysTakenFromTheConfiguration() {
        try (SecretManagerClient client = open(Map.of("secrets.values.answer", "42"))) {
            assertArrayEquals("42".getBytes(StandardCharsets.UTF_8), client.readBytes("answer"));
            assertThrows(SecretNotFoundException.class, () -> client.readString("secrets.provider"));
            assertThrows(SecretNotFoundException.class, () -> client.readString("secrets.values.answer"));
        }
    }

    @Test
    void needsAtLeastOneSource() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> open(Map.of()));
        assertTrue(e.getMessage().contains("secrets.property-resource-path"));
    }

    @Test
    void aMissingFileOrDirectoryFails() {
        Map<String, String> missingFile = Map.of("secrets.property-resource-path", dir.resolve("missing").toString());
        assertThrows(SecretManagerException.class, () -> open(missingFile));
        Map<String, String> missingDirectory = Map.of("secrets.directory", dir.resolve("missing").toString());
        assertThrows(SecretManagerException.class, () -> open(missingDirectory));
    }

    @Test
    void anUnresolvedReferenceFailsWithoutTheValue() throws IOException {
        Path file = dir.resolve("secrets.properties");
        Files.writeString(file, "a=hunter2${missing}\n");
        Map<String, String> configuration = Map.of("secrets.property-resource-path", file.toString());
        SecretManagerException e = assertThrows(SecretManagerException.class, () -> open(configuration));
        for (Throwable t = e; t != null; t = t.getCause()) {
            assertFalse(String.valueOf(t.getMessage()).contains("hunter2"), t.toString());
        }
    }

    @Test
    void readsAKubernetesSecretVolume() throws IOException {
        // A mounted secret: the files are symbolic links through ..data to a timestamped directory.
        Path volume = Files.createDirectory(dir.resolve("volume"));
        Path data = Files.createDirectory(volume.resolve("..2026_11_17_12_00_00.000000001"));
        Files.writeString(data.resolve("db.password"), "s3cret\r\n");
        try {
            Files.createSymbolicLink(volume.resolve("..data"), data.getFileName());
            Files.createSymbolicLink(volume.resolve("db.password"), Path.of("..data", "db.password"));
        } catch (UnsupportedOperationException | IOException e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "symbolic links are not supported here");
        }
        try (SecretManagerClient client = open(Map.of("secrets.directory", volume.toString()))) {
            assertEquals("s3cret", client.readString("db.password"), "one trailing CRLF is removed");
            assertThrows(SecretNotFoundException.class, () -> client.readString("..data"));
        }
    }

    @Test
    void theOnlyVersionIsLatestAndMissingSecretsAreNotFound() {
        try (SecretManagerClient client = open(Map.of("secrets.values.a", "1"))) {
            assertEquals("1", client.readString("a", "latest"));
            assertThrows(SecretNotFoundException.class, () -> client.readString("a", "1"));
            assertThrows(SecretNotFoundException.class, () -> client.readString("missing"));
        }
    }

    @Test
    void readBytesReturnsACopy() {
        try (SecretManagerClient client = open(Map.of("secrets.values.a", "secret"))) {
            client.readBytes("a")[0] = 'X';
            assertEquals("secret", client.readString("a"));
        }
    }

    @Test
    void readCopiesTheValueIntoGuardedMemoryAndCloseClosesIt() {
        Secret secret;
        try (SecretManagerClient client = open(Map.of("secrets.values.a", "blåbær"))) {
            secret = client.read("a");
            assertEquals("blåbær", secret.withChars(String::new));
            try (Secret again = client.read("a", "latest")) {
                assertTrue(again.contentEquals(secret));
            }
            assertThrows(SecretNotFoundException.class, () -> client.read("missing"));
        }
        assertEquals("Secret (closed)", secret.toString());
    }

    @Test
    void aCallbackThatCallsTheClientWhileItClosesFailsInsteadOfDeadlocking() throws Exception {
        SecretManagerClient client = open(Map.of("secrets.values.a", "1"));
        Secret secret = client.read("a");
        CountDownLatch inCallback = new CountDownLatch(1);
        CountDownLatch closing = new CountDownLatch(1);
        AtomicReference<Thread> closer = new AtomicReference<>();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<?> reader = executor.submit(() -> secret.withSegment(segment -> {
                inCallback.countDown();
                awaitQuietly(closing);
                // The closer waits for this callback; calling the client now must not wait for the closer.
                while (closer.get().getState() != Thread.State.WAITING) {
                    Thread.onSpinWait();
                }
                return assertThrows(IllegalStateException.class, () -> client.readBytes("a"));
            }));
            assertTrue(inCallback.await(10, TimeUnit.SECONDS));
            closer.set(Thread.ofPlatform().start(client::close));
            closing.countDown();
            assertInstanceOf(IllegalStateException.class, reader.get(10, TimeUnit.SECONDS));
            closer.get().join(Duration.ofSeconds(10));
            assertFalse(closer.get().isAlive());
        } finally {
            executor.shutdownNow();
        }
        assertEquals("Secret (closed)", secret.toString());
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            assertTrue(latch.await(10, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }

    @Test
    void closeInsideACallbackFailsAndALaterCloseWipes() throws Exception {
        SecretManagerClient client = open(Map.of("secrets.values.a", "1"));
        Secret secret = client.read("a");
        secret.withSegment(segment -> assertThrows(IllegalStateException.class, client::close));
        assertEquals("Secret", secret.toString(), "nothing is wiped inside the callback");
        client.close();
        assertEquals("Secret (closed)", secret.toString());
        assertThrows(IllegalStateException.class, () -> client.read("a"));
    }


    @Test
    void isReadOnly() {
        try (SecretManagerClient client = open(Map.of("secrets.values.a", "1"))) {
            assertThrows(UnsupportedOperationException.class, () -> client.addVersion("a", "2"));
            assertEquals("1", client.readString("a"));
        }
    }

    @Test
    void aClosedClientRefusesEverythingAndCloseIsIdempotent() {
        SecretManagerClient client = open(Map.of("secrets.values.a", "1"));
        client.close();
        client.close();
        assertThrows(IllegalStateException.class, () -> client.readBytes("a"));
        assertThrows(IllegalStateException.class, () -> client.read("a"));
        assertThrows(IllegalStateException.class, () -> client.addVersion("a", "2"));
    }

    @Test
    void concurrentReadsSeeWholeValuesUntilTheClientIsClosedUnderThem() throws Exception {
        SecretManagerClient client = open(Map.of("secrets.values.a", "0123456789"));
        callsRaceWithClose(client, () -> assertEquals("0123456789", client.readString("a")));
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
