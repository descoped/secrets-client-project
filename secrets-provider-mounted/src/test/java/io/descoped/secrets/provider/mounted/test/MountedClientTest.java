package io.descoped.secrets.provider.mounted.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class MountedClientTest {

    @TempDir
    Path dir;

    private Path secrets;

    private SecretManagerClient open() throws IOException {
        secrets = Files.createDirectories(dir.resolve("secrets"));
        return SecretManagerClient.create(configuration(secrets.toString()));
    }

    private static Map<String, String> configuration(String directory) {
        return Map.of("secrets.provider", "mounted", "secrets.mounted.directory", directory);
    }

    @Test
    void aValueIsTheFileExactlyAndIsReadOnEveryRead() throws IOException {
        try (SecretManagerClient client = open()) {
            Files.writeString(secrets.resolve("api-key"), "s3cret\n");
            assertEquals("s3cret\n", client.readString("api-key"));
            assertEquals("s3cret\n", client.readString("api-key", "latest"));
            try (Secret secret = client.read("api-key")) {
                assertEquals("s3cret\n", secret.withChars(String::new));
            }
            // Rotated in place: the next read sees it.
            Files.writeString(secrets.resolve("api-key"), "rotated");
            assertEquals("rotated", client.readString("api-key"));
            Files.write(secrets.resolve("empty"), new byte[0]);
            assertArrayEquals(new byte[0], client.readBytes("empty"));
        }
    }

    @Test
    void binaryAndLargeValuesAreRead() throws IOException {
        byte[] large = new byte[3 * 1024 * 1024 + 17];
        new Random(42).nextBytes(large);
        try (SecretManagerClient client = open()) {
            Files.write(secrets.resolve("large.bin"), large);
            assertArrayEquals(large, client.readBytes("large.bin"));
            Files.write(secrets.resolve("too-large"), new byte[4 * 1024 * 1024 + 1]);
            SecretManagerException e = assertThrows(SecretManagerException.class,
                    () -> client.readBytes("too-large"));
            assertTrue(e.getMessage().contains("larger than"), e.getMessage());
            Files.write(secrets.resolve("at-limit"), new byte[4 * 1024 * 1024]);
            assertEquals(4 * 1024 * 1024, client.readBytes("at-limit").length);
        }
    }

    /** A file whose size is not known in advance (a FIFO reports 0): read until its end. */
    @Test
    void aFileOfUnknownSizeIsReadToItsEnd() throws Exception {
        try (SecretManagerClient client = open()) {
            Path fifo = secrets.resolve("stream");
            Process mkfifo;
            try {
                mkfifo = new ProcessBuilder("mkfifo", fifo.toString()).start();
            } catch (IOException e) {
                assumeTrue(false, "no mkfifo: " + e.getMessage());
                return;
            }
            assumeTrue(mkfifo.waitFor(10, TimeUnit.SECONDS) && mkfifo.exitValue() == 0, "mkfifo failed");
            byte[] value = new byte[100_000];
            new Random(7).nextBytes(value);
            CompletableFuture<Void> writer = CompletableFuture.runAsync(() -> {
                try (OutputStream out = Files.newOutputStream(fifo)) {
                    out.write(value);
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            assertArrayEquals(value, client.readBytes("stream"));
            writer.get(10, TimeUnit.SECONDS);
        }
    }

    @Test
    void nestedNamesAndKubernetesStyleLinksAreRead() throws IOException {
        try (SecretManagerClient client = open()) {
            Files.createDirectories(secrets.resolve("db"));
            Files.writeString(secrets.resolve("db/password"), "pw");
            assertEquals("pw", client.readString("db/password"));
            // Kubernetes: <dir>/key -> ..data/key, ..data -> ..2026_11_27_12_00_00.1/
            Path version = Files.createDirectories(secrets.resolve("..2026_11_27_12_00_00.1"));
            Files.writeString(version.resolve("token"), "t0ken");
            Files.createSymbolicLink(secrets.resolve("..data"), version.getFileName());
            Files.createSymbolicLink(secrets.resolve("token"), Path.of("..data", "token"));
            assertEquals("t0ken", client.readString("token"));
        }
    }

    /**
     * Reads racing Kubernetes-style rotations: a file resolved through {@code ..data} can be gone when it is opened.
     * A stress test, not a deterministic one, with rotations far more frequent than Kubernetes makes: without the
     * provider's retries it fails in most runs, with them in none measured.
     */
    @Test
    void aRotationDuringAReadIsNotReportedAsMissing() throws Exception {
        try (SecretManagerClient client = open()) {
            Path first = Files.createDirectories(secrets.resolve("..first"));
            Files.writeString(first.resolve("token"), "one");
            Files.createSymbolicLink(secrets.resolve("..data"), first.getFileName());
            Files.createSymbolicLink(secrets.resolve("token"), Path.of("..data", "token"));
            AtomicBoolean stop = new AtomicBoolean();
            CompletableFuture<Void> rotator = CompletableFuture.runAsync(() -> {
                int n = 0;
                try {
                    while (!stop.get()) {
                        Path next = Files.createDirectories(secrets.resolve("..v" + ++n));
                        Files.writeString(next.resolve("token"), "v" + n);
                        Path link = Files.createSymbolicLink(secrets.resolve("..data_tmp"), next.getFileName());
                        Files.move(link, secrets.resolve("..data"), StandardCopyOption.ATOMIC_MOVE);
                        Path old = secrets.resolve(n == 1 ? "..first" : "..v" + (n - 1));
                        Files.delete(old.resolve("token"));
                        Files.delete(old);
                        // Kubernetes rotates rarely; a pause keeps two swaps from landing within one read.
                        LockSupport.parkNanos(TimeUnit.MICROSECONDS.toNanos(100));
                    }
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            try {
                for (int i = 0; i < 60000; i++) {
                    assertFalse(client.readString("token").isEmpty());
                }
            } finally {
                stop.set(true);
                rotator.get(10, TimeUnit.SECONDS);
            }
        }
    }

    @Test
    void aLinkOutOfTheDirectoryIsRefused() throws IOException {
        try (SecretManagerClient client = open()) {
            Path outside = Files.writeString(dir.resolve("outside"), "not yours");
            Files.createSymbolicLink(secrets.resolve("escape"), outside);
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.readBytes("escape"));
            assertTrue(e.getMessage().contains("outside"), e.getMessage());
            assertFalse(e.getMessage().contains("not yours"), e.getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "missing", "..", "../outside", "a/../b", "/etc/passwd", "a//b", "a/", ".hidden",
            "..data/token", "db", "-dash", "sp ace", "q?"})
    void namesThatAreNotSecretsAreNotFound(String name) throws IOException {
        try (SecretManagerClient client = open()) {
            Files.createDirectories(secrets.resolve("db"));
            Files.writeString(dir.resolve("outside"), "x");
            assertThrows(SecretNotFoundException.class, () -> client.readBytes(name));
        }
    }

    @Test
    void onlyTheLatestVersionExistsAndWritesAreRefused() throws IOException {
        try (SecretManagerClient client = open()) {
            Files.writeString(secrets.resolve("a"), "v");
            assertThrows(SecretNotFoundException.class, () -> client.readBytes("a", "1"));
            assertThrows(UnsupportedOperationException.class, () -> client.addVersion("a", "w"));
            try (Secret value = client.read("a")) {
                assertThrows(UnsupportedOperationException.class, () -> client.addVersion("a", value));
            }
            assertEquals("v", client.readString("a"));
        }
    }

    @Test
    void closingClosesTheClientAndTheSecretsItReturned() throws IOException {
        SecretManagerClient client = open();
        Files.writeString(secrets.resolve("a"), "v");
        Secret secret = client.read("a");
        client.close();
        client.close();
        assertThrows(IllegalStateException.class, () -> client.readBytes("a"));
        assertThrows(IllegalStateException.class, () -> client.read("a"));
        assertThrows(IllegalStateException.class, () -> client.addVersion("a", "w"));
        assertThrows(IllegalStateException.class, () -> secret.withSegment(segment -> null));
    }

    @Test
    void configurationIsChecked() throws IOException {
        Map<String, String> none = Map.of("secrets.provider", "mounted");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(none));
        Map<String, String> missing = configuration(dir.resolve("absent").toString());
        SecretManagerException e = assertThrows(SecretManagerException.class,
                () -> SecretManagerClient.create(missing));
        assertTrue(e.getMessage().startsWith("Cannot open the mounted secrets directory"), e.getMessage());
        Path file = Files.writeString(dir.resolve("file"), "x");
        Map<String, String> notADirectory = configuration(file.toString());
        e = assertThrows(SecretManagerException.class, () -> SecretManagerClient.create(notADirectory));
        assertTrue(e.getMessage().endsWith("is not a directory"), e.getMessage());
    }

    @Test
    void secretsAreNotInMessages() throws IOException {
        try (SecretManagerClient client = open()) {
            Files.write(secrets.resolve("big"), "hunter2".repeat(700_000).getBytes(StandardCharsets.UTF_8));
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.readBytes("big"));
            assertFalse(e.getMessage().contains("hunter2"), e.getMessage());
        }
    }
}
