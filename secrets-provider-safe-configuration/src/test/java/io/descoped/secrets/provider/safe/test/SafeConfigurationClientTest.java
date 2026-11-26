package io.descoped.secrets.provider.safe.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class SafeConfigurationClientTest {

    @TempDir
    Path dir;

    private Path file(String content) throws IOException {
        Path file = dir.resolve("secrets.properties");
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private static SecretManagerClient open(Path file) {
        return SecretManagerClient.create(Map.of(
                "secrets.provider", "safe-configuration",
                "secrets.property-resource-path", file.toString()));
    }

    private static String read(Path file) throws IOException {
        return Files.readString(file, StandardCharsets.UTF_8);
    }

    @Test
    void readsTheFormat() throws IOException {
        Path file = file("""
                # a comment
                  # an indented comment

                plain=password1
                with-equals=key=value
                  trimmed key  = value with spaces\s
                url=https://x:8080/a!b\\c
                unicode=blåbær €
                empty=
                last=no newline""");
        try (SecretManagerClient client = open(file)) {
            assertEquals("password1", client.readString("plain"));
            assertEquals("key=value", client.readString("with-equals"));
            assertEquals(" value with spaces ", client.readString("trimmed key"));
            assertEquals("https://x:8080/a!b\\c", client.readString("url"));
            assertEquals("blåbær €", client.readString("unicode"));
            assertArrayEquals(new byte[0], client.readBytes("empty"));
            assertEquals("no newline", client.readString("last"));
        }
    }

    @Test
    void readsCrlfAndAByteOrderMark() throws IOException {
        Path file = dir.resolve("dos.properties");
        Files.write(file, "\uFEFFa=1\r\n# c\r\nb=2\r\n".getBytes(StandardCharsets.UTF_8));
        try (SecretManagerClient client = open(file)) {
            assertEquals("1", client.readString("a"));
            assertEquals("2", client.readString("b"));
        }
    }

    @Test
    void malformedLinesFailWithTheLineNumberAndNeverTheValue() throws IOException {
        Path noEquals = file("a=1\nhunter2\n");
        SecretManagerException e = assertThrows(SecretManagerException.class, () -> open(noEquals));
        assertTrue(e.getMessage().contains("line 2 has no '='"), e.getMessage());
        assertFalse(e.getMessage().contains("hunter2"));

        Path emptyKey = file("  =hunter2\n");
        e = assertThrows(SecretManagerException.class, () -> open(emptyKey));
        assertTrue(e.getMessage().contains("line 1 has an empty key"), e.getMessage());
        assertFalse(e.getMessage().contains("hunter2"));

        Path duplicate = file("a=1\nb=2\na=hunter2\n");
        e = assertThrows(SecretManagerException.class, () -> open(duplicate));
        assertTrue(e.getMessage().contains("line 3: duplicate key 'a'"), e.getMessage());
        assertFalse(e.getMessage().contains("hunter2"));
    }

    @Test
    void aMissingFileFails() {
        Path missing = dir.resolve("missing.properties");
        assertThrows(SecretManagerException.class, () -> open(missing));
    }

    @Test
    void theOnlyVersionIsLatest() throws IOException {
        try (SecretManagerClient client = open(file("a=1\n"))) {
            assertEquals("1", client.readString("a", "latest"));
            assertThrows(SecretNotFoundException.class, () -> client.readString("a", "1"));
            assertThrows(SecretNotFoundException.class, () -> client.readString("missing"));
        }
    }

    @Test
    void readBytesReturnsACopy() throws IOException {
        try (SecretManagerClient client = open(file("a=secret\n"))) {
            byte[] first = client.readBytes("a");
            first[0] = 'X';
            assertEquals("secret", client.readString("a"));
        }
    }

    @Test
    void readReturnsACopyInGuardedMemoryThatTheCallerAndCloseOfTheClientClose() throws IOException {
        Secret kept;
        try (SecretManagerClient client = open(file("a=blåbær\n"))) {
            kept = client.read("a");
            try (Secret other = client.read("a", "latest")) {
                assertTrue(other.contentEquals(kept));
            }
            assertEquals("blåbær", kept.withChars(String::new), "closing one copy leaves the others");
            assertEquals("blåbær", client.readString("a"), "and the client's own value");
            assertThrows(SecretNotFoundException.class, () -> client.read("a", "1"));
            assertThrows(SecretNotFoundException.class, () -> client.read("missing"));
        }
        assertEquals("Secret (closed)", kept.toString());
    }

    @Test
    void addVersionOfASecretWritesItAndLeavesTheSecretToTheCaller() throws IOException {
        Path file = file("a=1\n");
        try (SecretManagerClient client = open(file);
             SecretMemory memory = SecretMemory.create(Map.of());
             Secret value = memory.fromBytes("blåbær".getBytes(StandardCharsets.UTF_8));
             Secret broken = memory.fromBytes("line1\nhunter2".getBytes(StandardCharsets.UTF_8))) {
            assertEquals("latest", client.addVersion("b", value));
            assertEquals("blåbær", value.withChars(String::new));
            assertEquals("blåbær", client.readString("b"));
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.addVersion("c", broken));
            assertFalse(e.getMessage().contains("hunter2"));
        }
        assertEquals("a=1\nb=blåbær\n", read(file));
    }

    @Test
    void anEmptyFileHasNoSecrets() throws IOException {
        Path file = file("");
        try (SecretManagerClient client = open(file)) {
            assertThrows(SecretNotFoundException.class, () -> client.read("a"));
            client.addVersion("a", "1");
        }
        assertEquals("a=1\n", read(file));
    }

    @Test
    void theGuardedMemoryIsConfiguredWithTheClient() throws IOException {
        Path file = file("a=1\n");
        try (SecretManagerClient client = SecretManagerClient.create(Map.of(
                "secrets.provider", "safe-configuration",
                "secrets.property-resource-path", file.toString(),
                SecretMemory.GUARD_KEY, "off"))) {
            assertEquals("1", client.readString("a"));
        }
        Map<String, String> invalid = Map.of(
                "secrets.provider", "safe-configuration",
                "secrets.property-resource-path", file.toString(),
                SecretMemory.LOCK_KEY, "sometimes");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(invalid));
    }

    @Test
    void addVersionRewritesOnlyItsLineAndKeepsEverythingElse() throws IOException {
        Path file = file("# header\r\nurl=https://x:8080\r\n\r\nquestion=41\r\nkv=key=value\r\n");
        try (SecretManagerClient client = open(file)) {
            assertEquals("latest", client.addVersion("question", "42"));
            assertEquals("latest", client.addVersion("added", "blåbær"));
            assertEquals("42", client.readString("question"));
            assertEquals("blåbær", client.readString("added"));
        }
        assertEquals("# header\r\nurl=https://x:8080\r\n\r\nquestion=42\r\nkv=key=value\r\nadded=blåbær\r\n",
                read(file));
        try (SecretManagerClient client = open(file)) {
            assertEquals("https://x:8080", client.readString("url"));
            assertEquals("key=value", client.readString("kv"));
            assertEquals("42", client.readString("question"));
            assertEquals("blåbær", client.readString("added"));
        }
    }

    @Test
    void addVersionAppendsAfterALastLineWithoutNewline() throws IOException {
        Path file = file("a=1");
        try (SecretManagerClient client = open(file)) {
            client.addVersion("b", "2");
        }
        assertEquals("a=1\nb=2\n", read(file));
    }

    @Test
    void addVersionKeepsChangesMadeToTheFileByOthers() throws IOException {
        Path file = file("a=1\n");
        try (SecretManagerClient client = open(file)) {
            Files.writeString(file, "a=1\nother=written-elsewhere\n");
            client.addVersion("a", "2");
        }
        assertEquals("a=2\nother=written-elsewhere\n", read(file));
    }

    @Test
    void addVersionStoresACopy() throws IOException {
        try (SecretManagerClient client = open(file(""))) {
            byte[] value = "secret".getBytes(StandardCharsets.UTF_8);
            client.addVersion("a", value);
            value[0] = 'X';
            assertEquals("secret", client.readString("a"));
        }
    }

    @Test
    void addVersionRejectsWhatTheFormatCannotHold() throws IOException {
        Path file = file("a=1\n");
        try (SecretManagerClient client = open(file)) {
            SecretManagerException e = assertThrows(SecretManagerException.class,
                    () -> client.addVersion("b", "line1\nhunter2"));
            assertFalse(e.getMessage().contains("hunter2"));
            assertThrows(SecretManagerException.class, () -> client.addVersion("b", "x\ry"));
            for (String name : List.of("", " ", " b", "b\t", "\fb", "b=c", "#b", "b\nc")) {
                assertThrows(SecretManagerException.class, () -> client.addVersion(name, "1"), name);
            }
            byte[] value = "1".getBytes(StandardCharsets.UTF_8);
            assertThrows(SecretManagerException.class, () -> client.addVersion("b\uD800", value),
                    "an unpaired surrogate would be written as '?'");
            assertThrows(SecretNotFoundException.class, () -> client.readString("b"));
        }
        assertEquals("a=1\n", read(file));
    }

    @Test
    void theWrittenFileIsReadableByItsOwnerOnly() throws IOException {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path file = file("a=1\n");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
        try (SecretManagerClient client = open(file)) {
            client.addVersion("a", "2");
        }
        assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                Files.getPosixFilePermissions(file));
        try (var files = Files.list(dir)) {
            assertEquals(List.of(file), files.toList(), "no temporary file is left behind");
        }
    }

    @Test
    void aReadOnlyFileIsAnErrorAndChangesNothing() throws IOException {
        assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        assumeFalse("root".equals(System.getProperty("user.name")), "root may write to a read-only file");
        Path file = file("a=1\n");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("r--------"));
        try (SecretManagerClient client = open(file)) {
            assertThrows(SecretManagerException.class, () -> client.addVersion("a", "2"));
            assertEquals("1", client.readString("a"));
        }
        assertEquals("a=1\n", read(file));
    }

    @Test
    void aClosedClientRefusesEverythingAndCloseIsIdempotent() throws IOException {
        SecretManagerClient client = open(file("a=1\n"));
        client.close();
        client.close();
        assertThrows(IllegalStateException.class, () -> client.readBytes("a"));
        assertThrows(IllegalStateException.class, () -> client.read("a"));
        assertThrows(IllegalStateException.class, () -> client.addVersion("a", "2"));
        try (SecretMemory memory = SecretMemory.create(Map.of()); Secret value = memory.fromBytes(new byte[]{'2'})) {
            assertThrows(IllegalStateException.class, () -> client.addVersion("a", value));
        }
        assertThrows(IllegalStateException.class, () -> client.addVersion("#invalid", "2"),
                "a closed client fails before it checks the name");
    }

    @Test
    void aCallbackThatCallsTheClientWhileItClosesFailsInsteadOfDeadlocking() throws Exception {
        SecretManagerClient client = open(file("a=1\n"));
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
        SecretManagerClient client = open(file("a=1\n"));
        Secret secret = client.read("a");
        secret.withSegment(segment -> assertThrows(IllegalStateException.class, client::close));
        assertEquals("Secret", secret.toString(), "nothing is wiped inside the callback");
        client.close();
        assertEquals("Secret (closed)", secret.toString());
        assertThrows(IllegalStateException.class, () -> client.read("a"));
    }


    @Test
    void blanksAroundKeysAndBeforeCommentsAreSpaceTabFormFeedAndVerticalTab() throws IOException {
        try (SecretManagerClient client = open(file("\f# a comment\n\u000B\tkey\f = value\n"))) {
            assertEquals(" value", client.readString("key"));
            assertThrows(SecretNotFoundException.class, () -> client.readString("# a comment"));
        }
    }

    @Test
    void addVersionFailsWithoutChangesWhenSomeoneElseBrokeTheFile() throws IOException {
        Path file = file("a=1\n");
        try (SecretManagerClient client = open(file)) {
            Files.writeString(file, "a=1\nbroken line\n");
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.addVersion("a", "2"));
            assertTrue(e.getMessage().contains("line 2 has no '='"), e.getMessage());
            assertEquals("1", client.readString("a"));
        }
        assertEquals("a=1\nbroken line\n", read(file));
    }

    @Test
    void addVersionWritesThroughASymbolicLinkAndKeepsTheLink() throws IOException {
        Path target = file("a=1\n");
        Path link;
        try {
            link = Files.createSymbolicLink(dir.resolve("link.properties"), target);
        } catch (UnsupportedOperationException | IOException e) {
            assumeTrue(false, "symbolic links are not supported here");
            return;
        }
        try (SecretManagerClient client = open(link)) {
            client.addVersion("a", "2");
        }
        assertTrue(Files.isSymbolicLink(link));
        assertEquals("a=2\n", read(target));
    }

    @Test
    void concurrentReadsAndWritesSeeWholeValues() throws Exception {
        try (SecretManagerClient client = open(file("a=0000\n"))) {
            ExecutorService executor = Executors.newFixedThreadPool(8);
            try {
                List<Future<?>> futures = new ArrayList<>();
                for (int i = 0; i < 200; i++) {
                    String value = String.format("%04d", i);
                    futures.add(executor.submit(() -> client.addVersion("a", value)));
                    futures.add(executor.submit(() -> {
                        String read = client.readString("a");
                        assertTrue(read.matches("\\d{4}"), read);
                    }));
                }
                for (Future<?> future : futures) {
                    future.get();
                }
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void readsAndWritesInFlightWhenTheClientIsClosedFinishOrSeeAClosedClient() throws Exception {
        SecretManagerClient client = open(file("a=0000\n"));
        callsRaceWithClose(client, () -> {
            client.addVersion("a", "1111");
            assertTrue(client.readString("a").matches("\\d{4}"));
        });
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
