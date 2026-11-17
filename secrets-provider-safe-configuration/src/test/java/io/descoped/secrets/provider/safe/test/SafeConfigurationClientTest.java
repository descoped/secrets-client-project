package io.descoped.secrets.provider.safe.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
                last=no newline""".replace("no newline\n", "no newline"));
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
        Files.write(file, "﻿a=1\r\n# c\r\nb=2\r\n".getBytes(StandardCharsets.UTF_8));
        try (SecretManagerClient client = open(file)) {
            assertEquals("1", client.readString("a"));
            assertEquals("2", client.readString("b"));
        }
    }

    @Test
    void malformedLinesFailWithTheLineNumberAndNeverTheValue() throws IOException {
        SecretManagerException e = assertThrows(SecretManagerException.class,
                () -> open(file("a=1\nhunter2\n")));
        assertTrue(e.getMessage().contains("line 2 has no '='"), e.getMessage());
        assertFalse(e.getMessage().contains("hunter2"));

        e = assertThrows(SecretManagerException.class, () -> open(file("  =hunter2\n")));
        assertTrue(e.getMessage().contains("line 1 has an empty key"), e.getMessage());
        assertFalse(e.getMessage().contains("hunter2"));

        e = assertThrows(SecretManagerException.class, () -> open(file("a=1\nb=2\na=hunter2\n")));
        assertTrue(e.getMessage().contains("line 3: duplicate key 'a'"), e.getMessage());
        assertFalse(e.getMessage().contains("hunter2"));
    }

    @Test
    void aMissingFileFails() {
        assertThrows(SecretManagerException.class, () -> open(dir.resolve("missing.properties")));
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
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> client.addVersion("b", "line1\nhunter2"));
            assertFalse(e.getMessage().contains("hunter2"));
            assertThrows(IllegalArgumentException.class, () -> client.addVersion("b", "x\ry"));
            for (String name : List.of("", " ", " b", "b=c", "#b", "b\nc")) {
                assertThrows(IllegalArgumentException.class, () -> client.addVersion(name, "1"), name);
            }
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
        assertThrows(IllegalStateException.class, () -> client.addVersion("a", "2"));
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
}
