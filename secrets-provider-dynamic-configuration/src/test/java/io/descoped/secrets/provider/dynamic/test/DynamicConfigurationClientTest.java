package io.descoped.secrets.provider.dynamic.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
        assertThrows(SecretManagerException.class,
                () -> open(Map.of("secrets.property-resource-path", dir.resolve("missing").toString())));
        assertThrows(SecretManagerException.class,
                () -> open(Map.of("secrets.directory", dir.resolve("missing").toString())));
    }

    @Test
    void anUnresolvedReferenceFailsWithoutTheValue() throws IOException {
        Path file = dir.resolve("secrets.properties");
        Files.writeString(file, "a=hunter2${missing}\n");
        SecretManagerException e = assertThrows(SecretManagerException.class,
                () -> open(Map.of("secrets.property-resource-path", file.toString())));
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
        assertThrows(IllegalStateException.class, () -> client.addVersion("a", "2"));
    }
}
