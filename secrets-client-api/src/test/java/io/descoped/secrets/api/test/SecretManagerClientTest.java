package io.descoped.secrets.api.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;
import io.descoped.service.provider.api.ProviderException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretManagerClientTest {

    private static final Map<String, String> MEMORY = Map.of(
            SecretManagerClient.PROVIDER_KEY, "memory",
            "memory.required", "yes");

    private static MemoryClient memory() {
        return (MemoryClient) SecretManagerClient.create(MEMORY);
    }

    private static boolean wiped(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    @Test
    void createSelectsTheProviderNamedInTheConfigurationAndPassesTheWholeMap() {
        try (SecretManagerClient client = SecretManagerClient.create(MEMORY)) {
            assertInstanceOf(MemoryClient.class, client);
            assertEquals(MEMORY, MemoryClientInitializer.lastConfiguration);
        }
    }

    @Test
    void createWithoutAProviderNameFails() {
        Map<String, String> noProvider = Map.of("memory.required", "yes");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> SecretManagerClient.create(noProvider));
        assertTrue(e.getMessage().contains(SecretManagerClient.PROVIDER_KEY));
        Map<String, String> blankProvider = Map.of(SecretManagerClient.PROVIDER_KEY, " ");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(blankProvider));
        assertThrows(NullPointerException.class, () -> SecretManagerClient.create(null));
    }

    @Test
    void createWithAnUnknownProviderFails() {
        Map<String, String> unknown = Map.of(SecretManagerClient.PROVIDER_KEY, "nope");
        assertThrows(ProviderException.class, () -> SecretManagerClient.create(unknown));
    }

    @Test
    void createWithoutARequiredKeyFails() {
        Map<String, String> missingKey = Map.of(SecretManagerClient.PROVIDER_KEY, "memory");
        assertThrows(IllegalArgumentException.class, () -> SecretManagerClient.create(missingKey));
    }

    @Test
    void createRejectsNullValues() {
        Map<String, String> configuration = new HashMap<>(MEMORY);
        configuration.put("other", null);
        assertThrows(NullPointerException.class, () -> SecretManagerClient.create(configuration));
    }

    @Test
    void readOfTheLatestVersionAndAddVersionOfASecretRoundTrip() {
        try (MemoryClient client = memory();
             SecretMemory own = SecretMemory.create(Map.of(SecretMemory.GUARD_KEY, "off"));
             Secret value = own.fromBytes("blåbær".getBytes(StandardCharsets.UTF_8))) {
            assertEquals("1", client.addVersion("a", value));
            byte[] handedOver = client.received.getLast();
            assertTrue(wiped(handedOver), "the heap copy is wiped when addVersion returns");
            try (Secret read = client.read("a")) {
                assertTrue(read.contentEquals(value));
            }
            assertTrue(wiped(client.returned.getLast()), "read wipes the array it copied");
            assertThrows(NullPointerException.class, () -> client.addVersion(null, value));
            assertThrows(NullPointerException.class, () -> client.addVersion("a", (Secret) null));
            assertThrows(SecretNotFoundException.class, () -> client.read("missing"));
        }
    }

    @Test
    void stringsAndCharsRoundTripAsUtf8() {
        try (MemoryClient client = memory()) {
            assertEquals("1", client.addVersion("greeting", "blåbær €"));
            assertEquals("2", client.addVersion("greeting", "hei".toCharArray()));
            assertEquals("hei", client.readString("greeting"));
            assertEquals("blåbær €", client.readString("greeting", "1"));
            assertArrayEquals("blåbær €".toCharArray(), client.readChars("greeting", "1"));
            assertArrayEquals("hei".getBytes(StandardCharsets.UTF_8), client.readBytes("greeting"));
            assertArrayEquals(new char[0], readEmpty(client));
        }
    }

    private static char[] readEmpty(MemoryClient client) {
        client.addVersion("empty", new byte[0]);
        return client.readChars("empty");
    }

    @Test
    void readCharsAndReadStringWipeTheBytesTheyRead() {
        try (MemoryClient client = memory()) {
            client.addVersion("password", "secret");
            client.readChars("password");
            client.readString("password");
            assertEquals(2, client.returned.size());
            client.returned.forEach(bytes -> assertTrue(wiped(bytes)));
        }
    }

    @Test
    void addVersionFromCharsOrStringWipesTheBytesItPassedOn() {
        try (MemoryClient client = memory()) {
            client.addVersion("a", "secret".toCharArray());
            client.addVersion("b", "secret");
            assertEquals(2, client.received.size());
            client.received.forEach(bytes -> assertTrue(wiped(bytes)));
            assertEquals("secret", client.readString("a"));
            assertEquals("secret", client.readString("b"));
        }
    }

    @Test
    void addVersionFromCharsLeavesTheCallersArrayAlone() {
        try (MemoryClient client = memory()) {
            char[] value = "secret".toCharArray();
            client.addVersion("a", value);
            assertArrayEquals("secret".toCharArray(), value);
        }
    }

    @Test
    void invalidUtf8FailsWithoutTheValueInTheMessageAndIsWiped() {
        try (MemoryClient client = memory()) {
            byte[] invalid = {'p', 'w', (byte) 0xC3, (byte) 0x28};
            client.addVersion("binary", invalid);
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.readChars("binary"));
            assertTrue(e.getMessage().contains("'binary'"));
            assertFalse(e.getMessage().contains("pw"));
            assertTrue(wiped(client.returned.get(0)));
        }
    }

    @Test
    void anUnpairedSurrogateIsRejectedNotReplaced() {
        try (MemoryClient client = memory()) {
            SecretManagerException e = assertThrows(SecretManagerException.class,
                    () -> client.addVersion("bad", "ab\uD800"));
            assertTrue(e.getMessage().contains("'bad'"));
            assertThrows(SecretManagerException.class, () -> client.addVersion("bad", new char[]{'a', '\uDC00'}));
            assertTrue(client.received.isEmpty());
        }
    }

    @Test
    void aMissingSecretOrVersionThrowsSecretNotFound() {
        try (MemoryClient client = memory()) {
            SecretNotFoundException e = assertThrows(SecretNotFoundException.class, () -> client.readString("missing"));
            assertEquals("missing", e.secretName());
            assertNull(e.secretVersion());
            assertEquals("Secret 'missing' not found", e.getMessage());

            client.addVersion("present", "x");
            e = assertThrows(SecretNotFoundException.class, () -> client.readChars("present", "7"));
            assertEquals("7", e.secretVersion());
            assertEquals("Secret 'present' version '7' not found", e.getMessage());
            assertInstanceOf(SecretManagerException.class, e);
        }
    }

    @Test
    void nullArgumentsAreRejected() {
        try (MemoryClient client = memory()) {
            assertThrows(NullPointerException.class, () -> client.addVersion("a", (String) null));
            assertThrows(NullPointerException.class, () -> client.addVersion("a", (char[]) null));
            assertThrows(NullPointerException.class, () -> client.readString(null));
        }
    }
}
