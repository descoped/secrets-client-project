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

import static org.junit.jupiter.api.Assertions.assertEquals;
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
    void readOfTheLatestOrAGivenVersionAndAddVersionRoundTrip() {
        try (MemoryClient client = memory();
             SecretMemory own = SecretMemory.create(Map.of(SecretMemory.GUARD_KEY, "off"));
             Secret first = own.fromBytes("blåbær".getBytes(StandardCharsets.UTF_8));
             Secret second = own.fromChars("hei".toCharArray())) {
            assertEquals("1", client.addVersion("a", first));
            assertEquals("2", client.addVersion("a", second));
            try (Secret latest = client.read("a"); Secret one = client.read("a", "1")) {
                assertTrue(latest.contentEquals(second));
                assertTrue(one.contentEquals(first));
                assertEquals("blåbær", one.withChars(String::new));
            }
        }
    }

    @Test
    void aMissingSecretOrVersionThrowsSecretNotFound() {
        try (MemoryClient client = memory();
             SecretMemory own = SecretMemory.create(Map.of(SecretMemory.GUARD_KEY, "off"));
             Secret x = own.fromChars(new char[]{'x'})) {
            SecretNotFoundException e = assertThrows(SecretNotFoundException.class, () -> client.read("missing"));
            assertEquals("missing", e.secretName());
            assertNull(e.secretVersion());
            assertEquals("Secret 'missing' not found", e.getMessage());

            client.addVersion("present", x);
            e = assertThrows(SecretNotFoundException.class, () -> client.read("present", "7"));
            assertEquals("7", e.secretVersion());
            assertEquals("Secret 'present' version '7' not found", e.getMessage());
            assertInstanceOf(SecretManagerException.class, e);
        }
    }

    @Test
    void nullArgumentsAreRejected() {
        try (MemoryClient client = memory();
             SecretMemory own = SecretMemory.create(Map.of(SecretMemory.GUARD_KEY, "off"));
             Secret x = own.fromChars(new char[]{'x'})) {
            assertThrows(NullPointerException.class, () -> client.read(null));
            assertThrows(NullPointerException.class, () -> client.addVersion(null, x));
            assertThrows(NullPointerException.class, () -> client.addVersion("a", null));
        }
    }
}
