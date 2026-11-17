package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.SecretManagerClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Against the real Google Secret Manager, only when {@code SECRETS_GOOGLE_TEST_PROJECT} names a project. Credentials
 * are Application Default Credentials, or the key file in {@code SECRETS_GOOGLE_TEST_KEY_PATH}. It adds versions to
 * the secret {@code secrets-client-live-test}, creating it with automatic replication if needed. Not run in CI.
 */
@EnabledIfEnvironmentVariable(named = "SECRETS_GOOGLE_TEST_PROJECT", matches = ".+")
class GoogleSecretManagerLiveTest {

    @Test
    void addThenReadVersions() {
        Map<String, String> configuration = new HashMap<>(Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", System.getenv("SECRETS_GOOGLE_TEST_PROJECT")));
        String keyPath = System.getenv("SECRETS_GOOGLE_TEST_KEY_PATH");
        if (keyPath != null) {
            configuration.put("secrets.service-account-key-path", keyPath);
        }
        String first = UUID.randomUUID().toString();
        String second = UUID.randomUUID().toString();
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            String v1 = client.addVersion("secrets-client-live-test", first);
            String v2 = client.addVersion("secrets-client-live-test", second);
            assertEquals(second, client.readString("secrets-client-live-test"));
            assertEquals(first, client.readString("secrets-client-live-test", v1));
            assertEquals(second, client.readString("secrets-client-live-test", v2));
        }
    }
}
