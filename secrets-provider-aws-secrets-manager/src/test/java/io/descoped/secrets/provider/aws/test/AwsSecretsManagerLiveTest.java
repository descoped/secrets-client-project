package io.descoped.secrets.provider.aws.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Against the real AWS Secrets Manager, only when {@code SECRETS_AWS_TEST_REGION} names a region; not run in CI.
 * Credentials come from the source {@code SECRETS_AWS_TEST_CREDENTIALS} names ({@code profile}, {@code container},
 * {@code instance}; on ECS {@code container}, so that the run proves the task role), else the default chain; a
 * profile from {@code SECRETS_AWS_TEST_PROFILE} (else {@code AWS_PROFILE}, else {@code default}). It adds versions to the secrets {@code secrets-client-live-test} and
 * {@code secrets-client-live-test-binary}, creating them if needed; Secrets Manager drops versions without a staging
 * label by itself, so nothing is cleaned up. Each secret is billed while it exists.
 */
@EnabledIfEnvironmentVariable(named = "SECRETS_AWS_TEST_REGION", matches = ".+")
class AwsSecretsManagerLiveTest {

    static final String SECRET = "secrets-client-live-test";

    private static Map<String, String> configuration() {
        Map<String, String> configuration = new HashMap<>(Map.of(
                "secrets.provider", "aws-secrets-manager",
                "secrets.region", System.getenv("SECRETS_AWS_TEST_REGION")));
        String profile = System.getenv("SECRETS_AWS_TEST_PROFILE");
        if (profile != null) {
            configuration.put("secrets.aws-profile", profile);
        }
        String credentials = System.getenv("SECRETS_AWS_TEST_CREDENTIALS");
        if (credentials != null) {
            configuration.put("secrets.credentials", credentials);
        }
        return configuration;
    }

    @Test
    void addThenReadVersions() {
        String first = "first " + UUID.randomUUID() + " \"quoted\" åäö";
        String second = "second " + UUID.randomUUID();
        byte[] binary = new byte[60 * 1024];
        new SecureRandom().nextBytes(binary);
        binary[0] = (byte) 0xFF;
        try (SecretManagerClient client = SecretManagerClient.create(configuration())) {
            String firstId = Values.add(client, SECRET, first);
            String secondId = Values.add(client, SECRET, second);
            assertEquals(second, Values.text(client, SECRET));
            assertEquals(second, Values.text(client, SECRET, secondId));
            assertEquals(first, Values.text(client, SECRET, firstId));
            assertEquals(first, Values.text(client, SECRET, "AWSPREVIOUS"));

            Values.add(client, SECRET + "-binary", binary);
            assertArrayEquals(binary, Values.bytes(client, SECRET + "-binary"));

            assertThrows(SecretNotFoundException.class, () -> client.read("secrets-client-live-test-missing"));
        }
    }
}
