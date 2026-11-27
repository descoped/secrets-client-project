package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.test.support.HeapDump;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * The subject {@link GoogleSecretManagerCanaryTest} runs in a child JVM:
 * {@code <canary file> <dump file> <mode> <endpoint> [<trust store>]}; with a trust store, FakeGoogle is on https and
 * its certificate is in that store. FakeGoogle, in the test's JVM, serves the canary as the secret
 * value and as the access token; in mode {@code user} the canary file is an {@code authorized_user} credentials file
 * whose refresh token is the canary, in mode {@code metadata} the token comes from the metadata server. The subject
 * reads the secret, checks it, writes it back with {@code addVersion(name, Secret)}, closes everything and dumps its
 * heap.
 */
public final class CanaryClient {

    private CanaryClient() {
    }

    public static void main(String[] args) throws IOException {
        Path file = Path.of(args[0]);
        Path dump = Path.of(args[1]);
        String endpoint = args[3];
        if (args.length > 4) {
            // FakeGoogle on https: its certificate is in this trust store.
            TestCertificates.trust(Path.of(args[4]));
        }
        Map<String, String> configuration = new HashMap<>(Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", "test-project",
                "secrets.endpoint", endpoint));
        switch (args[2]) {
            case "user" -> {
                configuration.put("secrets.credentials-path", file.toString());
                configuration.put("secrets.token-endpoint", endpoint + "/token");
            }
            case "metadata" -> {
                configuration.put("secrets.credentials", "metadata");
                configuration.put("secrets.metadata-endpoint", endpoint);
            }
            default -> throw new IllegalArgumentException("Unknown mode " + args[2]);
        }
        try (SecretManagerClient client = SecretManagerClient.create(configuration);
             Secret secret = client.read("canary")) {
            secret.withSegment(segment -> {
                HeapDump.checksum(segment);
                return null;
            });
            client.addVersion("copy", secret);
        }
        HeapDump.dump(dump);
    }
}
