package io.descoped.secrets.provider.aws.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.test.support.HeapDump;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * The subject {@link AwsSecretsManagerCanaryTest} runs in a child JVM:
 * {@code <canary file> <dump file> <mode> <endpoint> [<CA file>]}. The canary file is a shared credentials file whose
 * secret access key or session token is the canary; FakeAws, in the test's JVM, serves the canary as the secret value
 * too. The subject reads the secret, checks it, writes it back with {@code addVersion(name, Secret)}, closes
 * everything and dumps its heap. With a CA file, FakeAws is on https and its certificate is in that PEM file.
 */
public final class CanaryClient {

    private CanaryClient() {
    }

    public static void main(String[] args) throws IOException {
        Path file = Path.of(args[0]);
        Path dump = Path.of(args[1]);
        Map<String, String> configuration = new HashMap<>(Map.of(
                "secrets.provider", "aws-secrets-manager",
                "secrets.region", FakeAws.REGION,
                "secrets.endpoint", args[3],
                "secrets.credentials-path", file.toString(),
                "secrets.aws-profile", "default"));
        if (args.length > 4) {
            configuration.put("secrets.tls.ca-file", args[4]);
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
