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
 * secret access key or session token is the canary; in mode {@code CONTAINER} it is the container authorization
 * token's file instead, in mode {@code INSTANCE} it is not read, and in mode {@code CHAIN} the configuration names no
 * source, so the default chain finds one in the environment the test gives this JVM. FakeAws, in the test's JVM, serves the canary as
 * the secret value too, after three bytes that are not UTF-8 in the modes ending in {@code BINARY}, and in the
 * credentials its container endpoint and IMDS issue. The subject reads the secret, checks it, writes it back with
 * {@code addVersion(name, Secret)}, closes everything and dumps its heap. With a CA file, FakeAws is on https and its
 * certificate is in that PEM file.
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
                "secrets.endpoint", args[3]));
        switch (args[2]) {
            case "CONTAINER" -> {
                configuration.put("secrets.credentials", "container");
                configuration.put("secrets.container-credentials-uri", args[3] + FakeAws.CONTAINER_PATH);
                configuration.put("secrets.container-authorization-token-file", file.toString());
            }
            case "INSTANCE" -> {
                configuration.put("secrets.credentials", "instance");
                configuration.put("secrets.instance-metadata-endpoint", args[3]);
            }
            case "CHAIN" -> {
                // Nothing: the default chain finds the source in the environment the test gives this JVM.
            }
            default -> {
                configuration.put("secrets.credentials-path", file.toString());
                configuration.put("secrets.aws-profile", "default");
            }
        }
        if (args.length > 4) {
            configuration.put("secrets.tls.ca-file", args[4]);
        }
        try (SecretManagerClient client = SecretManagerClient.create(configuration);
             Secret secret = client.read("canary")) {
            // A binary value has three bytes that are not UTF-8 before the canary.
            long skip = args[2].endsWith("BINARY") ? 3 : 0;
            secret.withSegment(segment -> {
                HeapDump.checksum(segment.asSlice(skip));
                return null;
            });
            client.addVersion("copy", secret);
        }
        HeapDump.dump(dump);
    }
}
