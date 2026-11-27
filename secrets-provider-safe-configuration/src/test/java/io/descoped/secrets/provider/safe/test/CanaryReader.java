package io.descoped.secrets.provider.safe.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.test.support.HeapDump;

import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * The subject {@link SafeConfigurationCanaryTest} runs in a child JVM: {@code <canary file> <dump file> <mode>}. The
 * canary file holds the canary as the value of the key {@code canary}; the subject reaches it only through the
 * safe-configuration provider.
 *
 * <ul>
 *     <li>{@code read}: {@code read} it, use it, close everything, dump.</li>
 *     <li>{@code read-open}: the same, but dump while the client and the secret are open.</li>
 *     <li>{@code write}: rewrite the canary file through {@code addVersion} of another key (which copies the canary's
 *     line), add the canary to a second file through {@code addVersion(name, Secret)}, and read it back from there
 *     with a new client.</li>
 *     <li>{@code heap-copy}: {@code read}, then a heap copy that the caller makes and keeps: the dump must hold it.
 *     This proves the test sees a copy that this path makes.</li>
 * </ul>
 */
public final class CanaryReader {

    private static final String KEY = "canary";

    /** Kept reachable, so that the copy is in the dump however the collector behaves. */
    @SuppressWarnings("unused")
    private static byte[] kept;

    private CanaryReader() {
    }

    public static void main(String[] args) throws IOException {
        Path file = Path.of(args[0]);
        Path dump = Path.of(args[1]);
        switch (args[2]) {
            case "read" -> {
                try (SecretManagerClient client = open(file); Secret secret = client.read(KEY)) {
                    checksum(secret);
                }
                HeapDump.dump(dump);
            }
            case "read-open" -> {
                try (SecretManagerClient client = open(file); Secret secret = client.read(KEY)) {
                    checksum(secret);
                    HeapDump.dump(dump);
                }
            }
            case "write" -> {
                Path copy = file.resolveSibling("copy.properties");
                Files.writeString(copy, "# a copy\n", StandardCharsets.UTF_8);
                try (SecretManagerClient source = open(file); SecretManagerClient target = open(copy)) {
                    Values.add(source, "other", "not a secret");
                    try (Secret secret = source.read(KEY)) {
                        target.addVersion(KEY, secret);
                    }
                }
                try (SecretManagerClient client = open(copy); Secret secret = client.read(KEY)) {
                    checksum(secret);
                }
                HeapDump.dump(dump);
            }
            case "heap-copy" -> {
                try (SecretManagerClient client = open(file); Secret secret = client.read(KEY)) {
                    checksum(secret);
                    kept = secret.withSegment(segment -> segment.toArray(ValueLayout.JAVA_BYTE));
                }
                HeapDump.dump(dump);
            }
            default -> throw new IllegalArgumentException("Unknown mode " + args[2]);
        }
    }

    private static SecretManagerClient open(Path file) {
        return SecretManagerClient.create(Map.of(
                "secrets.provider", "safe-configuration",
                "secrets.property-resource-path", file.toString()));
    }

    private static void checksum(Secret secret) {
        secret.withSegment(segment -> {
            HeapDump.checksum(segment);
            return null;
        });
    }
}
