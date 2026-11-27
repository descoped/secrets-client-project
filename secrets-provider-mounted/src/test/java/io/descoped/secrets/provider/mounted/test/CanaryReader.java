package io.descoped.secrets.provider.mounted.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.test.support.HeapDump;

import java.nio.file.Path;
import java.util.Map;

/**
 * The subject {@link MountedCanaryTest} runs in a child JVM: {@code <canary file> <dump file> <mode>}. The canary file
 * is a mounted secret: its directory is the mount, its file name the secret's name; the subject reaches it only
 * through the mounted provider.
 *
 * <ul>
 *     <li>{@code read}: {@code read} it, use it, close everything, dump.</li>
 *     <li>{@code read-open}: the same, but dump while the client and the secret are open.</li>
 *     <li>{@code read-bytes}: {@code readBytes}, whose array is the caller's and is kept: the dump must hold it. This
 *     proves the test sees a copy that this path makes.</li>
 * </ul>
 */
public final class CanaryReader {

    /** Kept reachable, so that the copy is in the dump however the collector behaves. */
    @SuppressWarnings("unused")
    private static byte[] kept;

    private CanaryReader() {
    }

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args[0]);
        Path dump = Path.of(args[1]);
        String name = file.getFileName().toString();
        try (SecretManagerClient client = SecretManagerClient.create(Map.of(
                "secrets.provider", "mounted",
                "secrets.mounted.directory", file.getParent().toString()));
             Secret secret = client.read(name)) {
            secret.withSegment(segment -> {
                HeapDump.checksum(segment);
                return null;
            });
            switch (args[2]) {
                case "read" -> {
                    // Dumped after everything is closed.
                }
                case "read-open" -> HeapDump.dump(dump);
                case "read-bytes" -> kept = client.readBytes(name);
                default -> throw new IllegalArgumentException("Unknown mode " + args[2]);
            }
        }
        if (!args[2].equals("read-open")) {
            HeapDump.dump(dump);
        }
    }
}
