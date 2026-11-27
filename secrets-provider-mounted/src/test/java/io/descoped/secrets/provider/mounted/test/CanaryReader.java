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
 *     <li>{@code read-stream}: read it from a FIFO that {@code cat} fills from the canary file, outside this JVM: a
 *     file of unknown size, read through the buffer that grows (the canary file is padded past its first size).</li>
 *     <li>{@code read-bytes}: {@code readBytes}, whose array is the caller's and is kept: the dump must hold it. This
 *     proves the test sees a copy that this path makes.</li>
 * </ul>
 */
public final class CanaryReader {

    /** The padding {@link MountedCanaryTest} puts before and after the canary in {@code read-stream}. */
    static final int PADDING = 10_000;

    /** Kept reachable, so that the copy is in the dump however the collector behaves. */
    @SuppressWarnings("unused")
    private static byte[] kept;

    private CanaryReader() {
    }

    public static void main(String[] args) throws Exception {
        Path file = Path.of(args[0]);
        Path dump = Path.of(args[1]);
        String name = file.getFileName().toString();
        Process cat = null;
        long padding = 0;
        if (args[2].equals("read-stream")) {
            Path fifo = file.resolveSibling("stream");
            if (new ProcessBuilder("mkfifo", fifo.toString()).inheritIO().start().waitFor() != 0) {
                throw new IllegalStateException("mkfifo failed");
            }
            cat = new ProcessBuilder("sh", "-c", "cat \"$0\" > \"$1\"", file.toString(), fifo.toString())
                    .inheritIO().start();
            name = "stream";
            padding = PADDING;
        }
        try (SecretManagerClient client = SecretManagerClient.create(Map.of(
                "secrets.provider", "mounted",
                "secrets.mounted.directory", file.getParent().toString()));
             Secret secret = client.read(name)) {
            long pad = padding;
            secret.withSegment(segment -> {
                HeapDump.checksum(segment.asSlice(pad, segment.byteSize() - 2 * pad));
                return null;
            });
            switch (args[2]) {
                case "read", "read-stream" -> {
                    // Dumped after everything is closed.
                }
                case "read-open" -> HeapDump.dump(dump);
                case "read-bytes" -> kept = client.readBytes(name);
                default -> throw new IllegalArgumentException("Unknown mode " + args[2]);
            }
        }
        if (cat != null && cat.waitFor() != 0) {
            throw new IllegalStateException("cat failed");
        }
        if (!args[2].equals("read-open")) {
            HeapDump.dump(dump);
        }
    }
}
