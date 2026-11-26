package io.descoped.secrets.test.support.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.test.support.HeapDump;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * The subject {@link CanaryHarnessTest} runs in a child JVM: {@code <canary file> <dump file> <mode>}. The guarded
 * modes keep the canary in {@link SecretMemory} and must leave the heap clean; each leak mode puts one copy of it on
 * the heap, in one encoding, without ever holding the plain value on the heap.
 */
public final class CanarySubject {

    /** Kept reachable, so that the leaked copy is in the dump however the collector behaves. */
    @SuppressWarnings("unused")
    private static Object leaked;

    private CanarySubject() {
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        Path file = Path.of(args[0]);
        Path dump = Path.of(args[1]);
        String mode = args[2];
        if (mode.equals("hang")) {
            Thread.sleep(Long.MAX_VALUE);
        }
        if (mode.startsWith("leak-")) {
            ByteBuffer value = readDirect(file);
            HeapDump.checksum(value);
            leaked = leak(mode, value);
            HeapDump.dump(dump);
            return;
        }
        try (SecretMemory memory = SecretMemory.create(Map.of())) {
            Secret secret = readGuarded(memory, file);
            secret.withSegment(segment -> {
                HeapDump.checksum(segment);
                return null;
            });
            switch (mode) {
                case "guarded" -> secret.close();
                case "guarded-open" -> HeapDump.dump(dump);
                case "hand-over" -> {
                    int bytes = secret.withBytes(b -> b.length);
                    int chars = secret.withChars(c -> c.length);
                    System.out.println("HANDED OVER " + bytes + " " + chars);
                    secret.close();
                }
                default -> throw new IllegalArgumentException(mode);
            }
        }
        if (!mode.equals("guarded-open")) {
            HeapDump.dump(dump);
        }
    }

    /** Reads the file straight into guarded memory: a direct buffer over the secret's own segment. */
    private static Secret readGuarded(SecretMemory memory, Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file)) {
            return memory.allocate(channel.size(), segment -> readFully(channel, segment));
        }
    }

    private static void readFully(FileChannel channel, MemorySegment segment) {
        ByteBuffer buffer = segment.asByteBuffer();
        try {
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) {
                    throw new IllegalStateException("The file is shorter than it was");
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Reads the file into a direct buffer: off the heap, so only the leak itself puts it there. */
    private static ByteBuffer readDirect(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file)) {
            ByteBuffer buffer = ByteBuffer.allocateDirect((int) channel.size());
            while (buffer.hasRemaining()) {
                if (channel.read(buffer) < 0) {
                    throw new IllegalStateException("The file is shorter than it was");
                }
            }
            return buffer.flip();
        }
    }

    private static Object leak(String mode, ByteBuffer value) {
        int n = value.remaining();
        return switch (mode) {
            case "leak-ascii" -> {
                byte[] copy = new byte[n];
                value.get(0, copy);
                yield copy;
            }
            case "leak-utf16le" -> {
                // A heap dump stores a char[] big-endian. For an ASCII canary the UTF-16LE fragments match that
                // one byte in, so this is found as both; the label says which pattern matched, not the byte order.
                char[] chars = new char[n];
                for (int i = 0; i < n; i++) {
                    chars[i] = (char) value.get(i);
                }
                yield chars;
            }
            case "leak-utf16be" -> {
                byte[] bytes = new byte[2 * n];
                for (int i = 0; i < n; i++) {
                    bytes[2 * i + 1] = value.get(i);
                }
                yield bytes;
            }
            case "leak-hex" -> hex(value, "0123456789abcdef");
            case "leak-HEX" -> hex(value, "0123456789ABCDEF");
            case "leak-base64" -> base64(value, Base64.getEncoder(), 0);
            case "leak-base64-offset" -> base64(value, Base64.getEncoder(), 1);
            case "leak-base64url" -> base64(value, Base64.getUrlEncoder(), 0);
            default -> throw new IllegalArgumentException(mode);
        };
    }

    private static byte[] hex(ByteBuffer value, String digits) {
        byte[] out = new byte[2 * value.remaining()];
        for (int i = 0; i < value.remaining(); i++) {
            int b = value.get(i) & 0xFF;
            out[2 * i] = (byte) digits.charAt(b >> 4);
            out[2 * i + 1] = (byte) digits.charAt(b & 0xF);
        }
        return out;
    }

    /**
     * Base64 of {@code prefix} zero bytes followed by the value, as in a longer payload, encoded three bytes at a
     * time so that the plain value is never on the heap whole.
     */
    private static byte[] base64(ByteBuffer value, Base64.Encoder encoder, int prefix) {
        int total = prefix + value.remaining();
        byte[] out = new byte[(total + 2) / 3 * 4];
        byte[] three = new byte[3];
        byte[] four = new byte[4];
        int o = 0;
        for (int i = 0; i < total; i += 3) {
            int count = Math.min(3, total - i);
            for (int k = 0; k < count; k++) {
                int at = i + k - prefix;
                three[k] = at < 0 ? 0 : value.get(at);
            }
            int written = encoder.encode(count == 3 ? three : Arrays.copyOf(three, count), four);
            System.arraycopy(four, 0, out, o, written);
            o += written;
        }
        Arrays.fill(three, (byte) 0);
        return out;
    }
}
