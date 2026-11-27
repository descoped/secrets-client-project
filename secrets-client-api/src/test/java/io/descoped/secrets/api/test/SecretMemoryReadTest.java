package io.descoped.secrets.api.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretMemory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** {@link SecretMemory#read}: a channel to its end, into guarded memory. */
class SecretMemoryReadTest {

    @TempDir
    Path dir;

    private SecretMemory memory;

    @BeforeEach
    void create() {
        memory = SecretMemory.create(Map.of());
    }

    @AfterEach
    void close() {
        memory.close();
    }

    private static byte[] random(int length) {
        byte[] bytes = new byte[length];
        new Random(length).nextBytes(bytes);
        return bytes;
    }

    private static byte[] bytes(Secret secret) {
        return secret.withSegment(segment -> segment.toArray(ValueLayout.JAVA_BYTE));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 4095, 4096, 4097, 65_536, 65_537, 300_001})
    void aFileIsReadToItsEnd(int length) throws IOException {
        byte[] content = random(length);
        Path file = Files.write(dir.resolve("f"), content);
        try (FileChannel channel = FileChannel.open(file); Secret secret = memory.read(channel, Integer.MAX_VALUE)) {
            assertArrayEquals(content, bytes(secret));
        }
    }

    /** A channel of unknown length, delivering a few bytes at a time: the buffer grows until the end. */
    @Test
    void aChannelOfUnknownLengthIsReadToItsEnd() throws IOException {
        byte[] content = random(200_000);
        InputStream trickle = new ByteArrayInputStream(content) {
            @Override
            public synchronized int read(byte[] b, int off, int len) {
                return super.read(b, off, Math.min(len, 777));
            }
        };
        try (ReadableByteChannel channel = Channels.newChannel(trickle);
             Secret secret = memory.read(channel, Integer.MAX_VALUE)) {
            assertArrayEquals(content, bytes(secret));
        }
    }

    @Test
    void atMostMaxLengthIsReadFromTheCurrentPosition() throws IOException {
        byte[] content = random(10_000);
        Path file = Files.write(dir.resolve("f"), content);
        try (FileChannel channel = FileChannel.open(file)) {
            channel.position(100);
            try (Secret secret = memory.read(channel, 5000)) {
                assertArrayEquals(Arrays.copyOfRange(content, 100, 5100), bytes(secret));
            }
            try (Secret rest = memory.read(channel, Integer.MAX_VALUE)) {
                assertArrayEquals(Arrays.copyOfRange(content, 5100, 10_000), bytes(rest));
            }
            try (Secret none = memory.read(channel, 0)) {
                assertEquals(0, none.length());
            }
        }
    }

    @Test
    void failuresArePassedOn() throws IOException {
        ReadableByteChannel failing = new ReadableByteChannel() {
            @Override
            public int read(ByteBuffer dst) throws IOException {
                throw new IOException("disk on fire");
            }

            @Override
            public boolean isOpen() {
                return true;
            }

            @Override
            public void close() {
                // Nothing to close.
            }
        };
        IOException e = assertThrows(IOException.class, () -> memory.read(failing, 10));
        assertEquals("disk on fire", e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> memory.read(failing, -1));
        assertThrows(IllegalArgumentException.class, () -> memory.read(failing, Integer.MAX_VALUE + 1L));
        memory.close();
        assertThrows(IllegalStateException.class, () -> memory.read(failing, 10));
    }

    /**
     * Linux with {@code memfd_secret}: a read that pins the destination fails with {@code EFAULT} on those pages, as
     * a read from Cloud Run's FUSE secret volumes did. Direct I/O pins its buffer too, and is the same failure on any
     * Linux file system that supports it. {@link SecretMemory#read} reads such memory through ordinary pages.
     */
    @Test
    void aReadThatPinsItsBufferWorksOnMemoryHiddenFromTheKernel() throws IOException {
        assumeTrue(memory.isHiddenFromKernel(), "memfd_secret is not in use");
        byte[] content = random(64 * 1024);
        Path file = Files.write(dir.resolve("direct"), content);
        FileChannel direct;
        try {
            // com.sun.nio.file.ExtendedOpenOption.DIRECT, looked up so that javac does not warn about it (-Werror).
            OpenOption directIo = (OpenOption) Class.forName("com.sun.nio.file.ExtendedOpenOption")
                    .getField("DIRECT").get(null);
            direct = FileChannel.open(file, StandardOpenOption.READ, directIo);
        } catch (IOException | UnsupportedOperationException | ReflectiveOperationException e) {
            assumeTrue(false, "no direct I/O here: " + e);
            return;
        }
        try (FileChannel channel = direct) {
            // The failure: straight into memfd_secret pages (a fresh, page-aligned slab), the kernel refuses.
            UncheckedIOException refused = assertThrows(UncheckedIOException.class,
                    () -> memory.allocate(content.length, segment -> {
                        try {
                            channel.read(segment.asByteBuffer(), 0);
                        } catch (IOException e) {
                            throw new UncheckedIOException(e);
                        }
                    }).close());
            assertEquals("Bad address", refused.getCause().getMessage());
            // The way out: read() of the same file, as many bytes as it has (direct I/O reads whole blocks).
            channel.position(0);
            try (Secret secret = memory.read(channel, content.length)) {
                assertArrayEquals(content, bytes(secret));
            }
        }
    }
}
