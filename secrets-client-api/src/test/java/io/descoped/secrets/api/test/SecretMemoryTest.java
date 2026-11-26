package io.descoped.secrets.api.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretMemoryTest {

    private SecretMemory memory;

    @BeforeEach
    void create() {
        memory = SecretMemory.create(Map.of());
    }

    @AfterEach
    void close() {
        memory.close();
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static boolean wiped(byte[] bytes) {
        for (byte b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static boolean wiped(char[] chars) {
        for (char c : chars) {
            if (c != 0) {
                return false;
            }
        }
        return true;
    }

    @Test
    void guardedAndLockedByDefault() {
        assertTrue(memory.isGuarded());
        assertTrue(memory.isLocked());
    }

    /**
     * memfd_secret depends on the kernel (5.14 and later, on by default since 6.5) and on seccomp, so on Linux this
     * only reports it; it is never available elsewhere.
     */
    @Test
    void hiddenFromTheKernelOnlyOnLinux() {
        if (System.getProperty("os.name").startsWith("Linux")) {
            System.out.println("memfd_secret: " + memory.isHiddenFromKernel());
            try (Secret secret = memory.fromBytes(bytes("s3cret"))) {
                assertEquals("s3cret", secret.withChars(String::new));
            }
        } else {
            assertFalse(memory.isHiddenFromKernel());
        }
    }

    @Test
    void fromBytesCopiesAndWipesTheArgument() {
        byte[] value = bytes("s3cret");
        try (Secret secret = memory.fromBytes(value)) {
            assertTrue(wiped(value));
            assertEquals(6, secret.length());
            assertArrayEquals(bytes("s3cret"), secret.withBytes(byte[]::clone));
        }
    }

    @Test
    void theHandOverCopyIsWipedWhenTheCallReturns() {
        try (Secret secret = memory.fromBytes(bytes("s3cret"))) {
            AtomicReference<byte[]> kept = new AtomicReference<>();
            secret.withBytes(b -> {
                kept.set(b);
                return null;
            });
            assertTrue(wiped(kept.get()));

            AtomicReference<char[]> keptChars = new AtomicReference<>();
            secret.withChars(c -> {
                keptChars.set(c);
                return null;
            });
            assertTrue(wiped(keptChars.get()));
        }
    }

    @Test
    void theHandOverCopyIsWipedWhenTheCallThrows() {
        try (Secret secret = memory.fromBytes(bytes("s3cret"))) {
            AtomicReference<byte[]> kept = new AtomicReference<>();
            assertThrows(IllegalArgumentException.class, () -> secret.withBytes(b -> {
                kept.set(b);
                throw new IllegalArgumentException("consumer failed");
            }));
            assertTrue(wiped(kept.get()));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "a", "pässwörd", "パスワード", "key🔑with😀emoji", "\u0000nul"})
    void charsRoundTripAsUtf8(String value) {
        char[] chars = value.toCharArray();
        try (Secret secret = memory.fromChars(chars)) {
            assertTrue(wiped(chars));
            assertArrayEquals(bytes(value), secret.withBytes(byte[]::clone));
            assertEquals(value, secret.withChars(String::new));
        }
    }

    @Test
    void anUnpairedSurrogateIsRefusedAndStillWiped() {
        char[] chars = {'a', '\uD83D', 'b'};
        assertThrows(IllegalArgumentException.class, () -> memory.fromChars(chars));
        assertTrue(wiped(chars));
        char[] low = {'\uDE00'};
        assertThrows(IllegalArgumentException.class, () -> memory.fromChars(low));
    }

    @ParameterizedTest
    @ValueSource(strings = {"80", "C0AF", "C1BF", "E080AF", "EDA080", "F08080AF", "F4908080", "F5", "FF", "E282", "C3",
            "F09F98"})
    void malformedUtf8IsReportedWithoutTheValue(String hex) {
        byte[] value = java.util.HexFormat.of().parseHex(hex);
        try (Secret secret = memory.fromBytes(value)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> secret.withChars(String::new));
            assertEquals("The secret is not valid UTF-8", e.getMessage());
        }
    }

    @Test
    void allocateLetsTheWriterFillAZeroedSegment() {
        try (Secret secret = memory.allocate(4, segment -> {
            assertEquals(0, segment.get(ValueLayout.JAVA_INT_UNALIGNED, 0));
            segment.copyFrom(MemorySegment.ofArray(bytes("abcd")));
        })) {
            assertArrayEquals(bytes("abcd"), secret.withBytes(byte[]::clone));
        }
    }

    @Test
    void aWriterThatThrowsLeavesNothingAllocated() {
        AtomicReference<MemorySegment> kept = new AtomicReference<>();
        assertThrows(IllegalStateException.class, () -> memory.allocate(8, segment -> {
            kept.set(segment);
            throw new IllegalStateException("writer failed");
        }));
        // The writer's view is no longer valid.
        MemorySegment writerView = kept.get();
        assertThrows(IllegalStateException.class, () -> writerView.get(ValueLayout.JAVA_BYTE, 0));
    }

    @Test
    void theSegmentIsReadOnlyAndInvalidAfterTheCall() {
        try (Secret secret = memory.fromBytes(bytes("s3cret"))) {
            AtomicReference<MemorySegment> kept = new AtomicReference<>();
            secret.withSegment(segment -> {
                assertTrue(segment.isReadOnly());
                assertEquals(6, segment.byteSize());
                assertThrows(IllegalArgumentException.class,
                        () -> segment.set(ValueLayout.JAVA_BYTE, 0, (byte) 1));
                kept.set(segment);
                return null;
            });
            MemorySegment view = kept.get();
            assertThrows(IllegalStateException.class, () -> view.get(ValueLayout.JAVA_BYTE, 0));
        }
    }

    @Test
    void theSegmentCannotBeUsedFromAnotherThread() {
        try (Secret secret = memory.fromBytes(bytes("s3cret"));
             ExecutorService executor = Executors.newSingleThreadExecutor()) {
            secret.withSegment(segment -> {
                Future<?> other = executor.submit(() -> segment.get(ValueLayout.JAVA_BYTE, 0));
                Exception e = assertThrows(Exception.class, other::get);
                assertTrue(e.getCause() instanceof WrongThreadException, e.toString());
                return null;
            });
        }
    }

    @Test
    void aClosedSecretRefusesEverythingButClose() {
        Secret secret = memory.fromBytes(bytes("s3cret"));
        secret.close();
        secret.close();
        assertThrows(IllegalStateException.class, secret::length);
        assertThrows(IllegalStateException.class, () -> secret.withBytes(b -> null));
        assertThrows(IllegalStateException.class, () -> secret.withChars(c -> null));
        assertThrows(IllegalStateException.class, () -> secret.withSegment(s -> null));
        assertEquals("Secret (closed)", secret.toString());
    }

    @Test
    @SuppressWarnings("try")
    void aSecretCannotBeClosedInsideItsOwnCallback() {
        try (Secret secret = memory.fromBytes(bytes("s3cret"))) {
            assertThrows(IllegalStateException.class, () -> secret.withBytes(b -> {
                secret.close();
                return null;
            }));
            assertEquals(6, secret.length());
        }
    }

    @Test
    void toStringNeverShowsTheValueOrLength() {
        try (Secret secret = memory.fromBytes(bytes("s3cret"))) {
            assertEquals("Secret", secret.toString());
        }
    }

    @Test
    void contentEquals() {
        try (Secret a = memory.fromBytes(bytes("same"));
             Secret b = memory.fromBytes(bytes("same"));
             Secret c = memory.fromBytes(bytes("diff"));
             Secret d = memory.fromBytes(bytes("longer"))) {
            assertTrue(a.contentEquals(b));
            assertTrue(a.contentEquals(a));
            assertFalse(a.contentEquals(c));
            assertFalse(a.contentEquals(d));
        }
    }

    @Test
    void closingTheMemoryClosesItsSecrets() {
        Secret secret = memory.fromBytes(bytes("s3cret"));
        memory.close();
        memory.close();
        assertThrows(IllegalStateException.class, secret::length);
        byte[] value = bytes("x");
        assertThrows(IllegalStateException.class, () -> memory.fromBytes(value));
        secret.close();
    }

    @Test
    void manySecretsAcrossSlabsAndLargeOnes() {
        List<Secret> secrets = new ArrayList<>();
        try {
            for (int i = 0; i < 2000; i++) {
                secrets.add(memory.fromBytes(bytes("secret-" + i)));
            }
            byte[] large = new byte[100_000];
            java.util.Arrays.fill(large, (byte) 7);
            secrets.add(memory.fromBytes(large));
            for (int i = 0; i < 2000; i++) {
                assertArrayEquals(bytes("secret-" + i), secrets.get(i).withBytes(byte[]::clone));
            }
            assertEquals(100_000, secrets.get(2000).length());
            assertEquals(7, (byte) secrets.get(2000).withSegment(s -> s.get(ValueLayout.JAVA_BYTE, 99_999)));
            // Free every other one, then reuse the space.
            for (int i = 0; i < 2000; i += 2) {
                secrets.get(i).close();
            }
            for (int i = 0; i < 1000; i++) {
                secrets.add(memory.fromBytes(bytes("again-" + i)));
            }
            for (int i = 1; i < 2000; i += 2) {
                assertArrayEquals(bytes("secret-" + i), secrets.get(i).withBytes(byte[]::clone));
            }
        } finally {
            secrets.forEach(Secret::close);
        }
    }

    /**
     * Allocates and frees secrets of mixed sizes in a seeded random order, so that the slabs' free lists fragment, and
     * checks after every step that no secret shares memory with another: each holds a byte of its own, and still
     * does, with guarded and with plain slabs. Once caught {@code Slab.allocate} reading a free range's length from a TreeMap entry after removing it,
     * when the entry already described another range.
     */
    @ParameterizedTest
    @ValueSource(strings = {"on", "off"})
    void secretsNeverOverlapHoweverTheFreeSpaceFragments(String guard) {
        Random random = new Random(42);
        List<Secret> live = new ArrayList<>();
        List<Byte> marks = new ArrayList<>();
        try (SecretMemory slabs = SecretMemory.create(Map.of(SecretMemory.GUARD_KEY, guard))) {
            for (int step = 0; step < 4000; step++) {
                if (!live.isEmpty() && random.nextInt(5) < 2) {
                    int victim = random.nextInt(live.size());
                    live.remove(victim).close();
                    marks.remove(victim);
                } else {
                    byte mark = (byte) (1 + step % 250);
                    int length = random.nextInt(4) == 0 ? 1 + random.nextInt(3000) : 1 + random.nextInt(200);
                    live.add(slabs.allocate(length, segment -> segment.fill(mark)));
                    marks.add(mark);
                }
                if (step % 20 == 0) {
                    for (int i = 0; i < live.size(); i++) {
                        byte mark = marks.get(i);
                        boolean intact = live.get(i).withSegment(segment -> {
                            for (long k = 0; k < segment.byteSize(); k++) {
                                if (segment.get(ValueLayout.JAVA_BYTE, k) != mark) {
                                    return false;
                                }
                            }
                            return true;
                        });
                        assertTrue(intact, "secret " + i + " of " + live.size() + " at step " + step
                                + " was overwritten");
                    }
                }
            }
        }
    }

    @Test
    void concurrentReadersAndClose() throws Exception {
        Secret secret = memory.fromBytes(bytes("s3cret"));
        CountDownLatch reading = new CountDownLatch(4);
        CountDownLatch release = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newFixedThreadPool(4)) {
            List<Future<String>> readers = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                readers.add(executor.submit(() -> secret.withBytes(b -> {
                    reading.countDown();
                    await(release);
                    return new String(b, StandardCharsets.UTF_8);
                })));
            }
            assertTrue(reading.await(10, TimeUnit.SECONDS));
            Thread closer = Thread.ofPlatform().start(secret::close);
            closer.join(200);
            assertTrue(closer.isAlive(), "close waits for the readers");
            release.countDown();
            for (Future<String> reader : readers) {
                assertEquals("s3cret", reader.get(10, TimeUnit.SECONDS));
            }
            closer.join(10_000);
            assertFalse(closer.isAlive());
        }
        assertThrows(IllegalStateException.class, secret::length);
    }

    @Test
    void manyThreadsAllocatingReadingAndClosing() throws Exception {
        try (ExecutorService executor = Executors.newFixedThreadPool(8)) {
            List<Future<?>> tasks = new ArrayList<>();
            for (int t = 0; t < 8; t++) {
                int thread = t;
                tasks.add(executor.submit(() -> {
                    for (int i = 0; i < 500; i++) {
                        String value = "t" + thread + "-" + i;
                        try (Secret secret = memory.fromBytes(bytes(value))) {
                            assertEquals(value, secret.withChars(String::new));
                        }
                    }
                }));
            }
            for (Future<?> task : tasks) {
                assertNull(task.get(60, TimeUnit.SECONDS));
            }
        }
    }

    @Test
    void unguardedMemoryIsStillOffHeapAndWiped() {
        try (SecretMemory plain = SecretMemory.create(Map.of(SecretMemory.GUARD_KEY, "off"))) {
            assertFalse(plain.isGuarded());
            assertFalse(plain.isLocked());
            byte[] value = bytes("s3cret");
            try (Secret secret = plain.fromBytes(value)) {
                assertTrue(wiped(value));
                assertEquals("s3cret", secret.withChars(String::new));
                assertTrue(secret.withSegment(MemorySegment::isNative));
            }
        }
    }

    @Test
    void preferredLockingIsAccepted() {
        try (SecretMemory preferred = SecretMemory.create(Map.of(SecretMemory.LOCK_KEY, "preferred"))) {
            assertTrue(preferred.isGuarded());
        }
    }

    @Test
    void invalidConfigurationIsRefused() {
        Map<String, String> maybe = Map.of(SecretMemory.GUARD_KEY, "maybe");
        IllegalArgumentException guard = assertThrows(IllegalArgumentException.class,
                () -> SecretMemory.create(maybe));
        assertEquals("Invalid secrets.memory.guard 'maybe': on or off", guard.getMessage());
        Map<String, String> never = Map.of(SecretMemory.LOCK_KEY, "never");
        assertThrows(IllegalArgumentException.class, () -> SecretMemory.create(never));
        assertThrows(IllegalArgumentException.class, () -> memory.allocate(-1, s -> { }));
        assertThrows(NullPointerException.class, () -> memory.fromBytes(null));
    }

    @Test
    void aSecretThatWasNeverClosedIsWipedAndReported() throws Exception {
        try (LogCapture log = new LogCapture(Secret.class)) {
            leak();
            assertEquals(List.of("A secret was not closed; it is wiped now that it is unreachable"),
                    log.collectUntilLogged(20));
        }
    }

    @SuppressWarnings("resource")
    private void leak() {
        memory.fromBytes(bytes("leaked"));
    }

    @Test
    void aClosedSecretIsNotReportedWhenCollected() throws Exception {
        try (LogCapture log = new LogCapture(Secret.class)) {
            memory.fromBytes(bytes("closed")).close();
            assertEquals(List.of(), log.collectUntilLogged(1));
        }
    }

    @Test
    void closingTheMemoryWaitsForAWriterInProgress() throws Exception {
        CountDownLatch writing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
            Future<Secret> allocation = executor.submit(() -> memory.allocate(4, segment -> {
                writing.countDown();
                await(release);
                segment.copyFrom(MemorySegment.ofArray(bytes("abcd")));
            }));
            assertTrue(writing.await(10, TimeUnit.SECONDS));
            Future<?> closing = executor.submit(memory::close);
            assertThrows(TimeoutException.class, () -> closing.get(200, TimeUnit.MILLISECONDS),
                    "close waits for the writer");
            release.countDown();
            Secret secret = allocation.get(10, TimeUnit.SECONDS);
            closing.get(10, TimeUnit.SECONDS);
            assertThrows(IllegalStateException.class, secret::length);
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(10, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    @Test
    @SuppressWarnings("try")
    void theMemoryCannotBeClosedInsideACallbackAndStaysUsable() {
        try (Secret secret = memory.fromBytes(bytes("s3cret"))) {
            assertThrows(IllegalStateException.class, () -> secret.withBytes(b -> {
                memory.close();
                return null;
            }));
            assertEquals("s3cret", secret.withChars(String::new));
            try (Secret another = memory.fromBytes(bytes("more"))) {
                assertEquals(4, another.length());
            }
        }
    }

    @Test
    void contentEqualsBothWaysAtOnce() throws Exception {
        try (Secret a = memory.fromBytes(bytes("same"));
             Secret b = memory.fromBytes(bytes("same"));
             ExecutorService executor = Executors.newFixedThreadPool(2)) {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 200; i++) {
                results.add(executor.submit(() -> a.contentEquals(b)));
                results.add(executor.submit(() -> b.contentEquals(a)));
            }
            for (Future<Boolean> result : results) {
                assertTrue(result.get(10, TimeUnit.SECONDS));
            }
        }
    }

    @Test
    void memoryThatWasNeverClosedIsUnmappedAndReported() throws Exception {
        try (LogCapture log = new LogCapture(SecretMemory.class)) {
            leakMemory();
            assertEquals(List.of("Secret memory was not closed; it is wiped and unmapped now that it is unreachable"),
                    log.collectUntilLogged(20));
        }
    }

    @SuppressWarnings("resource")
    private static void leakMemory() {
        SecretMemory.create(Map.of()).fromBytes(bytes("leaked")).close();
    }

    @Test
    void theSegmentIsTheValueItself() {
        try (Secret secret = memory.fromBytes(bytes("s3cret"))) {
            MemorySegment first = secret.withSegment(s -> MemorySegment.ofAddress(s.address()));
            MemorySegment second = secret.withSegment(s -> MemorySegment.ofAddress(s.address()));
            assertEquals(first.address(), second.address());
            assertSame(Boolean.TRUE, secret.withSegment(MemorySegment::isNative));
        }
    }
}
