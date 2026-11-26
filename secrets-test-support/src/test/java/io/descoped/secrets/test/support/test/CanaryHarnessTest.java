package io.descoped.secrets.test.support.test;

import io.descoped.secrets.test.support.CanaryScan;
import io.descoped.secrets.test.support.HeapCanary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The harness proves itself both ways: guarded memory leaves the heap clean, and a copy in any encoding it searches
 * for is found.
 */
class CanaryHarnessTest {

    private static final String SUBJECT = "io.descoped.secrets.test.support.test/"
            + "io.descoped.secrets.test.support.test.CanarySubject";

    @TempDir
    Path dir;

    @Test
    void guardedMemoryLeavesTheHeapClean() throws Exception {
        HeapCanary.create(dir).run(SUBJECT, "guarded").assertClean();
    }

    @Test
    void anOpenSecretIsNotOnTheHeapEither() throws Exception {
        HeapCanary.create(dir).run(SUBJECT, "guarded-open").assertClean();
    }

    @Test
    void theHandOverCopiesAreGoneAfterTheCall() throws Exception {
        HeapCanary.Run run = HeapCanary.create(dir).run(SUBJECT, "hand-over").assertClean();
        assertTrue(run.output().contains("HANDED OVER 48 48"), run.output());
    }

    @ParameterizedTest
    @CsvSource({
            "leak-ascii, ascii",
            "leak-utf16le, utf-16le",
            "leak-utf16be, utf-16be",
            "leak-hex, hex",
            "leak-HEX, HEX",
            "leak-base64, base64",
            "leak-base64-offset, base64",
            "leak-base64url, base64url"})
    void aCopyInAnyEncodingIsFound(String mode, String encoding) throws Exception {
        HeapCanary.Run run = HeapCanary.create(dir).run(SUBJECT, mode).assertLeaked(encoding);
        AssertionError clean = assertThrows(AssertionError.class, run::assertClean);
        assertTrue(clean.getMessage().startsWith("The canary is on the heap: "), clean.getMessage());
    }

    @Test
    void aSubjectThatDidNotReadTheCanaryFails() throws Exception {
        HeapCanary canary = HeapCanary.create(dir);
        Files.writeString(canary.file(), "something else entirely, long enough to read....");
        HeapCanary.Run run = canary.run(SUBJECT, "guarded");
        AssertionError e = assertThrows(AssertionError.class, run::assertClean);
        assertTrue(e.getMessage().startsWith("The subject did not read the canary"), e.getMessage());
    }

    @Test
    void aSubjectThatFailsIsReported() throws Exception {
        HeapCanary.Run run = HeapCanary.create(dir).run(SUBJECT, "no-such-mode");
        AssertionError e = assertThrows(AssertionError.class, run::assertClean);
        assertTrue(e.getMessage().startsWith("The subject failed"), e.getMessage());
    }

    @Test
    void aSubjectThatHangsIsStoppedAtTheTimeout() throws Exception {
        HeapCanary canary = HeapCanary.create(dir).timeout(Duration.ofSeconds(3));
        long start = System.nanoTime();
        AssertionError e = assertThrows(AssertionError.class, () -> canary.run(SUBJECT, "hang"));
        assertTrue(e.getMessage().startsWith("The subject did not finish within PT3S"), e.getMessage());
        assertTrue(System.nanoTime() - start < Duration.ofSeconds(30).toNanos());
    }

    @Test
    void theCanaryCanBeWrappedInAFileFormat() throws Exception {
        HeapCanary canary = HeapCanary.create(dir, "# å\nkey=", "\n");
        String content = Files.readString(canary.file(), StandardCharsets.UTF_8);
        assertTrue(content.matches("# å\nkey=[A-Za-z0-9]{" + HeapCanary.LENGTH + "}\n"), content);
    }

    @Test
    void theScanFindsFragmentsAnywhereInAFile() throws Exception {
        byte[] canary = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv".getBytes(StandardCharsets.US_ASCII);
        Path file = dir.resolve("data");
        byte[] noise = new byte[100_000];
        new java.util.Random(1).nextBytes(noise);
        // The last 30 bytes of the canary at the very end of the file.
        byte[] content = java.util.Arrays.copyOf(noise, noise.length + 30);
        System.arraycopy(canary, canary.length - 30, content, noise.length, 30);
        Files.write(file, content);
        List<CanaryScan.Finding> findings = CanaryScan.of(canary).scan(file);
        assertEquals(List.of(new CanaryScan.Finding("ascii", noise.length + 30 - CanaryScan.FRAGMENT)), findings);
        Files.write(file, noise);
        assertEquals(List.of(), CanaryScan.of(canary).scan(file));
    }
}
