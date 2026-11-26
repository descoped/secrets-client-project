package io.descoped.secrets.test.support;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.zip.CRC32C;

/**
 * Proves that a code path keeps a secret off the Java heap.
 *
 * <p>A canary, a random value of {@value #LENGTH} letters and digits, is written to a file. A child JVM (the
 * subject) gets the file's path, reads it only through the code under test, reports a checksum of what it read and
 * dumps its whole heap, garbage included ({@link HeapDump}). The dump is then searched for the canary as it would
 * look in any copy: its bytes (also a Latin-1 {@code String}), UTF-16 in either byte order (a {@code char[]} or a
 * UTF-16 {@code String}), hex in either case, and Base64 and Base64url at each of the three alignments. Fragments of
 * {@value CanaryScan#FRAGMENT} bytes from the start, middle and end of each form are searched, so a partial copy is
 * found too.
 *
 * <p>The subject must not receive the canary any other way, which is why it runs in a JVM of its own: this one holds
 * the canary on its heap.
 *
 * <pre>{@code
 * HeapCanary.create(dir)
 *         .run("io.descoped.secrets.provider.safe.test/io.descoped.secrets.provider.safe.test.ReadSubject")
 *         .assertClean();
 * }</pre>
 */
public final class HeapCanary {

    /** The length of the canary, in ASCII letters and digits. */
    public static final int LENGTH = 48;

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int TIMEOUT_SECONDS = 120;

    private final Path dir;
    private final byte[] canary;
    private final Path file;

    private HeapCanary(Path dir, byte[] canary, Path file) {
        this.dir = dir;
        this.canary = canary;
        this.file = file;
    }

    /**
     * Generates a canary and writes it to {@code canary.secret} in {@code dir}, with no line ending.
     *
     * @param dir a directory of its own, for the canary, the heap dump and the child's error file
     * @return the canary
     * @throws IOException if the file cannot be written
     */
    public static HeapCanary create(Path dir) throws IOException {
        SecureRandom random = new SecureRandom();
        byte[] canary = new byte[LENGTH];
        for (int i = 0; i < LENGTH; i++) {
            canary[i] = (byte) ALPHABET.charAt(random.nextInt(ALPHABET.length()));
        }
        Path file = Files.write(dir.resolve("canary.secret"), canary);
        return new HeapCanary(dir, canary, file);
    }

    /**
     * The file that holds the canary.
     *
     * @return the file
     */
    public Path file() {
        return file;
    }

    /**
     * Runs {@code main}, a {@code module/class} on this JVM's module path, in a child JVM with
     * {@code --enable-native-access=io.descoped.secrets.api}, and searches its heap dump. The subject gets the
     * canary file, the dump file and {@code args}, in that order.
     *
     * @param main the subject, as {@code module/class}
     * @param args more arguments for the subject
     * @return what happened
     * @throws IOException          if the child cannot be started or the dump cannot be read
     * @throws InterruptedException if interrupted while waiting for the child
     */
    public Run run(String main, String... args) throws IOException, InterruptedException {
        Path dump = dir.resolve("heap-" + System.nanoTime() + ".hprof");
        List<String> command = new ArrayList<>();
        command.add(ProcessHandle.current().info().command()
                .orElse(Path.of(System.getProperty("java.home"), "bin", "java").toString()));
        // The coverage profile's JaCoCo agent, so that what runs in the child counts too.
        ManagementFactory.getRuntimeMXBean().getInputArguments().stream()
                .filter(argument -> argument.startsWith("-javaagent:"))
                .forEach(command::add);
        command.addAll(List.of(
                "--enable-native-access=io.descoped.secrets.api",
                "-Xmx128m",
                "-XX:-CreateCoredumpOnCrash", "-XX:ErrorFile=" + dir.resolve("hs_err_%p.log"),
                "--module-path", System.getProperty("jdk.module.path"),
                "--module", main,
                file.toString(), dump.toString()));
        command.addAll(Arrays.asList(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new AssertionError("The subject did not finish within " + TIMEOUT_SECONDS + " seconds:\n" + output);
        }
        List<CanaryScan.Finding> findings = Files.exists(dump) ? CanaryScan.of(canary).scan(dump) : List.of();
        return new Run(process.exitValue(), output, expectedChecksum(), Files.exists(dump), findings);
    }

    private String expectedChecksum() {
        CRC32C crc = new CRC32C();
        crc.update(canary);
        return HexFormat.of().toHexDigits((int) crc.getValue());
    }

    /**
     * What a subject did, and what its heap dump holds.
     *
     * @param exit     the subject's exit value
     * @param output   what it printed
     * @param checksum the canary's CRC32C, which the subject must report
     * @param dumped   whether it dumped its heap
     * @param findings the copies of the canary found in the dump
     */
    public record Run(int exit, String output, String checksum, boolean dumped, List<CanaryScan.Finding> findings) {

        /**
         * Asserts that the subject read the canary, dumped its heap, and that the dump holds no copy of it.
         *
         * @return this
         * @throws AssertionError if not
         */
        public Run assertClean() {
            assertCompleted();
            if (!findings.isEmpty()) {
                throw new AssertionError("The canary is on the heap: " + findings + "\n" + output);
            }
            return this;
        }

        /**
         * Asserts that the subject read the canary and dumped its heap, and that the dump holds a copy of it in
         * {@code encoding}. For proving the harness finds what it should.
         *
         * @param encoding one of the encodings {@link CanaryScan} searches, such as {@code utf-16le}
         * @return this
         * @throws AssertionError if not
         */
        public Run assertLeaked(String encoding) {
            assertCompleted();
            if (findings.stream().noneMatch(finding -> finding.encoding().equals(encoding))) {
                throw new AssertionError("No " + encoding + " copy of the canary found; found " + findings + "\n"
                        + output);
            }
            return this;
        }

        private void assertCompleted() {
            if (exit != 0 || !dumped || !output.contains(HeapDump.DUMPED)) {
                throw new AssertionError("The subject failed (exit " + exit + ", dumped " + dumped + "):\n" + output);
            }
            if (!output.contains(HeapDump.CHECKSUM + checksum)) {
                throw new AssertionError("The subject did not read the canary (expected checksum " + checksum + "):\n"
                        + output);
            }
        }
    }
}
