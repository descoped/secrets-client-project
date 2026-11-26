package io.descoped.secrets.api.test;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guard pages and access control, seen from a child JVM ({@link GuardProbe}) that reads raw addresses: a fault there
 * may end the process, which a test cannot survive in its own JVM.
 */
class GuardPageTest {

    @TempDir
    Path dir;

    private record Result(int exit, String output) {
    }

    private Result probe(String... args) throws IOException, InterruptedException {
        return run(List.of(), "--enable-native-access=io.descoped.secrets.api,io.descoped.secrets.api.test", args);
    }

    /**
     * Runs the probe with {@code args}, the JVM option {@code access} (native access), and {@code prefix} in front of
     * the command (a shell that sets a limit first).
     */
    private Result run(List<String> prefix, String access, String... args) throws IOException, InterruptedException {
        String java = ProcessHandle.current().info().command()
                .orElse(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        List<String> command = new ArrayList<>(prefix);
        command.addAll(List.of(java, access,
                "-XX:-CreateCoredumpOnCrash", "-XX:ErrorFile=" + dir.resolve("hs_err_%p.log"),
                "--module-path", System.getProperty("jdk.module.path"),
                "--module", "io.descoped.secrets.api.test/io.descoped.secrets.api.test.GuardProbe"));
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(60, TimeUnit.SECONDS));
        return new Result(process.exitValue(), output);
    }

    @Test
    void theProbeReadsMemoryItMayRead() throws Exception {
        Result result = probe("control");
        assertEquals(0, result.exit(), result.output());
        assertTrue(result.output().contains("READ 42"), result.output());
    }

    @Test
    void theGuardPageBeforeASlabCannotBeRead() throws Exception {
        assertFaults(probe("before"));
    }

    @Test
    void aSecretCannotBeReadOutsideItsCallback() throws Exception {
        assertFaults(probe("after"));
    }

    @Test
    void withoutNativeAccessGuardedMemoryIsRefused() throws Exception {
        // A harmless option in place of --enable-native-access.
        Result result = run(List.of(), "-Xshare:auto", "create");
        assertTrue(result.output().contains("REFUSED io.descoped.secrets.api.SecretManagerException: Guarded memory"
                + " needs native access: start the JVM with --enable-native-access=io.descoped.secrets.api"),
                result.output());
    }

    /** Linux enforces the locked-memory limit for an unprivileged process; macOS does not reliably. */
    @Test
    void overTheLockedMemoryLimitLockingFailsUnlessOnlyPreferred() throws Exception {
        Assumptions.assumeTrue(System.getProperty("os.name").startsWith("Linux"), "Linux only");
        Assumptions.assumeFalse("root".equals(System.getProperty("user.name")), "root may lock regardless");
        List<String> noLocking = List.of("/bin/sh", "-c", "ulimit -l 0 && exec \"$0\" \"$@\"");
        String access = "--enable-native-access=io.descoped.secrets.api,io.descoped.secrets.api.test";

        Result required = run(noLocking, access, "create", "required");
        assertTrue(required.output().contains("REFUSED io.descoped.secrets.api.SecretManagerException: Cannot lock"
                + " secret memory (mlock failed: errno"), required.output());
        assertTrue(required.output().contains("secrets.memory.lock=preferred"), required.output());

        Result preferred = run(noLocking, access, "create", "preferred");
        assertTrue(preferred.output().contains("CREATED locked=false length=1"), preferred.output());
        assertTrue(preferred.output().contains("could not be locked"), preferred.output());
    }

    private static void assertFaults(Result result) {
        assertFalse(result.output().contains("READ"), result.output());
        assertTrue(result.exit() != 0 || result.output().contains("FAULT"), result.output());
    }
}
