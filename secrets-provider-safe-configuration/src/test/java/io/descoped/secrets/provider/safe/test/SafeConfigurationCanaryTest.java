package io.descoped.secrets.provider.safe.test;

import io.descoped.secrets.test.support.HeapCanary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

/**
 * The canary gate for safe-configuration: reading a value and writing one keep it off the Java heap. Each test runs
 * {@link CanaryReader} in a child JVM and searches its heap dump.
 */
class SafeConfigurationCanaryTest {

    private static final String SUBJECT = "io.descoped.secrets.provider.safe.test/"
            + "io.descoped.secrets.provider.safe.test.CanaryReader";

    @TempDir
    Path dir;

    private HeapCanary canary() throws Exception {
        return HeapCanary.create(dir, "# canary test\nfirst=not a secret\ncanary=", "\nlast=not a secret\n");
    }

    @Test
    void readLeavesTheHeapClean() throws Exception {
        canary().run(SUBJECT, "read").assertClean();
    }

    @Test
    void anOpenClientAndSecretAreNotOnTheHeapEither() throws Exception {
        canary().run(SUBJECT, "read-open").assertClean();
    }

    @Test
    void writeLeavesTheHeapClean() throws Exception {
        canary().run(SUBJECT, "write").assertClean();
    }

    @Test
    void aHeapCopyTheCallerKeepsIsFound() throws Exception {
        canary().run(SUBJECT, "heap-copy").assertLeaked("ascii");
    }
}
