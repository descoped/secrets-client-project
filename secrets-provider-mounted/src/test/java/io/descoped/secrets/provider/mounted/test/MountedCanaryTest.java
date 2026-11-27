package io.descoped.secrets.provider.mounted.test;

import io.descoped.secrets.test.support.HeapCanary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

/**
 * The canary gate for the mounted provider: reading a mounted secret keeps it off the Java heap. Each test runs
 * {@link CanaryReader} in a child JVM and searches its heap dump.
 */
class MountedCanaryTest {

    private static final String SUBJECT = "io.descoped.secrets.provider.mounted.test/"
            + "io.descoped.secrets.provider.mounted.test.CanaryReader";

    @TempDir
    Path dir;

    @Test
    void readLeavesTheHeapClean() throws Exception {
        HeapCanary.create(dir).run(SUBJECT, "read").assertClean();
    }

    @Test
    void anOpenClientAndSecretAreNotOnTheHeapEither() throws Exception {
        HeapCanary.create(dir).run(SUBJECT, "read-open").assertClean();
    }

    @Test
    void theCopyReadBytesReturnsIsFound() throws Exception {
        HeapCanary.create(dir).run(SUBJECT, "read-bytes").assertLeaked("ascii");
    }
}
