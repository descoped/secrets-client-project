/**
 * Test support for the modules of this reactor, never published.
 *
 * <p>{@link io.descoped.secrets.test.support.HeapCanary} proves that a code path keeps a secret off the Java heap: a
 * child JVM reads a random canary only through the code under test, dumps its heap, and the dump is searched for the
 * canary in every encoding a copy could take. {@link io.descoped.secrets.test.support.HeapDump} is the child's side.
 */
module io.descoped.secrets.test.support {
    requires jdk.management;

    exports io.descoped.secrets.test.support;
}
