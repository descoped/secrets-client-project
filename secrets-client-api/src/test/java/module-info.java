/**
 * The API tests, as a module of their own that uses the API the way an application and a provider module do. Open,
 * so that JUnit can reach the test classes.
 */
open module io.descoped.secrets.api.test {
    requires io.descoped.secrets.api;
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;
    requires java.logging;
    requires java.management;
    // ExtendedOpenOption.DIRECT, for SecretMemoryReadTest's direct I/O.
    requires jdk.unsupported;

    provides io.descoped.secrets.api.SecretManagerClientInitializer with
            io.descoped.secrets.api.test.MemoryClientInitializer;
}
