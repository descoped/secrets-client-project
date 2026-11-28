/**
 * The mounted-secrets tests, as a module of their own: they reach the provider only through the API and
 * ServiceLoader, the way an application does; the canary tests run {@code CanaryReader} in a child JVM. Open, so that
 * JUnit can reach the test classes.
 */
open module io.descoped.secrets.provider.mounted.test {
    requires io.descoped.secrets.api;
    // Exports nothing, and the tests still reach it only through ServiceLoader: required so that an IDE, which puts on
    // the module path only what this module reaches, runs the provider as a named module, as Maven does.
    requires io.descoped.secrets.provider.mounted;
    requires io.descoped.secrets.test.support;
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;
}
