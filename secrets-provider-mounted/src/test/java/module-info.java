/**
 * The mounted-secrets tests, as a module of their own: they reach the provider only through the API and
 * ServiceLoader, the way an application does; the canary tests run {@code CanaryReader} in a child JVM. Open, so that
 * JUnit can reach the test classes.
 */
open module io.descoped.secrets.provider.mounted.test {
    requires io.descoped.secrets.api;
    requires io.descoped.secrets.test.support;
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;
}
