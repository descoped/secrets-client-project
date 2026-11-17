/**
 * The Google Secret Manager tests, as a module of their own: they reach the provider only through the API and
 * ServiceLoader, the way an application does, against a local fake of Google. Open, so that JUnit can reach the test
 * classes.
 */
open module io.descoped.secrets.provider.google.test {
    requires io.descoped.secrets.api;
    requires org.junit.jupiter.api;
    requires jdk.httpserver;
}
