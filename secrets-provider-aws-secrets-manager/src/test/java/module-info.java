/**
 * The AWS Secrets Manager tests, as a module of their own: they reach the provider only through the API and
 * ServiceLoader, the way an application does; {@code FakeAws} verifies each request's signature with the JDK. The
 * canary tests run {@code CanaryClient} in a child JVM. Open, so that JUnit can reach the test classes.
 */
open module io.descoped.secrets.provider.aws.test {
    requires io.descoped.secrets.api;
    requires io.descoped.secrets.test.support;
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;
    requires jdk.httpserver;
}
