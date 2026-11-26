/**
 * The harness's own tests: subjects that keep the canary in guarded memory, which must leave the heap clean, and
 * subjects that leak it in each encoding, which the scan must find. Open, so that JUnit can reach the test classes.
 */
open module io.descoped.secrets.test.support.test {
    requires io.descoped.secrets.test.support;
    requires io.descoped.secrets.api;
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;
}
