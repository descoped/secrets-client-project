package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A Secret Manager secret that Cloud Run mounts as a file, read through the {@code mounted} provider and compared
 * with the same secret read from Secret Manager through this provider. Only when
 * {@code SECRETS_MOUNTED_TEST_DIRECTORY} names the mount's parent directory and {@code SECRETS_GOOGLE_TEST_PROJECT} the
 * project; not run in CI. {@code SECRETS_MOUNTED_TEST_NAME} is the secret's path under the directory (default
 * {@code live/value}); {@code SECRETS_MOUNTED_TEST_SECRET} the Secret Manager secret mounted there (default
 * {@code secrets-client-live-test}), mounted as {@code latest}. It writes nothing, so that {@code latest} stays the
 * version that was mounted: run it where no other test adds versions at the same time.
 */
@EnabledIfEnvironmentVariable(named = "SECRETS_MOUNTED_TEST_DIRECTORY", matches = ".+")
@EnabledIfEnvironmentVariable(named = "SECRETS_GOOGLE_TEST_PROJECT", matches = ".+")
class MountedSecretLiveTest {

    private static String env(String name, String defaultValue) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? defaultValue : value;
    }

    @Test
    void theMountedFileIsTheSecretManagerValue() {
        String name = env("SECRETS_MOUNTED_TEST_NAME", "live/value");
        String secret = env("SECRETS_MOUNTED_TEST_SECRET", "secrets-client-live-test");
        try (SecretManagerClient mounted = SecretManagerClient.create(Map.of(
                "secrets.provider", "mounted",
                "secrets.mounted.directory", System.getenv("SECRETS_MOUNTED_TEST_DIRECTORY")));
             SecretManagerClient google = SecretManagerClient.create(GoogleSecretManagerLiveTest.configuration());
             Secret fromFile = mounted.read(name);
             Secret fromApi = google.read(secret)) {
            assertTrue(fromFile.length() > 0, "the mounted file is empty");
            assertEquals(fromApi.length(), fromFile.length(), "the mounted file and Secret Manager differ in length");
            long mismatch = fromFile.withSegment(file -> fromApi.withSegment(api -> file.mismatch(api)));
            assertEquals(-1, mismatch, "the mounted file and Secret Manager differ");
            // Read again, and as a heap copy: the same bytes.
            try (Secret again = mounted.read(name)) {
                long again2 = again.withSegment(a -> fromFile.withSegment(a::mismatch));
                assertEquals(-1, again2, "a second read differs");
            }
            assertArrayEquals(mounted.readBytes(name), google.readBytes(secret));
        }
    }
}
