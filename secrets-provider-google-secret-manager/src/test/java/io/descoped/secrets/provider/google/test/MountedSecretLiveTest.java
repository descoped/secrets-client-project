package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A Secret Manager secret that Cloud Run mounts as a file, read through the {@code mounted} provider and compared
 * with the same secret read from Secret Manager through this provider. Only when
 * {@code SECRETS_MOUNTED_TEST_DIRECTORY} names the mount's parent directory and {@code SECRETS_GOOGLE_TEST_PROJECT} the
 * project; not run in CI. {@code SECRETS_MOUNTED_TEST_NAME} is the secret's path under the directory (default
 * {@code live/value}); {@code SECRETS_MOUNTED_TEST_SECRET} the Secret Manager secret mounted there (default
 * {@code secrets-client-live-test}), mounted as {@code latest}. It writes nothing, so that {@code latest} stays the
 * version that was mounted: run it alone (the Cloud Run job selects only this class), where no other test adds
 * versions at the same time. {@link GoogleSecretManagerLiveTest}, which does, is disabled while
 * {@code SECRETS_MOUNTED_TEST_DIRECTORY} is set.
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
        String secret = env("SECRETS_MOUNTED_TEST_SECRET", GoogleSecretManagerLiveTest.SECRET);
        try (SecretManagerClient mounted = SecretManagerClient.create(Map.of(
                "secrets.provider", "mounted",
                "secrets.mounted.directory", System.getenv("SECRETS_MOUNTED_TEST_DIRECTORY")));
             SecretManagerClient google = SecretManagerClient.create(GoogleSecretManagerLiveTest.configuration());
             Secret fromFile = mounted.read(name);
             Secret fromApi = google.read(secret)) {
            assertTrue(fromFile.length() > 0, "the mounted file is empty");
            assertTrue(fromFile.contentEquals(fromApi), "the mounted file and Secret Manager differ");
            try (Secret again = mounted.read(name)) {
                assertTrue(again.contentEquals(fromFile), "a second read of the mounted file differs");
            }
            // As heap copies too; compared without printing a byte of them, and wiped.
            byte[] fileCopy = Values.bytes(mounted, name);
            byte[] apiCopy = Values.bytes(google, secret);
            try {
                assertTrue(Arrays.equals(fileCopy, apiCopy), "the heap copies differ");
            } finally {
                Arrays.fill(fileCopy, (byte) 0);
                Arrays.fill(apiCopy, (byte) 0);
            }
        }
    }
}
