package consumer;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Uses each provider through {@link SecretManagerClient#create(Map)} only. Prints one line per provider and exits
 * with 1 on the first failure.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) throws IOException {
        String mode = args.length > 0 ? args[0] : "?";
        Path file = Files.createTempFile("secrets", ".properties");
        try {
            Files.writeString(file, "answer=42\n");
            try (SecretManagerClient client = SecretManagerClient.create(Map.of(
                    "secrets.provider", "safe-configuration",
                    "secrets.property-resource-path", file.toString()));
                 SecretMemory memory = SecretMemory.create(Map.of());
                 Secret life = memory.fromChars("life".toCharArray())) {
                client.addVersion("question", life);
                try (Secret answer = client.read("answer"); Secret question = client.read("question")) {
                    check("safe-configuration guarded read", "42", answer.withChars(String::new));
                    check("safe-configuration write", "life", question.withChars(String::new));
                }
            }
        } finally {
            Files.deleteIfExists(file);
        }

        Path mount = Files.createTempDirectory("mounted");
        try {
            Files.writeString(mount.resolve("answer"), "42");
            try (SecretManagerClient client = SecretManagerClient.create(Map.of(
                    "secrets.provider", "mounted",
                    "secrets.mounted.directory", mount.toString()));
                 Secret answer = client.read("answer")) {
                check("mounted guarded read", "42", answer.withChars(String::new));
            }
        } finally {
            Files.deleteIfExists(mount.resolve("answer"));
            Files.deleteIfExists(mount);
        }

        // The Google provider must resolve and load, with no dependency but the API: a client that would take its
        // token from a metadata server on loopback is built; no request is sent.
        SecretManagerClient.create(Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", "smoke-test",
                "secrets.credentials", "metadata",
                "secrets.metadata-endpoint", "http://127.0.0.1:1",
                "secrets.endpoint", "http://127.0.0.1:1")).close();
        System.out.println("OK " + mode + " google-secret-manager client built");

        // A missing credentials file is reported as such, not as a class-loading or module error.
        try {
            SecretManagerClient.create(Map.of(
                    "secrets.provider", "google-secret-manager",
                    "secrets.project-id", "smoke-test",
                    "secrets.credentials-path", "/nonexistent/credentials.json")).close();
            fail("google-secret-manager: created a client without a credentials file");
        } catch (SecretManagerException e) {
            if (!e.getMessage().startsWith("Cannot read the Google credentials file")) {
                fail("google-secret-manager: " + e);
            }
            System.out.println("OK " + mode + " google-secret-manager missing credentials reported");
        }
    }

    private static void check(String what, String expected, String actual) {
        if (!expected.equals(actual)) {
            fail(what + ": the value read differs from the value written");
        }
        System.out.println("OK " + what);
    }

    private static void fail(String message) {
        System.err.println("FAIL " + message);
        System.exit(1);
    }
}
