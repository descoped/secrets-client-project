package consumer;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;

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
                    "secrets.property-resource-path", file.toString()))) {
                client.addVersion("question", "life");
                check("safe-configuration", "42", client.readString("answer"));
                check("safe-configuration write", "life", client.readString("question"));
            }
        } finally {
            Files.deleteIfExists(file);
        }

        try (SecretManagerClient client = SecretManagerClient.create(Map.of(
                "secrets.provider", "dynamic-configuration",
                "secrets.values.answer", "42"))) {
            check("dynamic-configuration", "42", client.readString("answer"));
        }

        // The Google provider and its automatic modules (google-auth and its dependencies) must resolve and load:
        // initializing it with a key file that does not exist gets as far as reading that file.
        try {
            SecretManagerClient.create(Map.of(
                    "secrets.provider", "google-secret-manager",
                    "secrets.project-id", "smoke-test",
                    "secrets.service-account-key-path", "/nonexistent/key.json")).close();
            fail("google-secret-manager: created a client without a key file");
        } catch (SecretManagerException e) {
            if (!e.getMessage().startsWith("Cannot read the service-account key")) {
                fail("google-secret-manager: " + e);
            }
            System.out.println("OK " + mode + " google-secret-manager loaded");
        }
    }

    private static void check(String what, String expected, String actual) {
        if (!expected.equals(actual)) {
            fail(what + ": expected " + expected + ", got " + actual);
        }
        System.out.println("OK " + what);
    }

    private static void fail(String message) {
        System.err.println("FAIL " + message);
        System.exit(1);
    }
}
