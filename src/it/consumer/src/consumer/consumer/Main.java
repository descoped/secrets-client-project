package consumer;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
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

        // The Google provider and its automatic modules (google-auth and its dependencies) must resolve and load: a
        // real client is built from a generated service-account key, which google-auth parses. No request is sent.
        Path key = Files.createTempFile("service-account", ".json");
        try {
            Files.writeString(key, serviceAccountKey());
            SecretManagerClient.create(Map.of(
                    "secrets.provider", "google-secret-manager",
                    "secrets.project-id", "smoke-test",
                    "secrets.service-account-key-path", key.toString(),
                    "secrets.endpoint", "http://127.0.0.1:1")).close();
            System.out.println("OK " + mode + " google-secret-manager client built");
        } catch (SecretManagerException e) {
            fail("google-secret-manager: " + e);
        } finally {
            Files.deleteIfExists(key);
        }

        // A missing key file is reported as such, not as a class-loading or module error.
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
            System.out.println("OK " + mode + " google-secret-manager missing key reported");
        }
    }

    private static String serviceAccountKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            String pem = "-----BEGIN PRIVATE KEY-----\\n"
                    + Base64.getMimeEncoder(64, new byte[]{'\n'})
                    .encodeToString(generator.generateKeyPair().getPrivate().getEncoded()).replace("\n", "\\n")
                    + "\\n-----END PRIVATE KEY-----\\n";
            return "{\"type\":\"service_account\",\"project_id\":\"smoke-test\",\"private_key_id\":\"k\","
                    + "\"private_key\":\"" + pem + "\",\"client_email\":\"smoke@smoke-test.iam.gserviceaccount.com\","
                    + "\"client_id\":\"1\",\"token_uri\":\"http://127.0.0.1:1/token\"}";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
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
