package io.descoped.secrets.provider.google.test;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretNotFoundException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Against the real Google Secret Manager, only when {@code SECRETS_GOOGLE_TEST_PROJECT} names a project; not run in CI.
 * Credentials are the authorized_user file in {@code SECRETS_GOOGLE_TEST_CREDENTIALS_PATH}, or else Application
 * Default Credentials as the provider finds them; {@code SECRETS_GOOGLE_TEST_CREDENTIALS=metadata} uses only the
 * metadata server (on Google Cloud, such as a Cloud Run job). It adds versions to the secret
 * {@code secrets-client-live-test}, creating it with automatic replication if needed, and afterwards destroys all
 * enabled versions but the newest {@value #KEEP} (active versions are billed). Not run when
 * {@code SECRETS_MOUNTED_TEST_DIRECTORY} is set, so that it never runs beside {@link MountedSecretLiveTest}.
 */
@EnabledIfEnvironmentVariable(named = "SECRETS_GOOGLE_TEST_PROJECT", matches = ".+")
// It adds versions, which would change what MountedSecretLiveTest compares the mounted file with.
@DisabledIfEnvironmentVariable(named = "SECRETS_MOUNTED_TEST_DIRECTORY", matches = ".+")
class GoogleSecretManagerLiveTest {

    static final String SECRET = "secrets-client-live-test";
    private static final int KEEP = 2;

    /** The configuration of a client of the live project, with the credentials the environment names. */
    static Map<String, String> configuration() {
        Map<String, String> configuration = new HashMap<>(Map.of(
                "secrets.provider", "google-secret-manager",
                "secrets.project-id", System.getenv("SECRETS_GOOGLE_TEST_PROJECT")));
        String credentialsPath = System.getenv("SECRETS_GOOGLE_TEST_CREDENTIALS_PATH");
        if (credentialsPath != null) {
            configuration.put("secrets.credentials-path", credentialsPath);
        }
        String credentials = System.getenv("SECRETS_GOOGLE_TEST_CREDENTIALS");
        if (credentials != null && !credentials.isEmpty()) {
            configuration.put("secrets.credentials", credentials);
        }
        return configuration;
    }

    @Test
    void addThenReadVersions() {
        String first = UUID.randomUUID().toString();
        // Near Secret Manager's 64 KiB limit: 80 KiB as Base64 in JSON, so Google's response is large.
        byte[] large = new byte[60 * 1024];
        new SecureRandom().nextBytes(large);
        try (SecretManagerClient client = SecretManagerClient.create(configuration())) {
            String v1 = Values.add(client, SECRET, first);
            String v2 = Values.add(client, SECRET, large);
            assertArrayEquals(large, Values.bytes(client, SECRET));
            assertEquals(first, Values.text(client, SECRET, v1));
            assertArrayEquals(large, Values.bytes(client, SECRET, v2));
            try (Secret secret = client.read(SECRET, v1)) {
                secret.withBytes(bytes -> {
                    assertArrayEquals(first.getBytes(StandardCharsets.UTF_8), bytes);
                    return null;
                });
            }
            String absent = "secrets-client-live-absent-" + UUID.randomUUID();
            assertThrows(SecretNotFoundException.class, () -> Values.bytes(client, absent));
        }
    }

    /**
     * Destroys all enabled versions but the newest {@value #KEEP}. Test code, on the heap, with the JDK's HTTP client:
     * the provider has no destroy, and this is cleanup, not a path under test.
     */
    @AfterAll
    static void destroyOldVersions() throws IOException, InterruptedException {
        String token = accessToken();
        String versions = "https://secretmanager.googleapis.com/v1/projects/"
                + System.getenv("SECRETS_GOOGLE_TEST_PROJECT") + "/secrets/" + SECRET + "/versions";
        try (HttpClient http = HttpClient.newHttpClient()) {
            List<Long> enabled = new ArrayList<>();
            String page = "";
            do {
                HttpResponse<String> list = http.send(HttpRequest.newBuilder(URI.create(
                                versions + "?filter=state:ENABLED&pageSize=100" + page))
                        .header("Authorization", "Bearer " + token).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (list.statusCode() != 200) {
                    throw new IOException("Cannot list the versions of " + SECRET + ": HTTP " + list.statusCode());
                }
                Matcher name = Pattern.compile("\"name\":\\s*\"[^\"]*/versions/(\\d+)\"").matcher(list.body());
                while (name.find()) {
                    enabled.add(Long.parseLong(name.group(1)));
                }
                Matcher next = Pattern.compile("\"nextPageToken\":\\s*\"([^\"]+)\"").matcher(list.body());
                page = next.find() ? "&pageToken=" + encode(next.group(1)) : "";
            } while (!page.isEmpty());
            enabled.sort(Comparator.reverseOrder());
            for (long version : enabled.subList(Math.min(KEEP, enabled.size()), enabled.size())) {
                HttpResponse<String> destroyed = http.send(HttpRequest.newBuilder(URI.create(
                                versions + "/" + version + ":destroy"))
                        .header("Authorization", "Bearer " + token).header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{}")).build(),
                        HttpResponse.BodyHandlers.ofString());
                if (destroyed.statusCode() != 200) {
                    throw new IOException("Cannot destroy version " + version + ": HTTP " + destroyed.statusCode());
                }
            }
        }
    }

    /** An access token from the same authorized_user file the provider uses, or from the metadata server. */
    private static String accessToken() throws IOException, InterruptedException {
        Path file = credentialsFile();
        try (HttpClient http = HttpClient.newHttpClient()) {
            HttpRequest request;
            if (file == null) {
                request = HttpRequest.newBuilder(URI.create("http://metadata.google.internal/computeMetadata/v1/"
                        + "instance/service-accounts/default/token")).header("Metadata-Flavor", "Google").build();
            } else {
                String json = Files.readString(file);
                String form = "grant_type=refresh_token"
                        + "&client_id=" + encode(field(json, "client_id"))
                        + "&client_secret=" + encode(field(json, "client_secret"))
                        + "&refresh_token=" + encode(field(json, "refresh_token"));
                request = HttpRequest.newBuilder(URI.create("https://oauth2.googleapis.com/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form)).build();
            }
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("Cannot get an access token for the cleanup: HTTP " + response.statusCode());
            }
            return field(response.body(), "access_token");
        }
    }

    private static Path credentialsFile() {
        if ("metadata".equals(System.getenv("SECRETS_GOOGLE_TEST_CREDENTIALS"))) {
            return null;
        }
        for (String variable : List.of("SECRETS_GOOGLE_TEST_CREDENTIALS_PATH", "GOOGLE_APPLICATION_CREDENTIALS")) {
            String value = System.getenv(variable);
            if (value != null && !value.isEmpty()) {
                return Path.of(value);
            }
        }
        String config = System.getenv("CLOUDSDK_CONFIG");
        Path directory = config != null && !config.isEmpty()
                ? Path.of(config)
                : Path.of(System.getProperty("user.home"), ".config", "gcloud");
        Path file = directory.resolve("application_default_credentials.json");
        return Files.isRegularFile(file) ? file : null;
    }

    private static String field(String json, String name) throws IOException {
        Matcher matcher = Pattern.compile("\"" + name + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        if (!matcher.find()) {
            throw new IOException("No " + name + " in the response");
        }
        return matcher.group(1);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
