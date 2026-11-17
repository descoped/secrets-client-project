package io.descoped.secrets.provider.google;

import com.google.auth.oauth2.GoogleCredentials;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerClientInitializer;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.service.provider.api.ProviderName;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The provider {@code google-secret-manager}: <a href="https://cloud.google.com/secret-manager">Google Secret
 * Manager</a> through its REST API.
 *
 * <table>
 *     <caption>Configuration</caption>
 *     <tr><th>Key</th><th>Value</th></tr>
 *     <tr><td>{@code secrets.provider}</td><td>{@code google-secret-manager}</td></tr>
 *     <tr><td>{@value #PROJECT_KEY}</td><td>the Google Cloud project id or number (required)</td></tr>
 *     <tr><td>{@value #KEY_PATH_KEY}</td><td>a service-account JSON key file; without it, Application Default
 *     Credentials are used (Workload Identity, the metadata server, {@code GOOGLE_APPLICATION_CREDENTIALS},
 *     {@code gcloud auth application-default login}). Do not use key files on a cluster.</td></tr>
 *     <tr><td>{@value #REPLICATION_KEY}</td><td>comma-separated locations, such as {@code europe-north1}, for secrets
 *     that {@code addVersion} creates (user-managed replication); automatic replication when absent</td></tr>
 *     <tr><td>{@value #ENDPOINT_KEY}</td><td>the API endpoint, default {@value #DEFAULT_ENDPOINT}; for example a
 *     regional endpoint</td></tr>
 *     <tr><td>{@value #CONNECT_TIMEOUT_KEY}</td><td>ISO-8601 duration, default {@code PT10S}</td></tr>
 *     <tr><td>{@value #REQUEST_TIMEOUT_KEY}</td><td>ISO-8601 duration, default {@code PT30S}</td></tr>
 * </table>
 *
 * <p>Versions are Secret Manager's: {@code latest} or a version number; {@code addVersion} returns the new number.
 * Secret names must match Secret Manager's rule: 1 to 255 letters, digits, {@code -} and {@code _}.
 */
@ProviderName("google-secret-manager")
public final class GoogleSecretManagerClientInitializer implements SecretManagerClientInitializer {

    /**
     * The configuration key for the project.
     */
    public static final String PROJECT_KEY = "secrets.project-id";

    /**
     * The configuration key for a service-account key file.
     */
    public static final String KEY_PATH_KEY = "secrets.service-account-key-path";

    /**
     * The configuration key for the replication locations of secrets created by {@code addVersion}.
     */
    public static final String REPLICATION_KEY = "secrets.replication-locations";

    /**
     * The configuration key for the API endpoint.
     */
    public static final String ENDPOINT_KEY = "secrets.endpoint";

    /**
     * The configuration key for the connect timeout.
     */
    public static final String CONNECT_TIMEOUT_KEY = "secrets.connect-timeout";

    /**
     * The configuration key for the request timeout.
     */
    public static final String REQUEST_TIMEOUT_KEY = "secrets.request-timeout";

    /**
     * The default API endpoint.
     */
    public static final String DEFAULT_ENDPOINT = "https://secretmanager.googleapis.com";

    private static final String SCOPE = "https://www.googleapis.com/auth/cloud-platform";
    private static final Pattern PROJECT = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");

    /**
     * Creates the initializer; called by {@link java.util.ServiceLoader}.
     */
    public GoogleSecretManagerClientInitializer() {
    }

    @Override
    public Set<String> configurationKeys() {
        return Set.of(PROJECT_KEY);
    }

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        String projectId = configuration.get(PROJECT_KEY);
        if (!PROJECT.matcher(projectId).matches()) {
            throw new IllegalArgumentException("Invalid '" + PROJECT_KEY + "': " + projectId);
        }
        URI endpoint = URI.create(configuration.getOrDefault(ENDPOINT_KEY, DEFAULT_ENDPOINT));
        List<String> locations = Arrays.stream(configuration.getOrDefault(REPLICATION_KEY, "").split(","))
                .map(String::strip)
                .filter(s -> !s.isEmpty())
                .toList();
        Duration connectTimeout = duration(configuration, CONNECT_TIMEOUT_KEY, Duration.ofSeconds(10));
        Duration requestTimeout = duration(configuration, REQUEST_TIMEOUT_KEY, Duration.ofSeconds(30));
        GoogleCredentials credentials = credentials(configuration.get(KEY_PATH_KEY)).createScoped(List.of(SCOPE));
        return new GoogleSecretManagerClient(endpoint, projectId, credentials, locations, connectTimeout,
                requestTimeout);
    }

    private static Duration duration(Map<String, String> configuration, String key, Duration defaultValue) {
        String value = configuration.get(key);
        if (value == null) {
            return defaultValue;
        }
        try {
            Duration duration = Duration.parse(value);
            if (duration.isNegative() || duration.isZero()) {
                throw new IllegalArgumentException("'" + key + "' must be positive: " + value);
            }
            return duration;
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("'" + key + "' is not an ISO-8601 duration such as PT30S: " + value, e);
        }
    }

    private static GoogleCredentials credentials(String keyPath) {
        try {
            if (keyPath == null) {
                return GoogleCredentials.getApplicationDefault();
            }
            try (InputStream in = Files.newInputStream(Path.of(keyPath))) {
                return GoogleCredentials.fromStream(in);
            }
        } catch (IOException e) {
            throw new SecretManagerException(keyPath == null
                    ? "No Google Application Default Credentials found"
                    : "Cannot read the service-account key " + keyPath, e);
        }
    }
}
