package io.descoped.secrets.provider.google;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerClientInitializer;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.service.provider.api.ProviderName;

import java.io.IOException;
import java.net.InetAddress;
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
 * Manager</a> through its REST API, with no dependency but the API module. Values, the access token and the refresh
 * token are kept in guarded memory ({@link io.descoped.secrets.api.SecretMemory}) from the network or the file to the
 * caller: the provider's own HTTP client builds each request there and reads each response there. This needs native
 * access ({@code --enable-native-access=io.descoped.secrets.api}).
 *
 * <table>
 *     <caption>Configuration</caption>
 *     <tr><th>Key</th><th>Value</th></tr>
 *     <tr><td>{@code secrets.provider}</td><td>{@code google-secret-manager}</td></tr>
 *     <tr><td>{@value #PROJECT_KEY}</td><td>the Google Cloud project id or number (required)</td></tr>
 *     <tr><td>{@value #CREDENTIALS_KEY}</td><td>{@code application-default} (the default): the file in
 *     {@value #CREDENTIALS_PATH_KEY}, else the file {@code GOOGLE_APPLICATION_CREDENTIALS} names, else the file
 *     {@code gcloud auth application-default login} writes, else the metadata server. {@code metadata}: the
 *     metadata server only (Workload Identity on GKE, the attached service account on Cloud Run and Compute
 *     Engine).</td></tr>
 *     <tr><td>{@value #CREDENTIALS_PATH_KEY}</td><td>an {@code authorized_user} credentials file, as
 *     {@code gcloud auth application-default login} writes it. Service-account keys and other credential types are
 *     refused: signing with a private key would put it on the Java heap.</td></tr>
 *     <tr><td>{@value #REPLICATION_KEY}</td><td>comma-separated locations, such as {@code europe-north1}, for secrets
 *     that {@code addVersion} creates (user-managed replication); automatic replication when absent</td></tr>
 *     <tr><td>{@value #ENDPOINT_KEY}</td><td>the API endpoint, default {@value #DEFAULT_ENDPOINT}; another host
 *     serving the same global API, such as a Private Service Connect endpoint or a test server. Regional secrets
 *     ({@code locations/*}) are not supported. It must use https; plain http only for a loopback address.</td></tr>
 *     <tr><td>{@value #TOKEN_ENDPOINT_KEY}</td><td>the OAuth token endpoint for {@code authorized_user}
 *     credentials, default {@value #DEFAULT_TOKEN_ENDPOINT}; https, plain http only for a loopback address</td></tr>
 *     <tr><td>{@value #METADATA_ENDPOINT_KEY}</td><td>the metadata server, default
 *     {@value #DEFAULT_METADATA_ENDPOINT}; {@code metadata.google.internal}, {@code 169.254.169.254} or a loopback
 *     address</td></tr>
 *     <tr><td>{@value #CONNECT_TIMEOUT_KEY}</td><td>ISO-8601 duration, default {@code PT10S}</td></tr>
 *     <tr><td>{@value #REQUEST_TIMEOUT_KEY}</td><td>ISO-8601 duration, default {@code PT30S}</td></tr>
 *     <tr><td>{@value io.descoped.secrets.api.SecretMemory#GUARD_KEY},
 *     {@value io.descoped.secrets.api.SecretMemory#LOCK_KEY}</td><td>the guarded memory, see
 *     {@link io.descoped.secrets.api.SecretMemory}</td></tr>
 * </table>
 *
 * <p>The access token is fetched on first use and replaced when it has less than three minutes left. TLS is the
 * JDK's ({@code SSLEngine}, TLS 1.3 or 1.2, the default trust store, host name verification).
 *
 * <p>Versions are Secret Manager's: {@code latest} or a version number; {@code addVersion} returns the new number.
 * Secret names follow Secret Manager's rule: 1 to 255 letters, digits, {@code -} and {@code _}. Reading a name or
 * version outside that rule is a {@link io.descoped.secrets.api.SecretNotFoundException}, and {@code addVersion} with
 * such a name a {@link SecretManagerException}; neither sends a request. A disabled or destroyed version exists, so
 * reading it is a {@link SecretManagerException} ({@code FAILED_PRECONDITION}), not "not found".
 */
@ProviderName("google-secret-manager")
public final class GoogleSecretManagerClientInitializer implements SecretManagerClientInitializer {

    /** The configuration key for the project. */
    public static final String PROJECT_KEY = "secrets.project-id";

    /** The configuration key for where credentials come from: {@code application-default} or {@code metadata}. */
    public static final String CREDENTIALS_KEY = "secrets.credentials";

    /** The configuration key for an {@code authorized_user} credentials file. */
    public static final String CREDENTIALS_PATH_KEY = "secrets.credentials-path";

    /** The configuration key for the replication locations of secrets created by {@code addVersion}. */
    public static final String REPLICATION_KEY = "secrets.replication-locations";

    /** The configuration key for the API endpoint. */
    public static final String ENDPOINT_KEY = "secrets.endpoint";

    /** The configuration key for the OAuth token endpoint. */
    public static final String TOKEN_ENDPOINT_KEY = "secrets.token-endpoint";

    /** The configuration key for the metadata server. */
    public static final String METADATA_ENDPOINT_KEY = "secrets.metadata-endpoint";

    /** The configuration key for the connect timeout. */
    public static final String CONNECT_TIMEOUT_KEY = "secrets.connect-timeout";

    /** The configuration key for the request timeout. */
    public static final String REQUEST_TIMEOUT_KEY = "secrets.request-timeout";

    /** The default API endpoint. */
    public static final String DEFAULT_ENDPOINT = "https://secretmanager.googleapis.com";

    /** The default OAuth token endpoint. */
    public static final String DEFAULT_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

    /** The default metadata server. */
    public static final String DEFAULT_METADATA_ENDPOINT = "http://metadata.google.internal";

    /** The key of 3.x, which named a service-account key; refused with a message. */
    private static final String REMOVED_KEY_PATH_KEY = "secrets.service-account-key-path";
    private static final Pattern PROJECT = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");
    private static final Pattern LOCATION = Pattern.compile("[a-z0-9-]{1,63}");

    /**
     * Creates the initializer; called by {@link java.util.ServiceLoader}.
     */
    public GoogleSecretManagerClientInitializer() {
        // No state: ServiceLoader needs a public no-argument constructor, the work is done in initialize.
    }

    @Override
    public Set<String> configurationKeys() {
        return Set.of(PROJECT_KEY);
    }

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        if (configuration.containsKey(REMOVED_KEY_PATH_KEY)) {
            throw new IllegalArgumentException("'" + REMOVED_KEY_PATH_KEY + "' is no longer supported: service-account"
                    + " keys are refused, since signing with them would put the key on the Java heap. Use the"
                    + " metadata server on Google Cloud, or '" + CREDENTIALS_PATH_KEY + "' with"
                    + " gcloud auth application-default login credentials for development");
        }
        String projectId = configuration.get(PROJECT_KEY);
        if (!PROJECT.matcher(projectId).matches()) {
            throw new IllegalArgumentException("Invalid '" + PROJECT_KEY + "': " + projectId);
        }
        URI endpoint = httpsOrLoopback(ENDPOINT_KEY, configuration.getOrDefault(ENDPOINT_KEY, DEFAULT_ENDPOINT));
        URI tokenEndpoint = httpsOrLoopback(TOKEN_ENDPOINT_KEY,
                configuration.getOrDefault(TOKEN_ENDPOINT_KEY, DEFAULT_TOKEN_ENDPOINT));
        URI metadataEndpoint = metadata(configuration.getOrDefault(METADATA_ENDPOINT_KEY,
                DEFAULT_METADATA_ENDPOINT));
        List<String> locations = Arrays.stream(configuration.getOrDefault(REPLICATION_KEY, "").split(","))
                .map(String::strip)
                .filter(s -> !s.isEmpty())
                .toList();
        for (String location : locations) {
            if (!LOCATION.matcher(location).matches()) {
                throw new IllegalArgumentException("Invalid location in '" + REPLICATION_KEY + "': " + location);
            }
        }
        String mode = configuration.getOrDefault(CREDENTIALS_KEY, "application-default");
        if (!mode.equals("application-default") && !mode.equals("metadata")) {
            throw new IllegalArgumentException("Invalid '" + CREDENTIALS_KEY + "': " + mode
                    + " (application-default or metadata)");
        }
        String credentialsPath = configuration.get(CREDENTIALS_PATH_KEY);
        if (mode.equals("metadata") && credentialsPath != null) {
            throw new IllegalArgumentException("'" + CREDENTIALS_PATH_KEY + "' and " + CREDENTIALS_KEY
                    + "=metadata exclude each other");
        }
        Http.Timeouts timeouts = new Http.Timeouts(
                duration(configuration, CONNECT_TIMEOUT_KEY, Duration.ofSeconds(10)),
                duration(configuration, REQUEST_TIMEOUT_KEY, Duration.ofSeconds(30)));
        SecretMemory memory = SecretMemory.create(configuration);
        try {
            Path file = mode.equals("metadata") ? null : credentialsFile(credentialsPath);
            AccessTokens.Source source = file == null
                    ? new AccessTokens.MetadataServer(Http.Target.of(metadataEndpoint), timeouts, memory)
                    : AccessTokens.AuthorizedUser.load(file, Http.Target.of(tokenEndpoint), timeouts, memory);
            return new GoogleSecretManagerClient(Http.Target.of(endpoint), projectId, locations, timeouts, memory,
                    new AccessTokens(source));
        } catch (RuntimeException e) {
            memory.close();
            throw e;
        }
    }

    /**
     * The credentials file, as Application Default Credentials look it up: the configured one,
     * {@code GOOGLE_APPLICATION_CREDENTIALS}, or gcloud's, if it exists; {@code null} for the metadata server.
     */
    private static Path credentialsFile(String configured) {
        if (configured != null) {
            return Path.of(configured);
        }
        String variable = System.getenv("GOOGLE_APPLICATION_CREDENTIALS");
        if (variable != null && !variable.isEmpty()) {
            return Path.of(variable);
        }
        String config = System.getenv("CLOUDSDK_CONFIG");
        Path gcloud = config != null && !config.isEmpty() ? Path.of(config)
                : Path.of(System.getProperty("user.home"), ".config", "gcloud");
        Path file = gcloud.resolve("application_default_credentials.json");
        return Files.isRegularFile(file) ? file : null;
    }

    /**
     * An https URI, or http for a loopback address only (a local emulator or test server), so that tokens and values
     * are never sent in clear text over a network.
     */
    private static URI httpsOrLoopback(String key, String value) {
        URI uri = uri(key, value);
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            return uri;
        }
        if ("http".equalsIgnoreCase(uri.getScheme()) && isLoopback(uri.getHost())) {
            return uri;
        }
        throw new IllegalArgumentException("'" + key + "' must use https (http only for a loopback address): "
                + value);
    }

    /** The metadata server is plain http on a link-local address; a loopback address is a test server. */
    private static URI metadata(String value) {
        URI uri = uri(METADATA_ENDPOINT_KEY, value);
        String host = uri.getHost();
        if ("http".equalsIgnoreCase(uri.getScheme()) && (host.equalsIgnoreCase("metadata.google.internal")
                || host.equals("169.254.169.254") || isLoopback(host))) {
            return uri;
        }
        throw new IllegalArgumentException("'" + METADATA_ENDPOINT_KEY + "' must be http on metadata.google.internal,"
                + " 169.254.169.254 or a loopback address: " + value);
    }

    private static URI uri(String key, String value) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("'" + key + "' is not a URI: " + value, e);
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("'" + key + "' has no host: " + value);
        }
        return uri;
    }

    private static boolean isLoopback(String host) {
        if ("localhost".equalsIgnoreCase(host)) {
            return true;
        }
        String literal = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        // Only IP literals: a name is never looked up here.
        if (!literal.matches("[0-9.]+|[0-9a-fA-F:]+")) {
            return false;
        }
        try {
            return InetAddress.getByName(literal).isLoopbackAddress();
        } catch (IOException _) {
            return false;
        }
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
}
