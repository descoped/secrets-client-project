package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerClientInitializer;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.http.Http;
import io.descoped.secrets.api.tls.TlsContext;
import io.descoped.service.provider.api.ProviderName;

import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

/**
 * The provider {@code aws-secrets-manager}: <a href="https://aws.amazon.com/secrets-manager/">AWS Secrets Manager</a>
 * through its JSON API, signed with Signature Version 4, with no dependency but the API module (no AWS SDK). Values,
 * the secret access key and the session token are kept in guarded memory ({@link SecretMemory}) from the network or
 * the file to the caller: requests are built and signed there (HMAC-SHA256 and SHA-256 through OpenSSL), and
 * responses read and parsed there. TLS goes through the system's OpenSSL 3, as for the Google provider. This needs
 * native access ({@code --enable-native-access=io.descoped.secrets.api}).
 *
 * <table>
 *     <caption>Configuration</caption>
 *     <tr><th>Key</th><th>Value</th></tr>
 *     <tr><td>{@code secrets.provider}</td><td>{@code aws-secrets-manager}</td></tr>
 *     <tr><td>{@value #REGION_KEY}</td><td>the region, such as {@code eu-north-1}; else {@code AWS_REGION}, else
 *     {@code AWS_DEFAULT_REGION} (required)</td></tr>
 *     <tr><td>{@value #CREDENTIALS_KEY}</td><td>{@code default} (the default): the chain below; {@code profile},
 *     {@code container}, {@code instance} or {@code environment}: that source only</td></tr>
 *     <tr><td>{@value #CREDENTIALS_PATH_KEY}</td><td>the shared credentials file; else the file
 *     {@code AWS_SHARED_CREDENTIALS_FILE} names, else {@code ~/.aws/credentials}</td></tr>
 *     <tr><td>{@value #PROFILE_KEY}</td><td>the profile in that file; else {@code AWS_PROFILE}, else
 *     {@code default}</td></tr>
 *     <tr><td>{@value #CONTAINER_URI_KEY}</td><td>the container credentials endpoint; else
 *     {@code AWS_CONTAINER_CREDENTIALS_FULL_URI}, else {@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI} on
 *     {@code 169.254.170.2}. http only to the ECS and EKS Pod Identity addresses or loopback, else https.</td></tr>
 *     <tr><td>{@value #CONTAINER_TOKEN_FILE_KEY}</td><td>the file of the container endpoint's authorization token;
 *     else {@code AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE}</td></tr>
 *     <tr><td>{@value #INSTANCE_METADATA_KEY}</td><td>EC2 instance metadata; else
 *     {@code AWS_EC2_METADATA_SERVICE_ENDPOINT}, else {@code http://169.254.169.254}</td></tr>
 *     <tr><td>{@value #ENDPOINT_KEY}</td><td>the API endpoint, default
 *     {@code https://secretsmanager.<region>.amazonaws.com} ({@code amazonaws.com.cn} in the China regions); another
 *     host serving the same API, such as a VPC or FIPS endpoint or a test server. It must use https; plain http only
 *     for a loopback address.</td></tr>
 *     <tr><td>{@value #KMS_KEY_ID_KEY}</td><td>the KMS key for secrets that {@code addVersion} creates: a key ID, an
 *     ARN or an alias; the account's {@code aws/secretsmanager} key when absent</td></tr>
 *     <tr><td>{@value #REPLICA_REGIONS_KEY}</td><td>comma-separated regions to replicate secrets that
 *     {@code addVersion} creates to</td></tr>
 *     <tr><td>{@value #CONNECT_TIMEOUT_KEY}</td><td>ISO-8601 duration, default {@code PT10S}</td></tr>
 *     <tr><td>{@value #REQUEST_TIMEOUT_KEY}</td><td>ISO-8601 duration, default {@code PT30S}</td></tr>
 *     <tr><td>{@value #CA_FILE_KEY}</td><td>a PEM file of the only certificates to trust, such as a private CA;
 *     the system's trusted certificates when absent</td></tr>
 *     <tr><td>{@value io.descoped.secrets.api.SecretMemory#GUARD_KEY},
 *     {@value io.descoped.secrets.api.SecretMemory#LOCK_KEY}</td><td>the guarded memory, see
 *     {@link SecretMemory}</td></tr>
 * </table>
 *
 * <p>Credentials, each kept in guarded memory and fetched again five minutes before temporary ones expire, come from
 * the source {@value #CREDENTIALS_KEY} names, or the first of this chain that applies:
 *
 * <ol>
 *     <li>{@code AWS_ACCESS_KEY_ID} set: the client refuses to start, since keys in the environment are on the Java
 *     heap; {@code environment} uses them anyway, outside the guarantee (for AWS Lambda);</li>
 *     <li>{@code AWS_WEB_IDENTITY_TOKEN_FILE} set: refused, web identity (EKS IRSA) is not supported yet;</li>
 *     <li>{@code profile}: the shared credentials file, when it is configured or {@code ~/.aws/credentials} exists.
 *     Static keys, or temporary ones, which are read from the file again every minute;</li>
 *     <li>{@code container}: the container credentials endpoint (ECS task role, EKS Pod Identity), when it is
 *     configured or the platform sets its variables;</li>
 *     <li>{@code instance}: EC2 instance metadata, IMDSv2 only, unless {@code AWS_EC2_METADATA_DISABLED} is
 *     {@code true}.</li>
 * </ol>
 *
 * <p>Versions: {@code latest} (or {@code null}) is the current version ({@code AWSCURRENT}); a version ID selects
 * that version, and any other string is a staging label, such as {@code AWSPREVIOUS}. {@code addVersion} returns the
 * new version ID. Names are 1 to 512 letters, digits and {@code /_+=.@-}, or a secret's ARN; reading a name or
 * version outside that rule is a {@link io.descoped.secrets.api.SecretNotFoundException} and sends no request.
 */
@ProviderName("aws-secrets-manager")
public final class AwsSecretsManagerClientInitializer implements SecretManagerClientInitializer {

    /** The configuration key for the region. */
    public static final String REGION_KEY = "secrets.region";

    /**
     * The configuration key for the credentials source: {@code default} (the chain), {@code profile},
     * {@code container}, {@code instance} or {@code environment}.
     */
    public static final String CREDENTIALS_KEY = "secrets.credentials";

    /** The configuration key for the shared credentials file. */
    public static final String CREDENTIALS_PATH_KEY = "secrets.credentials-path";

    /** The configuration key for the container credentials endpoint, instead of the platform's variables. */
    public static final String CONTAINER_URI_KEY = "secrets.container-credentials-uri";

    /** The configuration key for the container authorization token's file. */
    public static final String CONTAINER_TOKEN_FILE_KEY = "secrets.container-authorization-token-file";

    /** The configuration key for the EC2 instance metadata endpoint. */
    public static final String INSTANCE_METADATA_KEY = "secrets.instance-metadata-endpoint";

    /** The configuration key for the profile in the shared credentials file. */
    public static final String PROFILE_KEY = "secrets.aws-profile";

    /** The configuration key for the API endpoint. */
    public static final String ENDPOINT_KEY = "secrets.endpoint";

    /** The configuration key for the KMS key of created secrets. */
    public static final String KMS_KEY_ID_KEY = "secrets.kms-key-id";

    /** The configuration key for the replica regions of created secrets. */
    public static final String REPLICA_REGIONS_KEY = "secrets.replica-regions";

    /** The configuration key for the connect timeout. */
    public static final String CONNECT_TIMEOUT_KEY = "secrets.connect-timeout";

    /** The configuration key for the request timeout. */
    public static final String REQUEST_TIMEOUT_KEY = "secrets.request-timeout";

    /** The configuration key for a PEM file of the only certificates to trust, instead of the system's. */
    public static final String CA_FILE_KEY = "secrets.tls.ca-file";

    /** {@code eu-north-1}, {@code us-gov-west-1}, {@code ap-southeast-5}. */
    private static final Pattern REGION = Pattern.compile("[a-z]{2}(?:-[a-z]{1,12}){1,3}-\\d{1,2}");
    private static final Pattern KMS_KEY_ID = Pattern.compile("[A-Za-z0-9:/_-]{1,2048}");
    private static final Duration MAX_TIMEOUT = Duration.ofHours(1);

    /**
     * Creates the initializer; called by {@link java.util.ServiceLoader}.
     */
    public AwsSecretsManagerClientInitializer() {
        // No state: ServiceLoader needs a public no-argument constructor, the work is done in initialize.
    }

    @Override
    public Set<String> configurationKeys() {
        return Set.of();
    }

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        String region = region(configuration);
        // The China regions are a partition of their own, with their own domain.
        String domain = region.startsWith("cn-") ? "amazonaws.com.cn" : "amazonaws.com";
        URI endpoint = httpsOrLoopback(ENDPOINT_KEY, configuration.getOrDefault(ENDPOINT_KEY,
                "https://secretsmanager." + region + "." + domain));
        String kmsKeyId = configuration.get(KMS_KEY_ID_KEY);
        if (kmsKeyId != null && !KMS_KEY_ID.matcher(kmsKeyId).matches()) {
            throw new IllegalArgumentException("Invalid '" + KMS_KEY_ID_KEY + "': " + kmsKeyId);
        }
        List<String> replicas = replicaRegions(configuration);
        Http.Timeouts timeouts = new Http.Timeouts(
                duration(configuration, CONNECT_TIMEOUT_KEY, Duration.ofSeconds(10)),
                duration(configuration, REQUEST_TIMEOUT_KEY, Duration.ofSeconds(30)));
        UnaryOperator<String> environment = System::getenv;
        CredentialSources.Choice choice = CredentialSources.choose(configuration, environment);
        boolean secure = "https".equalsIgnoreCase(endpoint.getScheme()) || choice.needsTls();
        TlsContext tls = secure ? tlsContext(configuration) : null;
        try {
            SecretMemory memory = SecretMemory.create(configuration);
            Clock clock = Clock.systemUTC();
            CredentialsProvider credentials = new CredentialsProvider(
                    choice.source(memory, tls, timeouts, clock, environment), clock);
            AwsSecretsManagerClient.Settings settings = new AwsSecretsManagerClient.Settings(
                    Http.Target.of(endpoint, tls), timeouts, kmsKeyId, replicas);
            return new AwsSecretsManagerClient(settings, new SigV4(memory, region, "secretsmanager"), memory,
                    credentials, tls, clock);
        } catch (RuntimeException e) {
            if (tls != null) {
                tls.close();
            }
            throw e;
        }
    }

    private static TlsContext tlsContext(Map<String, String> configuration) {
        String caFile = configuration.get(CA_FILE_KEY);
        Path path = caFile == null ? null : Path.of(caFile);
        return TlsContext.create(path);
    }

    private static String region(Map<String, String> configuration) {
        String region = CredentialSources.firstOf(configuration.get(REGION_KEY), System.getenv("AWS_REGION"),
                System.getenv("AWS_DEFAULT_REGION"));
        if (region == null) {
            throw new IllegalArgumentException("No AWS region: set '" + REGION_KEY + "' or AWS_REGION");
        }
        if (!REGION.matcher(region).matches()) {
            throw new IllegalArgumentException("Invalid AWS region: " + region);
        }
        return region;
    }

    private static List<String> replicaRegions(Map<String, String> configuration) {
        List<String> regions = Arrays.stream(configuration.getOrDefault(REPLICA_REGIONS_KEY, "").split(","))
                .map(String::strip)
                .filter(s -> !s.isEmpty())
                .toList();
        for (String region : regions) {
            if (!REGION.matcher(region).matches()) {
                throw new IllegalArgumentException("Invalid region in '" + REPLICA_REGIONS_KEY + "': " + region);
            }
        }
        return regions;
    }

    private static URI httpsOrLoopback(String key, String value) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("'" + key + "' is not a URI: " + value, e);
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("'" + key + "' has no host: " + value);
        }
        if ("https".equalsIgnoreCase(uri.getScheme())
                || "http".equalsIgnoreCase(uri.getScheme()) && CredentialSources.isLoopback(uri.getHost())) {
            return uri;
        }
        throw new IllegalArgumentException("'" + key + "' must use https (http only for a loopback address): "
                + value);
    }

    private static Duration duration(Map<String, String> configuration, String key, Duration defaultValue) {
        String value = configuration.get(key);
        if (value == null) {
            return defaultValue;
        }
        try {
            Duration duration = Duration.parse(value);
            if (duration.isNegative() || duration.isZero() || duration.compareTo(MAX_TIMEOUT) > 0) {
                throw new IllegalArgumentException("'" + key + "' must be positive and at most PT1H: " + value);
            }
            return duration;
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("'" + key + "' is not an ISO-8601 duration such as PT30S: " + value, e);
        }
    }
}
