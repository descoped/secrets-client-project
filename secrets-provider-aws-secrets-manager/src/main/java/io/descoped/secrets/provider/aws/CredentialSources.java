package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.http.Http;
import io.descoped.secrets.api.tls.TlsContext;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

import static io.descoped.secrets.provider.aws.AwsSecretsManagerClientInitializer.CONTAINER_TOKEN_FILE_KEY;
import static io.descoped.secrets.provider.aws.AwsSecretsManagerClientInitializer.CONTAINER_URI_KEY;
import static io.descoped.secrets.provider.aws.AwsSecretsManagerClientInitializer.CREDENTIALS_KEY;
import static io.descoped.secrets.provider.aws.AwsSecretsManagerClientInitializer.CREDENTIALS_PATH_KEY;
import static io.descoped.secrets.provider.aws.AwsSecretsManagerClientInitializer.INSTANCE_METADATA_KEY;
import static io.descoped.secrets.provider.aws.AwsSecretsManagerClientInitializer.PROFILE_KEY;

/**
 * Which source a client takes its credentials from: the one {@code secrets.credentials} names, or else the first of
 * the chain that applies, in the order of the AWS SDKs where that keeps the guarantee:
 *
 * <ol>
 *     <li>the shared credentials file, when the configuration names a file or profile;</li>
 *     <li>{@code AWS_ACCESS_KEY_ID} set: refused, unless {@code secrets.credentials=environment} (the environment is
 *     on the heap); never skipped silently, since the application meant those keys;</li>
 *     <li>{@code AWS_WEB_IDENTITY_TOKEN_FILE} set: refused, web identity is not supported yet;</li>
 *     <li>the shared credentials file, when it exists ({@code AWS_SHARED_CREDENTIALS_FILE}, else
 *     {@code ~/.aws/credentials});</li>
 *     <li>the container credentials endpoint, when it is configured or the platform sets its variables (ECS, EKS Pod
 *     Identity);</li>
 *     <li>EC2 instance metadata (IMDSv2), unless {@code AWS_EC2_METADATA_DISABLED} is {@code true}.</li>
 * </ol>
 */
final class CredentialSources {

    /** The ECS task role endpoint's host, for {@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}. */
    @SuppressWarnings("java:S1313")
    static final String ECS_HOST = "169.254.170.2";
    @SuppressWarnings("java:S1313")
    private static final Set<String> CONTAINER_HOSTS = Set.of(ECS_HOST, "169.254.170.23", "fd00:ec2::23");
    @SuppressWarnings("java:S1313")
    private static final Set<String> INSTANCE_HOSTS = Set.of("169.254.169.254", "fd00:ec2::254");
    @SuppressWarnings("java:S1313")
    private static final String INSTANCE_ENDPOINT = "http://169.254.169.254";

    private static final String DEFAULT = "default";

    /** A source. */
    enum Kind {
        PROFILE, CONTAINER, INSTANCE, ENVIRONMENT
    }

    /**
     * The chosen source and where it is.
     *
     * @param kind      the source
     * @param file      the shared credentials file ({@code PROFILE})
     * @param profile   the profile in it ({@code PROFILE})
     * @param uri       the endpoint ({@code CONTAINER}, {@code INSTANCE})
     * @param tokenFile the container authorization token's file, or {@code null}
     */
    record Choice(Kind kind, Path file, String profile, URI uri, Path tokenFile) {

        /** Whether the source is reached over https. */
        boolean needsTls() {
            return uri != null && "https".equalsIgnoreCase(uri.getScheme());
        }

        CredentialsProvider.Source source(SecretMemory memory, TlsContext tls, Http.Timeouts timeouts, Clock clock,
                                          UnaryOperator<String> environment) {
            return switch (kind) {
                case PROFILE -> new SharedCredentialsFile(memory, file, profile, clock);
                case CONTAINER -> new ContainerCredentials(memory, Http.Target.of(uri, tls), tokenFile, timeouts);
                case INSTANCE -> new InstanceMetadataCredentials(memory, Http.Target.of(uri, tls), timeouts);
                case ENVIRONMENT -> new EnvironmentCredentials(memory, environment);
            };
        }
    }

    private CredentialSources() {
    }

    static Choice choose(Map<String, String> configuration, UnaryOperator<String> environment) {
        String pinned = configuration.getOrDefault(CREDENTIALS_KEY, DEFAULT);
        return switch (pinned) {
            case "profile" -> profile(configuration, environment);
            case "container" -> container(configuration, environment, true);
            case "instance" -> instance(configuration, environment);
            case "environment" -> new Choice(Kind.ENVIRONMENT, null, null, null, null);
            case DEFAULT -> chain(configuration, environment);
            default -> throw new IllegalArgumentException("Invalid '" + CREDENTIALS_KEY + "': " + pinned
                    + " (default, profile, container, instance or environment)");
        };
    }

    /**
     * The chain. A file or profile in the configuration chooses the profile, as an explicit profile provider does in
     * the AWS SDKs, whatever the environment holds; one in the environment only if the file exists, so that a stray
     * {@code AWS_PROFILE} in an image does not hide the platform's credentials.
     */
    private static Choice chain(Map<String, String> configuration, UnaryOperator<String> environment) {
        if (isSet(configuration.get(CREDENTIALS_PATH_KEY)) || isSet(configuration.get(PROFILE_KEY))) {
            return profile(configuration, environment);
        }
        if (isSet(environment.apply(EnvironmentCredentials.ACCESS_KEY_ID))) {
            throw new IllegalArgumentException(EnvironmentCredentials.ACCESS_KEY_ID + " is set, but keys in the"
                    + " environment are on the Java heap: set '" + CREDENTIALS_KEY + "=environment' to use them anyway,"
                    + " or unset it to use the next source");
        }
        if (isSet(environment.apply("AWS_WEB_IDENTITY_TOKEN_FILE"))) {
            throw new IllegalArgumentException("AWS_WEB_IDENTITY_TOKEN_FILE is set, but web identity credentials (EKS"
                    + " IRSA) are not supported yet: use EKS Pod Identity, or set '" + CREDENTIALS_KEY + "'");
        }
        Choice profile = profile(configuration, environment);
        if (Files.exists(profile.file())) {
            return profile;
        }
        Choice container = container(configuration, environment, false);
        if (container != null) {
            return container;
        }
        if ("true".equalsIgnoreCase(environment.apply("AWS_EC2_METADATA_DISABLED"))) {
            throw new IllegalArgumentException("No AWS credentials: no credentials file, no container credentials"
                    + " endpoint, and AWS_EC2_METADATA_DISABLED is true");
        }
        return instance(configuration, environment);
    }

    private static Choice profile(Map<String, String> configuration, UnaryOperator<String> environment) {
        String configured = firstOf(configuration.get(CREDENTIALS_PATH_KEY),
                environment.apply("AWS_SHARED_CREDENTIALS_FILE"));
        Path file = configured != null ? Path.of(configured) : defaultCredentialsFile(environment);
        String profile = firstOf(configuration.get(PROFILE_KEY), environment.apply("AWS_PROFILE"), DEFAULT);
        return new Choice(Kind.PROFILE, file, profile, null, null);
    }

    /** The container endpoint, or {@code null} if none is set and it is not {@code required}. */
    private static Choice container(Map<String, String> configuration, UnaryOperator<String> environment,
                                    boolean required) {
        String full = firstOf(configuration.get(CONTAINER_URI_KEY),
                environment.apply("AWS_CONTAINER_CREDENTIALS_FULL_URI"));
        String value = full;
        String relative = environment.apply("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
        if (value == null && isSet(relative)) {
            value = "http://" + ECS_HOST + relative;
        }
        if (value == null) {
            if (required) {
                throw new IllegalArgumentException("No container credentials endpoint: set '" + CONTAINER_URI_KEY
                        + "', or AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or _FULL_URI");
            }
            return null;
        }
        URI uri = endpoint("the container credentials endpoint", value, CONTAINER_HOSTS, true);
        String token = firstOf(configuration.get(CONTAINER_TOKEN_FILE_KEY),
                environment.apply("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"));
        if (token == null && isSet(environment.apply("AWS_CONTAINER_AUTHORIZATION_TOKEN"))) {
            throw new IllegalArgumentException("AWS_CONTAINER_AUTHORIZATION_TOKEN is set, but a token in the"
                    + " environment is on the Java heap: give it in a file, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
        }
        return new Choice(Kind.CONTAINER, null, null, uri, token == null ? null : Path.of(token));
    }

    private static Choice instance(Map<String, String> configuration, UnaryOperator<String> environment) {
        String value = firstOf(configuration.get(INSTANCE_METADATA_KEY),
                environment.apply("AWS_EC2_METADATA_SERVICE_ENDPOINT"), INSTANCE_ENDPOINT);
        return new Choice(Kind.INSTANCE, null, null, endpoint("EC2 instance metadata", value, INSTANCE_HOSTS, false),
                null);
    }

    /**
     * An endpoint that must be one of {@code hosts} or a loopback address over http, or, if {@code httpsAllowed},
     * any host over https; it must have a path when https is allowed (the container endpoint).
     */
    private static URI endpoint(String what, String value, Set<String> hosts, boolean httpsAllowed) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The URI of " + what + " is not valid: " + value, e);
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost() == null ? "" : unbracketed(uri.getHost());
        boolean allowed = scheme.equals("http") && (hosts.contains(host) || isLoopback(host))
                || httpsAllowed && scheme.equals("https") && !host.isEmpty();
        if (!allowed) {
            throw new IllegalArgumentException("The URI of " + what + " must be http to " + hosts
                    + " or a loopback address" + (httpsAllowed ? ", or https" : "") + ": " + value);
        }
        if (httpsAllowed && (uri.getRawPath() == null || uri.getRawPath().isEmpty())) {
            throw new IllegalArgumentException("The URI of " + what + " has no path: " + value);
        }
        return uri;
    }

    private static String unbracketed(String host) {
        return host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
    }

    /** Whether {@code host} is {@code localhost} or a loopback IP literal; a name is never looked up. */
    static boolean isLoopback(String host) {
        if ("localhost".equalsIgnoreCase(host)) {
            return true;
        }
        String literal = unbracketed(host);
        if (!literal.matches("[0-9.]+|[0-9a-fA-F:]+")) {
            return false;
        }
        try {
            return InetAddress.getByName(literal).isLoopbackAddress();
        } catch (IOException _) {
            return false;
        }
    }

    /** {@code ~/.aws/credentials}, with {@code ~} from {@code HOME} as the AWS SDKs take it, else the JVM's. */
    private static Path defaultCredentialsFile(UnaryOperator<String> environment) {
        String home = firstOf(environment.apply("HOME"), System.getProperty("user.home"));
        return Path.of(home, ".aws", "credentials");
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }

    static String firstOf(String... values) {
        for (String value : values) {
            if (isSet(value)) {
                return value;
            }
        }
        return null;
    }
}
