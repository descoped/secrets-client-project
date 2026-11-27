package io.descoped.secrets.provider.aws.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The credential sources against {@link FakeAws}: the container credentials endpoint (ECS task role, EKS Pod
 * Identity) and EC2 instance metadata (IMDSv2), with temporary credentials that are fetched again before they expire.
 * The environment is the JVM's own; {@link AwsSecretsManagerCanaryTest} runs what depends on it in child JVMs.
 */
class AwsCredentialsTest {

    private static final String KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    private static final String SESSION = "IQoJb3JpZ2luX2VjEJr//////////wEaCmV1LW5vcnRoLTE=";

    @TempDir
    Path dir;

    private FakeAws aws;

    @BeforeEach
    void start() throws IOException {
        aws = new FakeAws();
        aws.secretAccessKey = KEY;
        aws.sessionToken = SESSION;
        aws.put("s", "v1", "value", null);
    }

    @AfterEach
    void stop() {
        aws.close();
    }

    private Map<String, String> configuration(String credentials) {
        return new HashMap<>(Map.of(
                "secrets.provider", "aws-secrets-manager",
                "secrets.region", FakeAws.REGION,
                "secrets.endpoint", aws.endpoint(),
                "secrets.credentials", credentials));
    }

    private Map<String, String> container() {
        Map<String, String> configuration = configuration("container");
        configuration.put("secrets.container-credentials-uri", aws.endpoint() + FakeAws.CONTAINER_PATH);
        return configuration;
    }

    private Map<String, String> instance() {
        Map<String, String> configuration = configuration("instance");
        configuration.put("secrets.instance-metadata-endpoint", aws.endpoint());
        return configuration;
    }

    private static void readTwice(Map<String, String> configuration) {
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            assertEquals("value", Values.text(client, "s"));
            assertEquals("value", Values.text(client, "s"));
        }
    }

    @Test
    void theEcsTaskRoleNeedsNoToken() {
        readTwice(container());
        assertEquals(List.of("GET " + FakeAws.CONTAINER_PATH + " null"), aws.credentialRequests,
                "fetched once, for both reads");
        assertTrue(aws.requests.stream().allMatch(r -> SESSION.equals(r.headers().get("x-amz-security-token"))));
    }

    /** EKS Pod Identity: the token is read from its file, without the line ending, on each fetch. */
    @Test
    void anAuthorizationTokenIsReadFromItsFile() throws IOException {
        aws.containerToken = "eyJhbGciOiJSUzI1NiJ9.pod-identity";
        Map<String, String> configuration = container();
        configuration.put("secrets.container-authorization-token-file",
                Files.writeString(dir.resolve("token"), aws.containerToken + "\n").toString());
        readTwice(configuration);
        assertEquals(List.of("GET " + FakeAws.CONTAINER_PATH + " " + aws.containerToken), aws.credentialRequests);
    }

    @Test
    void aWrongAuthorizationTokenIsReported() throws IOException {
        aws.containerToken = "the right one";
        Map<String, String> configuration = container();
        configuration.put("secrets.container-authorization-token-file",
                Files.writeString(dir.resolve("token"), "a wrong one").toString());
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertEquals("The container credentials endpoint returned HTTP 403", e.getMessage());
        }
        assertTrue(aws.requests.isEmpty(), "nothing was sent to Secrets Manager");
    }

    @Test
    void aMissingTokenFileIsReported() {
        Map<String, String> configuration = container();
        configuration.put("secrets.container-authorization-token-file", dir.resolve("missing").toString());
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertTrue(e.getMessage().startsWith("Cannot read the container authorization token file"),
                    e.getMessage());
        }
    }

    /** Credentials that expire within five minutes are fetched again before each use. */
    @Test
    void credentialsAboutToExpireAreFetchedAgain() {
        aws.credentialsLifetime = Duration.ofMinutes(4);
        readTwice(container());
        assertEquals(2, aws.credentialRequests.size());
    }

    @Test
    void instanceMetadataUsesASessionToken() {
        readTwice(instance());
        String token = aws.instanceToken;
        assertEquals(List.of("PUT /latest/api/token null",
                "GET /latest/meta-data/iam/security-credentials/ " + token,
                "GET /latest/meta-data/iam/security-credentials/" + FakeAws.ROLE + " " + token),
                aws.credentialRequests, "one fetch, with IMDSv2, for both reads");
    }

    /** Nothing listens on port 1 of the loopback address. */
    @Test
    void anUnreachableInstanceMetadataIsReported() {
        Map<String, String> configuration = instance();
        configuration.put("secrets.instance-metadata-endpoint", "http://127.0.0.1:1");
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertTrue(e.getMessage().startsWith("Cannot reach EC2 instance metadata for the session token"),
                    e.getMessage());
        }
    }

    @Test
    void aWrongInstanceMetadataTokenIsReported() {
        aws.issuedInstanceToken = "not accepted";
        try (SecretManagerClient client = SecretManagerClient.create(instance())) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertEquals("EC2 instance metadata returned HTTP 401 for the role", e.getMessage());
        }
    }

    @Test
    void malformedCredentialsAreReportedWithoutThem() {
        aws.malformedExpiration = true;
        try (SecretManagerClient client = SecretManagerClient.create(container())) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertEquals("Cannot parse the credentials from the container credentials endpoint"
                    + " (DateTimeParseException)", e.getMessage());
            assertNull(e.getCause(), "nothing about the keys is chained");
        }
    }

    @Test
    void endpointsOutsideTheAllowedHostsAreRefused() {
        for (Map.Entry<String, String> bad : List.of(
                Map.entry("secrets.container-credentials-uri", "http://example.com/v2/credentials"),
                Map.entry("secrets.container-credentials-uri", "https://example.com"),
                Map.entry("secrets.container-credentials-uri", "not a uri"),
                Map.entry("secrets.instance-metadata-endpoint", "https://169.254.169.254"),
                Map.entry("secrets.instance-metadata-endpoint", "http://metadata.example.com"))) {
            Map<String, String> configuration = bad.getKey().contains("container") ? container() : instance();
            configuration.put(bad.getKey(), bad.getValue());
            Exception e = assertThrows(Exception.class, () -> SecretManagerClient.create(configuration).close(),
                    bad.toString());
            assertInstanceOf(IllegalArgumentException.class, rootOf(e), bad.toString());
        }
    }

    @Test
    void anHttpsContainerEndpointOnAnyHostIsAccepted() {
        Map<String, String> configuration = container();
        configuration.put("secrets.container-credentials-uri", "https://credentials.example.com/v1/credentials");
        SecretManagerClient.create(configuration).close();
    }

    @Test
    void anUnknownSourceIsRefused() {
        Exception e = assertThrows(Exception.class, () -> SecretManagerClient.create(configuration("sso")).close());
        assertInstanceOf(IllegalArgumentException.class, rootOf(e));
        assertTrue(rootOf(e).getMessage().contains("default, profile, container, instance or environment"));
    }

    @Test
    void aContainerSourceWithoutAnEndpointIsRefused() {
        Exception e = assertThrows(Exception.class,
                () -> SecretManagerClient.create(configuration("container")).close());
        assertTrue(rootOf(e).getMessage().startsWith("No container credentials endpoint"), rootOf(e).getMessage());
    }

    /** The test JVM has no AWS keys in its environment, so {@code environment} has nothing to use. */
    @Test
    void theEnvironmentSourceNeedsBothKeys() {
        try (SecretManagerClient client = SecretManagerClient.create(configuration("environment"))) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertEquals("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not both set", e.getMessage());
        }
    }

    private static Throwable rootOf(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null && !(t instanceof IllegalArgumentException)) {
            t = t.getCause();
        }
        return t;
    }
}
