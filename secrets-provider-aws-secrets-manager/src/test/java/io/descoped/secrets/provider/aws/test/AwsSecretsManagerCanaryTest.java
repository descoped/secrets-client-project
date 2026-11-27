package io.descoped.secrets.provider.aws.test;

import io.descoped.secrets.test.support.HeapCanary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.net.ssl.SSLContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The canary gate for AWS Secrets Manager: the secret access key, the session token, a value read and a value written
 * stay off the Java heap, through SigV4 signing (HMAC and SHA-256 through OpenSSL). Each test runs
 * {@link CanaryClient} in a child JVM against FakeAws, which checks every signature, and searches the heap dump for
 * the canary: the secret access key or the session token, and the value at the same time. The value is a
 * {@code SecretString}, or a {@code SecretBinary} that is not valid UTF-8, so that it is written back as one too.
 */
class AwsSecretsManagerCanaryTest {

    private static final String SUBJECT = "io.descoped.secrets.provider.aws.test/"
            + "io.descoped.secrets.provider.aws.test.CanaryClient";
    private static final String PROFILE = "[default]\naws_access_key_id = " + FakeAws.ACCESS_KEY_ID + "\n";
    private static final String KNOWN_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    /** The subject's mode for the default chain, with no source in its configuration. */
    private static final String CHAIN = "CHAIN";
    private static final String KNOWN_SESSION ="IQoJb3JpZ2luX2VjEJr//////////wEaCmV1LW5vcnRoLTE=";
    /** Before the canary in a binary value: not UTF-8, and Base64 {@code ////}, so that escaping applies. */
    private static final byte[] NOT_UTF8 = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

    /** Where the canary is, and how the value is sent. */
    private enum Mode {
        KEY, TOKEN, BINARY, ESCAPED_BINARY,
        /** The container endpoint: the canary is the authorization token, the secret access key and the value. */
        CONTAINER,
        /** IMDSv2: the canary is the IMDS session token, the session token and the value. */
        INSTANCE
    }

    @TempDir
    Path dir;
    @TempDir
    Path keys;
    /** An empty {@code HOME} for the chain, so that no {@code ~/.aws/credentials} is found. */
    @TempDir
    Path home;

    private void run(Mode mode, SSLContext tls) throws Exception {
        boolean role = mode == Mode.CONTAINER || mode == Mode.INSTANCE;
        boolean token = mode == Mode.TOKEN || mode == Mode.INSTANCE;
        String before = role ? "" : PROFILE + (token
                ? "aws_secret_access_key = " + KNOWN_KEY + "\naws_session_token = "
                : "aws_secret_access_key = ");
        HeapCanary canary = HeapCanary.create(dir, before, role ? "" : "\n");
        String content = Files.readString(canary.file(), StandardCharsets.UTF_8);
        String value = content.substring(before.length(), before.length() + HeapCanary.LENGTH);
        boolean binary = mode == Mode.BINARY || mode == Mode.ESCAPED_BINARY;
        byte[] bytes = binary ? concat(NOT_UTF8, value.getBytes(StandardCharsets.US_ASCII)) : null;
        try (FakeAws aws = tls == null ? new FakeAws() : new FakeAws(tls)) {
            aws.secretAccessKey = token ? KNOWN_KEY : value;
            aws.sessionToken = token ? value : role ? KNOWN_SESSION : null;
            aws.escapeSlashes = mode == Mode.ESCAPED_BINARY;
            if (mode == Mode.CONTAINER) {
                aws.containerToken = value;
            } else if (mode == Mode.INSTANCE) {
                aws.instanceToken = value;
            }
            aws.put("canary", "00000000-0000-0000-0000-000000000001", binary ? null : value, bytes);
            List<String> args = new ArrayList<>(List.of(mode.name(), aws.endpoint()));
            if (tls != null) {
                args.add(TestCertificates.trusted(keys).toString());
            }
            canary.run(SUBJECT, args.toArray(String[]::new)).assertClean();
            // The read, the put that finds no secret, and the create: all signed right, or the copy would be missing.
            assertEquals(3, aws.requests.size());
            FakeAws.Version copy = aws.secrets.get("copy").versions.values().iterator().next();
            if (binary) {
                assertArrayEquals(bytes, copy.binary(), "the canary was written back as SecretBinary");
            } else {
                assertEquals(value, copy.string(), "the canary was written back as SecretString");
            }
            if (token) {
                assertTrue(aws.requests.stream().allMatch(r -> value.equals(r.headers().get("x-amz-security-token"))),
                        "the canary was the session token");
            }
            if (role) {
                assertTrue(aws.credentialRequests.stream().anyMatch(r -> r.endsWith(" " + value)),
                        "the canary was the container or IMDS token: " + aws.credentialRequests.size());
            }
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    @Test
    void aSecretAccessKeyLeavesTheHeapClean() throws Exception {
        run(Mode.KEY, null);
    }

    @Test
    void aSessionTokenLeavesTheHeapClean() throws Exception {
        run(Mode.TOKEN, null);
    }

    /** {@code SecretBinary} both ways: decoded from Base64 on reading, encoded on writing. */
    @Test
    void aBinaryValueLeavesTheHeapClean() throws Exception {
        run(Mode.BINARY, null);
    }

    /** {@code SecretBinary} with {@code \/} escapes, unescaped into guarded memory before decoding. */
    @Test
    void anEscapedBinaryValueLeavesTheHeapClean() throws Exception {
        run(Mode.ESCAPED_BINARY, null);
    }

    /** ECS task role or EKS Pod Identity: the authorization token read from its file, and the credentials issued. */
    @Test
    void containerCredentialsLeaveTheHeapClean() throws Exception {
        run(Mode.CONTAINER, null);
    }

    /** IMDSv2: the IMDS session token, and the credentials issued. */
    @Test
    void instanceCredentialsLeaveTheHeapClean() throws Exception {
        run(Mode.INSTANCE, null);
    }

    /**
     * The default chain, with an empty {@code HOME}, finds the container endpoint the platform sets in the environment
     * (EKS Pod Identity: a full URI and a token file), and keeps everything off the heap.
     */
    @Test
    void theChainFindsTheContainerEndpoint() throws Exception {
        HeapCanary canary = HeapCanary.create(dir);
        String value = Files.readString(canary.file(), StandardCharsets.US_ASCII);
        try (FakeAws aws = new FakeAws()) {
            aws.secretAccessKey = value;
            aws.sessionToken = KNOWN_SESSION;
            aws.containerToken = value;
            aws.put("canary", "00000000-0000-0000-0000-000000000001", value, null);
            canary.environment(Map.of(
                    "HOME", home.toString(),
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI", aws.endpoint() + FakeAws.CONTAINER_PATH,
                    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", canary.file().toString()))
                    .run(SUBJECT, CHAIN, aws.endpoint()).assertClean();
            assertEquals(1, aws.credentialRequests.size());
            assertEquals(3, aws.requests.size());
        }
    }

    /** What the chain refuses to use, before any request: each a variable that would put a credential on the heap. */
    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "AWS_ACCESS_KEY_ID|AKIAIOSFODNN7EXAMPLE|AWS_ACCESS_KEY_ID is set, but keys in the environment are on the"
                    + " Java heap",
            "AWS_WEB_IDENTITY_TOKEN_FILE|/var/run/secrets/token|AWS_WEB_IDENTITY_TOKEN_FILE is set, but web identity",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN|Bearer x|AWS_CONTAINER_AUTHORIZATION_TOKEN is set, but a token in the"
                    + " environment is on the Java heap"})
    void theChainRefuses(String variable, String setting, String message) throws Exception {
        HeapCanary canary = HeapCanary.create(dir);
        try (FakeAws aws = new FakeAws()) {
            Map<String, String> environment = new HashMap<>(Map.of("HOME", home.toString(), variable, setting));
            environment.put("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", FakeAws.CONTAINER_PATH);
            HeapCanary.Run run = canary.environment(environment).run(SUBJECT, CHAIN, aws.endpoint());
            assertNotEquals(0, run.exit());
            assertTrue(run.output().contains(message), run.output());
            assertTrue(aws.requests.isEmpty() && aws.credentialRequests.isEmpty(), "nothing was sent");
        }
    }

    /** The same over TLS (OpenSSL). */
    @Test
    void tlsLeavesTheHeapClean() throws Exception {
        run(Mode.TOKEN, TestCertificates.server(keys, "fake-aws", "SAN=ip:127.0.0.1"));
    }
}
