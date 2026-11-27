package io.descoped.secrets.provider.aws.test;

import io.descoped.secrets.test.support.HeapCanary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The canary gate for AWS Secrets Manager: the secret access key, the session token, a value read and a value written
 * stay off the Java heap, through SigV4 signing (HMAC and SHA-256 through OpenSSL). Each test runs
 * {@link CanaryClient} in a child JVM against FakeAws, which checks every signature, and searches the heap dump for
 * the canary: the secret access key or the session token, and the value at the same time.
 */
class AwsSecretsManagerCanaryTest {

    private static final String SUBJECT = "io.descoped.secrets.provider.aws.test/"
            + "io.descoped.secrets.provider.aws.test.CanaryClient";
    private static final String PROFILE = "[default]\naws_access_key_id = " + FakeAws.ACCESS_KEY_ID + "\n";
    private static final String KNOWN_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    @TempDir
    Path dir;
    @TempDir
    Path keys;

    /** {@code token}: the canary is the session token, else the secret access key. */
    private void run(boolean token, SSLContext tls) throws Exception {
        String before = PROFILE + (token
                ? "aws_secret_access_key = " + KNOWN_KEY + "\naws_session_token = "
                : "aws_secret_access_key = ");
        HeapCanary canary = HeapCanary.create(dir, before, "\n");
        String content = Files.readString(canary.file(), StandardCharsets.UTF_8);
        String value = content.substring(before.length(), before.length() + HeapCanary.LENGTH);
        try (FakeAws aws = tls == null ? new FakeAws() : new FakeAws(tls)) {
            aws.secretAccessKey = token ? KNOWN_KEY : value;
            aws.sessionToken = token ? value : null;
            aws.put("canary", "00000000-0000-0000-0000-000000000001", value, null);
            List<String> args = new ArrayList<>(List.of("subject", aws.endpoint()));
            if (tls != null) {
                args.add(TestCertificates.trusted(keys).toString());
            }
            canary.run(SUBJECT, args.toArray(String[]::new)).assertClean();
            // The read, the put that finds no secret, and the create: all signed right, or the copy would be missing.
            assertEquals(3, aws.requests.size());
            assertEquals(value, aws.secrets.get("copy").versions.values().iterator().next().string(),
                    "the canary was written back");
            if (token) {
                assertTrue(aws.requests.stream().allMatch(r -> value.equals(r.headers().get("x-amz-security-token"))),
                        "the canary was the session token");
            }
        }
    }

    @Test
    void aSecretAccessKeyLeavesTheHeapClean() throws Exception {
        run(false, null);
    }

    @Test
    void aSessionTokenLeavesTheHeapClean() throws Exception {
        run(true, null);
    }

    /** The same over TLS (OpenSSL). */
    @Test
    void tlsLeavesTheHeapClean() throws Exception {
        run(true, TestCertificates.server(keys, "fake-aws", "SAN=ip:127.0.0.1"));
    }
}
