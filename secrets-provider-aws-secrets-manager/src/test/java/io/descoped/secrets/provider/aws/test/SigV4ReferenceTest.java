package io.descoped.secrets.provider.aws.test;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The test-side SigV4 against AWS's published examples, so that {@link FakeAws} checks the provider against a
 * reference that is right.
 */
class SigV4ReferenceTest {

    private static final String SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    /** AWS's example of deriving a signing key (IAM, 2012-02-15, us-east-1). */
    @Test
    void theSigningKeyMatchesAwsExample() {
        assertEquals("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d",
                HexFormat.of().formatHex(SigV4Reference.signingKey(SECRET, "20120215", "us-east-1", "iam")));
    }

    /** {@code get-vanilla} and {@code post-vanilla} from AWS's Signature Version 4 test suite. */
    @Test
    void theVanillaRequestsMatchAwsTestSuite() {
        Map<String, String> headers = Map.of("host", "example.amazonaws.com", "x-amz-date", "20150830T123600Z");
        assertEquals("5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
                SigV4Reference.signature(SECRET, "20150830T123600Z", "us-east-1", "service",
                        SigV4Reference.canonicalRequest("GET", "/", headers, new byte[0])));
        assertEquals("5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
                SigV4Reference.signature(SECRET, "20150830T123600Z", "us-east-1", "service",
                        SigV4Reference.canonicalRequest("POST", "/", headers, new byte[0])));
    }
}
