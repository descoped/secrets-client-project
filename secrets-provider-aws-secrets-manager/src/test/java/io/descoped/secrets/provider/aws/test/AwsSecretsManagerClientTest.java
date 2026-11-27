package io.descoped.secrets.provider.aws.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;
import io.descoped.secrets.provider.aws.test.FakeAws.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The provider against {@link FakeAws}, which checks every signature. */
class AwsSecretsManagerClientTest {

    @TempDir
    Path dir;

    private FakeAws aws;

    @BeforeEach
    void start() throws IOException {
        aws = new FakeAws();
    }

    @AfterEach
    void stop() {
        aws.close();
    }

    private Map<String, String> configuration() throws IOException {
        return new HashMap<>(Map.of(
                "secrets.provider", "aws-secrets-manager",
                "secrets.region", FakeAws.REGION,
                "secrets.endpoint", aws.endpoint(),
                "secrets.credentials-path", aws.credentialsFile(dir, "test").toString(),
                "secrets.aws-profile", "test"));
    }

    private SecretManagerClient open() throws IOException {
        return SecretManagerClient.create(configuration());
    }

    @Test
    void readsAStringValue() throws IOException {
        aws.put("app/db", "v1", "pässword \"quoted\"\n", null);
        try (SecretManagerClient client = open()) {
            assertEquals("pässword \"quoted\"\n", Values.text(client, "app/db"));
            assertEquals("pässword \"quoted\"\n", Values.text(client, "app/db", "latest"));
        }
        assertEquals("{\"SecretId\":\"app/db\",\"VersionStage\":\"AWSCURRENT\"}",
                aws.requests("GetSecretValue").getFirst().body());
    }

    @Test
    void readsABinaryValue() throws IOException {
        byte[] value = new byte[3000];
        new Random(1).nextBytes(value);
        aws.put("key", "v1", null, value);
        try (SecretManagerClient client = open()) {
            assertArrayEquals(value, Values.bytes(client, "key"));
        }
    }

    @Test
    void readsVersionsByIdAndStage() throws IOException {
        String first = "11111111-1111-1111-1111-111111111111";
        String second = "22222222-2222-2222-2222-222222222222";
        aws.put("s", first, "one", null);
        aws.put("s", second, "two", null);
        try (SecretManagerClient client = open()) {
            assertEquals("two", Values.text(client, "s"));
            assertEquals("one", Values.text(client, "s", "AWSPREVIOUS"));
            assertEquals("one", Values.text(client, "s", first));
            assertEquals("two", Values.text(client, "s", second));
        }
        assertEquals("{\"SecretId\":\"s\",\"VersionId\":\"" + first + "\"}",
                aws.requests("GetSecretValue").get(2).body());
    }

    @Test
    void aMissingSecretOrVersionIsNotFound() throws IOException {
        aws.put("s", "v1", "one", null);
        try (SecretManagerClient client = open()) {
            assertThrows(SecretNotFoundException.class, () -> client.read("missing"));
            assertThrows(SecretNotFoundException.class, () -> client.read("s", "AWSPENDING"));
            assertThrows(SecretNotFoundException.class,
                    () -> client.read("s", "33333333-3333-3333-3333-333333333333"));
        }
    }

    /** A secret's ARN is accepted as its ID, and sent as it is. */
    @Test
    void anArnReadsTheSecret() throws IOException {
        String arn = "arn:aws:secretsmanager:eu-north-1:123456789012:secret:app/db-AbCdEf";
        aws.put(arn, "v1", "by arn", null);
        try (SecretManagerClient client = open()) {
            assertEquals("by arn", Values.text(client, arn));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "has space", "quote\"", "back\\slash", "ünïcode", "colon:name",
            "arn:aws:iam::123456789012:user/someone"})
    void anInvalidNameIsNotFoundWithoutARequest(String name) throws IOException {
        try (SecretManagerClient client = open()) {
            assertThrows(SecretNotFoundException.class, () -> client.read(name));
            assertThrows(SecretNotFoundException.class, () -> client.read("s", "bad version"));
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> Values.add(client, name, "v"));
            assertFalse(e instanceof SecretNotFoundException);
        }
        assertTrue(aws.requests.isEmpty());
    }

    /** Names are at most 512 characters; only ARNs are longer. */
    @Test
    void aNameLongerThan512IsNotFoundWithoutARequest() throws IOException {
        String name = "n".repeat(513);
        try (SecretManagerClient client = open()) {
            assertThrows(SecretNotFoundException.class, () -> client.read(name));
        }
        assertTrue(aws.requests.isEmpty());
    }

    @Test
    void addVersionCreatesTheSecretThenAddsVersions() throws IOException {
        try (SecretManagerClient client = open()) {
            String first = Values.add(client, "new/secret", "first\u0001\t\"x\"");
            String second = Values.add(client, "new/secret", "second");
            assertNotEquals(first, second);
            assertEquals("second", Values.text(client, "new/secret"));
            assertEquals("first\u0001\t\"x\"", Values.text(client, "new/secret", first));
            assertEquals("first\u0001\t\"x\"", Values.text(client, "new/secret", "AWSPREVIOUS"));
        }
        List<FakeAws.Request> puts = aws.requests("PutSecretValue");
        assertEquals(2, puts.size());
        assertEquals(1, aws.requests("CreateSecret").size());
        Map<String, Object> create = aws.requests("CreateSecret").getFirst().json();
        assertEquals("new/secret", create.get("Name"));
        assertEquals("first\u0001\t\"x\"", create.get("SecretString"));
        assertFalse(create.containsKey("KmsKeyId"));
        assertNotEquals(puts.get(0).json().get("ClientRequestToken"), create.get("ClientRequestToken"));
    }

    @Test
    void aValueThatIsNotUtf8IsWrittenAsBinary() throws IOException {
        byte[] value = {(byte) 0xFF, 0, (byte) 0xC3, 'a'};
        try (SecretManagerClient client = open()) {
            Values.add(client, "bin", value);
            assertArrayEquals(value, Values.bytes(client, "bin"));
        }
        Map<String, Object> create = aws.requests("CreateSecret").getFirst().json();
        assertEquals("/wDDYQ==", create.get("SecretBinary"));
        assertFalse(create.containsKey("SecretString"));
    }

    @Test
    void createdSecretsGetTheConfiguredKeyAndReplicas() throws IOException {
        Map<String, String> configuration = configuration();
        configuration.put("secrets.kms-key-id", "alias/app-secrets");
        configuration.put("secrets.replica-regions", "eu-west-1, us-east-2");
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            Values.add(client, "replicated", "v");
        }
        Map<String, Object> create = aws.requests("CreateSecret").getFirst().json();
        assertEquals("alias/app-secrets", create.get("KmsKeyId"));
        assertEquals(List.of(Map.of("Region", "eu-west-1"), Map.of("Region", "us-east-2")),
                create.get("AddReplicaRegions"));
    }

    /** Created by someone else between the put and the create: the version is added to theirs. */
    @Test
    void aSecretCreatedMeanwhileGetsTheVersion() throws IOException {
        aws.on("CreateSecret", FakeAws.error(400, "ResourceExistsException", "exists"));
        aws.on("PutSecretValue",
                FakeAws.error(400, "ResourceNotFoundException", "not found"),
                new Response(200, "{\"Name\":\"race\",\"VersionId\":\"v-theirs-and-ours-0000000000000000\"}"));
        try (SecretManagerClient client = open()) {
            assertEquals("v-theirs-and-ours-0000000000000000", Values.add(client, "race", "v"));
        }
        assertEquals(2, aws.requests("PutSecretValue").size());
    }

    @Test
    void temporaryCredentialsSendAndSignTheSessionToken() throws IOException {
        aws.sessionToken = "FwoGZXIvYXdzEJr//////////wEaDOtoken+/=";
        aws.put("s", "v1", "value", null);
        try (SecretManagerClient client = open()) {
            assertEquals("value", Values.text(client, "s"));
        }
        FakeAws.Request request = aws.requests.getFirst();
        assertEquals(aws.sessionToken, request.headers().get("x-amz-security-token"));
        assertTrue(request.headers().get("authorization").contains("x-amz-security-token"));
    }

    @Test
    void aWrongKeyIsRefusedBySignature() throws IOException {
        Map<String, String> configuration = configuration();
        aws.secretAccessKey = "another-key";
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertTrue(e.getMessage().contains("InvalidSignatureException"), e.getMessage());
            assertTrue(e.getMessage().contains("HTTP 403"), e.getMessage());
        }
    }

    @Test
    void errorsNameTheTypeAndMessage() throws IOException {
        aws.on("GetSecretValue", FakeAws.error(400, "DecryptionFailure", "Can't decrypt"),
                new Response(500, "not json"));
        try (SecretManagerClient client = open()) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertEquals("AWS Secrets Manager returned HTTP 400 DecryptionFailure when reading secret 's': "
                    + "Can't decrypt", e.getMessage());
            e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertEquals("AWS Secrets Manager returned HTTP 500 when reading secret 's'", e.getMessage());
        }
    }

    @Test
    void malformedResponsesAreReportedWithoutTheBody() throws IOException {
        aws.on("GetSecretValue",
                new Response(200, "{\"SecretBinary\":\"not base64!\"}"),
                new Response(200, "{\"Name\":\"s\"}"),
                new Response(200, "{\"SecretString\":\"bad \\q escape\"}"),
                new Response(200, "{\"SecretBinary\":\"AAE\\/\"}").asChunks());
        aws.on("PutSecretValue", new Response(200, "{\"Name\":\"s\"}"));
        aws.put("s", "v1", "x", null);
        try (SecretManagerClient client = open()) {
            assertTrue(assertThrows(SecretManagerException.class, () -> client.read("s")).getMessage()
                    .startsWith("Cannot parse the response for secret 's'"));
            assertEquals("No SecretString or SecretBinary in the response for secret 's'",
                    assertThrows(SecretManagerException.class, () -> client.read("s")).getMessage());
            assertTrue(assertThrows(SecretManagerException.class, () -> client.read("s")).getMessage()
                    .startsWith("Cannot parse the response for secret 's'"));
            // "AAE\/" is "AAE/" with the slash escaped, as JSON allows: 00 01 3F.
            assertArrayEquals(new byte[]{0, 1, 0x3F}, Values.bytes(client, "s"));
            assertEquals("No VersionId in the response for secret 's'",
                    assertThrows(SecretManagerException.class, () -> Values.add(client, "s", "v")).getMessage());
        }
    }

    @Test
    void aSlowServerTimesOut() throws IOException {
        aws.on("GetSecretValue", new Response(200, "{}").delayed(5000));
        Map<String, String> configuration = configuration();
        configuration.put("secrets.request-timeout", "PT0.3S");
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertEquals("Timed out reading secret 's'", e.getMessage());
        }
    }

    @Test
    void aClosedClientRefusesUse() throws IOException {
        SecretManagerClient client = open();
        client.close();
        client.close();
        assertThrows(IllegalStateException.class, () -> client.read("s"));
        assertThrows(IllegalStateException.class, () -> Values.add(client, "s", "v"));
    }

    @Test
    void credentialsFileProblemsAreReported() throws IOException {
        Map<String, String> configuration = configuration();
        configuration.put("secrets.aws-profile", "absent");
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertTrue(e.getMessage().contains("has no profile 'absent'"), e.getMessage());
        }
        configuration.put("secrets.aws-profile", "other");
        configuration.put("secrets.credentials-path", Files.writeString(dir.resolve("partial"),
                "[other]\naws_access_key_id = AKID\n").toString());
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertTrue(e.getMessage().contains("has no aws_access_key_id and aws_secret_access_key"),
                    e.getMessage());
        }
        configuration.put("secrets.credentials-path", dir.resolve("missing").toString());
        try (SecretManagerClient client = SecretManagerClient.create(configuration)) {
            SecretManagerException e = assertThrows(SecretManagerException.class, () -> client.read("s"));
            assertTrue(e.getMessage().startsWith("Cannot read the AWS credentials file"), e.getMessage());
        }
        assertTrue(aws.requests.isEmpty());
    }

    @Test
    void invalidConfigurationIsRefused() throws IOException {
        Map<String, String> base = configuration();
        for (Map.Entry<String, String> bad : List.of(
                Map.entry("secrets.region", "Europe"),
                Map.entry("secrets.endpoint", "http://example.com"),
                Map.entry("secrets.endpoint", "not a uri"),
                Map.entry("secrets.endpoint", "https:///nohost"),
                Map.entry("secrets.kms-key-id", "bad key\""),
                Map.entry("secrets.replica-regions", "eu-west-1,nowhere"),
                Map.entry("secrets.request-timeout", "PT2H"),
                Map.entry("secrets.connect-timeout", "soon"))) {
            Map<String, String> configuration = new HashMap<>(base);
            configuration.put(bad.getKey(), bad.getValue());
            Exception e = assertThrows(Exception.class, () -> SecretManagerClient.create(configuration).close(),
                    bad.toString());
            assertInstanceOf(IllegalArgumentException.class, rootOf(e), bad.toString());
        }
    }

    private static Throwable rootOf(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null && !(t instanceof IllegalArgumentException)) {
            t = t.getCause();
        }
        return t;
    }

    @Test
    void largeValuesRoundTrip() throws IOException {
        byte[] large = new byte[60 * 1024];
        new Random(3).nextBytes(large);
        String text = "x".repeat(60 * 1024);
        try (SecretManagerClient client = open()) {
            Values.add(client, "large-bin", large);
            Values.add(client, "large-text", text);
            assertArrayEquals(large, Values.bytes(client, "large-bin"));
            assertEquals(text, Values.text(client, "large-text"));
        }
        assertEquals(text, aws.secrets.get("large-text").versions.values().iterator().next().string());
    }
}
