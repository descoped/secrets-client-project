package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;
import io.descoped.secrets.api.http.Codec;
import io.descoped.secrets.api.http.Http;
import io.descoped.secrets.api.http.Json;
import io.descoped.secrets.api.tls.TlsContext;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.foreign.MemorySegment;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * AWS Secrets Manager through its JSON 1.1 API, signed with SigV4, on guarded memory from end to end: each request
 * is built and signed in guarded memory with the credentials, and each response is read into guarded memory, where
 * its JSON is parsed and the value unescaped or decoded from Base64 into the {@link Secret} that
 * {@link #read(String, String)} returns. See {@link AwsSecretsManagerClientInitializer} for the configuration.
 */
final class AwsSecretsManagerClient implements SecretManagerClient {

    /** Names as Secrets Manager accepts them. */
    static final Pattern SECRET_NAME_RULE = Pattern.compile("[A-Za-z0-9/_+=.@-]{1,512}");

    /** Secret ARNs, in any partition. */
    static final Pattern SECRET_ARN = Pattern.compile("arn:aws[a-z-]{0,20}:secretsmanager:[a-z0-9-]{1,30}:\\d{12}"
            + ":secret:[A-Za-z0-9/_+=.@-]{1,512}");

    /** A version ID (a UUID, or another client request token of 32 to 64 characters). */
    static final Pattern VERSION_ID = Pattern.compile("[A-Za-z0-9-]{32,64}");

    /** A staging label, such as {@code AWSCURRENT} or {@code AWSPREVIOUS}. */
    static final Pattern VERSION_STAGE = Pattern.compile("[A-Za-z0-9_+=.@-]{1,256}");

    private static final String SECRET_NAME = "secretName";
    private static final String SECRET_VALUE = "secretValue";
    private static final String TARGET = "secretsmanager.";
    private static final String NOT_FOUND = "ResourceNotFoundException";
    private static final String EXISTS = "ResourceExistsException";
    private static final String VERSION_ID_FIELD = "VersionId";

    /**
     * What the client talks to and how.
     *
     * @param api            the endpoint
     * @param timeouts       how long to wait
     * @param kmsKeyId       the KMS key of created secrets, or {@code null}
     * @param replicaRegions the regions to replicate created secrets to
     */
    record Settings(Http.Target api, Http.Timeouts timeouts, String kmsKeyId, List<String> replicaRegions) {

        Settings {
            replicaRegions = List.copyOf(replicaRegions);
        }
    }

    private final Settings settings;
    private final SigV4 signer;
    private final SecretMemory memory;
    private final CredentialsProvider credentials;
    private final TlsContext tls;
    private final Clock clock;
    private volatile boolean closed;

    AwsSecretsManagerClient(Settings settings, SigV4 signer, SecretMemory memory, CredentialsProvider credentials,
                            TlsContext tls, Clock clock) {
        this.settings = settings;
        this.signer = signer;
        this.memory = memory;
        this.credentials = credentials;
        this.tls = tls;
        this.clock = clock;
    }

    /** Whether Secrets Manager can hold {@code secretId}: a name, or the ARN of a secret. */
    static boolean isSecretId(String secretId) {
        return SECRET_NAME_RULE.matcher(secretId).matches() || SECRET_ARN.matcher(secretId).matches();
    }

    /**
     * Reads a version: {@code null} or {@code latest} is the current one ({@code AWSCURRENT}), a version ID selects
     * that version, and anything else is a staging label, such as {@code AWSPREVIOUS}. A staging label of 32 to 64
     * letters, digits and hyphens that does not start with {@code AWS} is taken for a version ID.
     */
    @Override
    public Secret read(String secretName, String secretVersion) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        checkOpen();
        String version = secretVersion == null || secretVersion.equals("latest") ? "AWSCURRENT" : secretVersion;
        // A name or version Secrets Manager cannot hold does not exist; no request is sent for it.
        if (!isSecretId(secretName) || !VERSION_STAGE.matcher(version).matches()) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        String selector = VERSION_ID.matcher(version).matches() && !version.startsWith("AWS")
                ? "\"VersionId\":\"" + version + "\"" : "\"VersionStage\":\"" + version + "\"";
        byte[] body = ("{\"SecretId\":\"" + secretName + "\"," + selector + "}").getBytes(StandardCharsets.US_ASCII);
        try (Http.Response response = send("GetSecretValue", MemorySegment.ofArray(body), secretName, "reading")) {
            if (response.status() != 200) {
                AwsError error = AwsError.of(response);
                if (error.is(NOT_FOUND)) {
                    throw new SecretNotFoundException(secretName, secretVersion);
                }
                throw error.exception("reading", secretName);
            }
            return value(response.body(), secretName);
        }
    }

    /**
     * Adds a version as the current one, and creates the secret first if it does not exist (with the KMS key and
     * replica regions from the configuration). Returns the new version ID. The value is sent as
     * {@code SecretString} when it is valid UTF-8, as other AWS tools expect, else as {@code SecretBinary}. Each
     * request carries a new client request token, so a retried request never adds a second version.
     */
    @Override
    public String addVersion(String secretName, Secret secretValue) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        Objects.requireNonNull(secretValue, SECRET_VALUE);
        checkOpen();
        if (!isSecretId(secretName)) {
            throw new SecretManagerException("Invalid secret name '" + secretName
                    + "': Secrets Manager allows 1 to 512 letters, digits and /_+=.@-, or a secret's ARN");
        }
        return secretValue.withSegment(value -> {
            String added = putValue(secretName, value, false);
            // Not found: create it with the value, or, if someone else created it meanwhile, add to theirs.
            return added != null ? added : createOrPut(secretName, value);
        });
    }

    /** {@code PutSecretValue}: the new version ID, or {@code null} if the secret does not exist and that is allowed. */
    private String putValue(String secretName, MemorySegment value, boolean mustExist) {
        try (Http.Response put = write("PutSecretValue", putPrefix(secretName), value, secretName)) {
            if (put.status() == 200) {
                return field(put.body(), VERSION_ID_FIELD, secretName);
            }
            AwsError error = AwsError.of(put);
            if (mustExist || !error.is(NOT_FOUND)) {
                throw error.exception("adding a version to", secretName);
            }
            return null;
        }
    }

    private String createOrPut(String secretName, MemorySegment value) {
        try (Http.Response create = write("CreateSecret", createPrefix(secretName), value, secretName)) {
            if (create.status() == 200) {
                return field(create.body(), VERSION_ID_FIELD, secretName);
            }
            AwsError error = AwsError.of(create);
            if (!error.is(EXISTS)) {
                throw error.exception("creating", secretName);
            }
        }
        return putValue(secretName, value, true);
    }

    private static String putPrefix(String secretName) {
        return "{\"SecretId\":\"" + secretName + "\",\"ClientRequestToken\":\"" + UUID.randomUUID() + "\"";
    }

    private String createPrefix(String secretName) {
        StringBuilder json = new StringBuilder("{\"Name\":\"").append(secretName)
                .append("\",\"ClientRequestToken\":\"").append(UUID.randomUUID()).append('"');
        if (settings.kmsKeyId() != null) {
            // Checked to be a key ID, ARN or alias, which need no escaping.
            json.append(",\"KmsKeyId\":\"").append(settings.kmsKeyId()).append('"');
        }
        List<String> replicas = settings.replicaRegions();
        if (!replicas.isEmpty()) {
            json.append(",\"AddReplicaRegions\":[");
            for (int i = 0; i < replicas.size(); i++) {
                json.append(i == 0 ? "" : ",").append("{\"Region\":\"").append(replicas.get(i)).append("\"}");
            }
            json.append(']');
        }
        return json.toString();
    }

    /** {@code prefix,"SecretString":"<escaped>"}} or {@code prefix,"SecretBinary":"<base64>"}}, in guarded memory. */
    private Http.Response write(String operation, String prefix, MemorySegment value, String secretName) {
        boolean text = Codec.isUtf8(value);
        byte[] head = (prefix + (text ? ",\"SecretString\":\"" : ",\"SecretBinary\":\""))
                .getBytes(StandardCharsets.US_ASCII);
        byte[] end = {'"', '}'};
        long encoded = text ? Codec.jsonEscapedLength(value) : Codec.base64EncodedLength(value.byteSize());
        try (Secret body = memory.allocate(head.length + encoded + end.length, out -> {
            long pos = Codec.putBytes(out, 0, head);
            pos = text ? Codec.jsonEscape(value, out, pos) : Codec.base64Encode(value, out, pos);
            Codec.putBytes(out, pos, end);
        })) {
            return body.withSegment(b -> send(operation, b, secretName, "writing"));
        }
    }

    /**
     * Closes the client: the credentials and every secret {@link #read(String, String)} returned are wiped, after
     * the callbacks running on them in other threads. Idempotent.
     */
    @Override
    public void close() {
        closed = true;
        try {
            credentials.close();
        } finally {
            try {
                memory.close();
            } finally {
                if (tls != null) {
                    tls.close();
                }
            }
        }
    }

    private void checkOpen() {
        if (closed) {
            throw new IllegalStateException("Client is closed");
        }
    }

    /** Signs and sends one operation with {@code body}. */
    private Http.Response send(String operation, MemorySegment body, String secretName, String action) {
        Http.Target api = settings.api();
        Secret request = credentials.withCredentials(c -> signer
                .sign(c, api.hostHeader(), TARGET + operation, body, clock.instant())
                .request(memory, api, body));
        try (request) {
            return Http.exchange(api, request, settings.timeouts(), memory);
        } catch (InterruptedIOException e) {
            if (e instanceof SocketTimeoutException) {
                throw new SecretManagerException("Timed out " + action + " secret '" + secretName + "'", e);
            }
            Thread.currentThread().interrupt();
            throw new SecretManagerException("Interrupted while " + action + " secret '" + secretName + "'", e);
        } catch (IOException e) {
            throw new SecretManagerException("Failed " + action + " secret '" + secretName + "': "
                    + e.getClass().getSimpleName(), e);
        }
    }

    /** {@code SecretString}, unescaped, or {@code SecretBinary}, decoded, into a new secret. */
    private Secret value(Secret body, String secretName) {
        return body.withSegment(json -> {
            try {
                Json.Obj response = Json.parse(json) instanceof Json.Obj object ? object : null;
                Json.Str string = response == null ? null : response.string("SecretString");
                Json.Str binary = response == null ? null : response.string("SecretBinary");
                if (string != null) {
                    MemorySegment raw = string.raw(json);
                    long length = Codec.unescapedLength(raw);
                    return memory.allocate(length, out -> unescape(raw, out));
                }
                if (binary != null) {
                    return decodeBase64(json, binary);
                }
                throw new SecretManagerException("No SecretString or SecretBinary in the response for secret '"
                        + secretName + "'");
            } catch (Codec.MalformedException | MalformedValue e) {
                // Not chained: nothing about the value may leave this method.
                throw new SecretManagerException("Cannot parse the response for secret '" + secretName + "' ("
                        + e.getClass().getSimpleName() + ")");
            }
        });
    }

    private static void unescape(MemorySegment raw, MemorySegment out) {
        try {
            Codec.unescape(raw, out);
        } catch (Codec.MalformedException e) {
            // Not reached: unescapedLength checked the same input.
            throw new MalformedValue(e);
        }
    }

    /** Decodes Base64 in a JSON string; a string with escapes ({@code \/}) is unescaped in guarded memory first. */
    private Secret decodeBase64(MemorySegment json, Json.Str data) throws Codec.MalformedException {
        MemorySegment raw = data.raw(json);
        long unescaped = Codec.unescapedLength(raw);
        if (unescaped == raw.byteSize()) {
            long length = Codec.base64DecodedLength(raw);
            return memory.allocate(length, out -> Codec.base64Decode(raw, out));
        }
        try (Secret base64 = memory.allocate(unescaped, out -> unescape(raw, out))) {
            return base64.withSegment(segment -> {
                try {
                    long length = Codec.base64DecodedLength(segment);
                    return memory.allocate(length, out -> Codec.base64Decode(segment, out));
                } catch (Codec.MalformedException e) {
                    throw new MalformedValue(e);
                }
            });
        }
    }

    /** Carries a {@link Codec.MalformedException} out of a callback, without a message or a cause. */
    private static final class MalformedValue extends RuntimeException {
        @java.io.Serial
        private static final long serialVersionUID = 1L;

        MalformedValue(Codec.MalformedException cause) {
            super(cause.getClass().getSimpleName(), null, false, false);
        }
    }

    /** A top-level string field of a response that holds no secret. */
    private static String field(Secret body, String name, String secretName) {
        return body.withSegment(json -> {
            try {
                if (Json.parse(json) instanceof Json.Obj object && object.string(name) != null) {
                    return Json.text(json, object.string(name));
                }
            } catch (Codec.MalformedException e) {
                throw new SecretManagerException("Cannot parse the response for secret '" + secretName + "' ("
                        + e.getMessage() + ")");
            }
            throw new SecretManagerException("No " + name + " in the response for secret '" + secretName + "'");
        });
    }

    /**
     * An AWS error: the HTTP status, {@code __type} (without a namespace before {@code #}) and {@code message}.
     * AWS error responses do not contain secret values; the body itself is never quoted.
     */
    private record AwsError(int status, String type, String message) {

        static AwsError of(Http.Response response) {
            String[] fields = response.body().withSegment(AwsError::fields);
            String type = fields[0] == null ? null : fields[0].substring(fields[0].lastIndexOf('#') + 1);
            return new AwsError(response.status(), type, fields[1]);
        }

        private static String[] fields(MemorySegment json) {
            String[] result = new String[2];
            try {
                if (Json.parse(json) instanceof Json.Obj object) {
                    if (object.string("__type") != null) {
                        result[0] = Json.text(json, object.string("__type"));
                    }
                    // JSON 1.1 services spell it either way.
                    Json.Str message = object.string(object.fields().containsKey("message") ? "message" : "Message");
                    if (message != null) {
                        result[1] = Json.text(json, message);
                    }
                }
            } catch (Codec.MalformedException _) {
                // Not an AWS error document; the HTTP status says enough.
            }
            return result;
        }

        boolean is(String errorType) {
            return errorType.equals(type);
        }

        SecretManagerException exception(String action, String secretName) {
            StringBuilder text = new StringBuilder("AWS Secrets Manager returned HTTP ").append(status);
            if (type != null) {
                text.append(' ').append(type);
            }
            text.append(" when ").append(action).append(" secret '").append(secretName).append('\'');
            if (message != null) {
                text.append(": ").append(message);
            }
            return new SecretManagerException(text.toString());
        }
    }
}
