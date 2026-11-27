package io.descoped.secrets.provider.google;

import io.descoped.secrets.api.http.Codec;
import io.descoped.secrets.api.http.Http;
import io.descoped.secrets.api.http.Json;
import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;
import io.descoped.secrets.api.tls.TlsContext;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.foreign.MemorySegment;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Google Secret Manager through its REST API (v1), on guarded memory from end to end: each request is built in
 * guarded memory with the access token, written from there, and each response read into guarded memory, where its
 * JSON is parsed and the value decoded from Base64 into the {@link Secret} that {@link #read(String, String)} returns.
 * Values carry a CRC32C checksum both ways. See {@link GoogleSecretManagerClientInitializer} for the configuration.
 */
final class GoogleSecretManagerClient implements SecretManagerClient {

    /** Secret ids as Secret Manager accepts them. */
    static final Pattern SECRET_ID = Pattern.compile("[A-Za-z0-9_-]{1,255}");

    /** Version ids: a version number or {@code latest}. */
    static final Pattern VERSION_ID = Pattern.compile("latest|[1-9]\\d{0,18}");

    private static final String SECRET_NAME = "secretName";
    private static final String SECRET_VALUE = "secretValue";
    private static final List<String> JSON = List.of("Content-Type: application/json");
    private static final byte[] DATA = "{\"payload\":{\"data\":\"".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CRC = "\",\"dataCrc32c\":\"".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] END = "\"}}".getBytes(StandardCharsets.US_ASCII);

    private final Http.Target api;
    private final String project;
    private final List<String> replicationLocations;
    private final Http.Timeouts timeouts;
    private final SecretMemory memory;
    private final AccessTokens tokens;
    private final TlsContext tls;
    private volatile boolean closed;

    GoogleSecretManagerClient(Http.Target api, String projectId, List<String> replicationLocations,
                              Http.Timeouts timeouts, SecretMemory memory, AccessTokens tokens, TlsContext tls) {
        this.api = api;
        this.project = "/v1/projects/" + projectId;
        this.replicationLocations = List.copyOf(replicationLocations);
        this.timeouts = timeouts;
        this.memory = memory;
        this.tokens = tokens;
        this.tls = tls;
    }

    @Override
    public Secret read(String secretName, String secretVersion) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        checkOpen();
        String version = secretVersion == null ? "latest" : secretVersion;
        // A name or version Secret Manager cannot hold does not exist; no request is sent for it.
        if (!SECRET_ID.matcher(secretName).matches() || !VERSION_ID.matcher(version).matches()) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        try (Http.Response response = send("GET", "/secrets/" + secretName + "/versions/" + version + ":access",
                null, secretName, "reading")) {
            if (response.status() == 404) {
                throw new SecretNotFoundException(secretName, secretVersion);
            }
            if (response.status() != 200) {
                throw failure(response, "reading", secretName);
            }
            return payload(response.body(), secretName);
        }
    }

    /**
     * Adds a version, and creates the secret first if it does not exist, with the replication from the
     * configuration. Returns the new version number. The request body is built in guarded memory.
     */
    @Override
    public String addVersion(String secretName, Secret secretValue) {
        Objects.requireNonNull(secretName, SECRET_NAME);
        Objects.requireNonNull(secretValue, SECRET_VALUE);
        checkOpen();
        if (!SECRET_ID.matcher(secretName).matches()) {
            throw new SecretManagerException("Invalid secret name '" + secretName
                    + "': Secret Manager allows 1 to 255 letters, digits, '-' and '_'");
        }
        try (Secret body = secretValue.withSegment(this::versionBody)) {
            Http.Response response = postVersion(secretName, body);
            if (response.status() == 404) {
                response.close();
                createSecret(secretName);
                response = postVersion(secretName, body);
            }
            try {
                if (response.status() != 200) {
                    throw failure(response, "adding a version to", secretName);
                }
                String name = field(response.body(), "name", secretName);
                return name.substring(name.lastIndexOf('/') + 1);
            } finally {
                response.close();
            }
        }
    }

    private Http.Response postVersion(String secretName, Secret body) {
        return send("POST", "/secrets/" + secretName + ":addVersion", body, secretName, "adding a version to");
    }

    private void createSecret(String secretName) {
        try (Secret body = memory.fromBytes(secretBody().getBytes(StandardCharsets.UTF_8));
             Http.Response response = send("POST", "/secrets?secretId=" + secretName, body, secretName,
                     "creating")) {
            // 409: created by someone else in the meantime, which is just as good.
            if (response.status() != 200 && response.status() != 409) {
                throw failure(response, "creating", secretName);
            }
        }
    }

    /**
     * Closes the client: the access token and every secret {@link #read(String, String)} returned are wiped, after
     * the callbacks running on them in other threads. Idempotent.
     */
    @Override
    public void close() {
        closed = true;
        try {
            tokens.close();
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

    /** Sends a request with the current access token, and a body in guarded memory or none. */
    private Http.Response send(String method, String path, Secret body, String secretName, String action) {
        Secret request = tokens.withToken(token -> body == null
                ? Http.request(memory, api, method, project + path, List.of(), token, null)
                : body.withSegment(b -> Http.request(memory, api, method, project + path, JSON, token, b)));
        try (request) {
            return Http.exchange(api, request, timeouts, memory);
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

    /** {@code {"payload":{"data":"<base64>","dataCrc32c":"<crc>"}}}, built in guarded memory. */
    private Secret versionBody(MemorySegment value) {
        byte[] crc = Long.toString(Codec.crc32c(value)).getBytes(StandardCharsets.US_ASCII);
        long length = DATA.length + Codec.base64EncodedLength(value.byteSize()) + CRC.length + crc.length + END.length;
        return memory.allocate(length, out -> {
            long pos = Codec.putBytes(out, 0, DATA);
            pos = Codec.base64Encode(value, out, pos);
            pos = Codec.putBytes(out, pos, CRC);
            pos = Codec.putBytes(out, pos, crc);
            Codec.putBytes(out, pos, END);
        });
    }

    /** {@code {"replication":{"automatic":{}}}}, or {@code userManaged} with the configured locations. */
    private String secretBody() {
        if (replicationLocations.isEmpty()) {
            return "{\"replication\":{\"automatic\":{}}}";
        }
        StringBuilder json = new StringBuilder("{\"replication\":{\"userManaged\":{\"replicas\":[");
        for (int i = 0; i < replicationLocations.size(); i++) {
            // Locations are checked to be [a-z0-9-]+, so they need no escaping.
            json.append(i == 0 ? "" : ",").append("{\"location\":\"").append(replicationLocations.get(i)).append("\"}");
        }
        return json.append("]}}}").toString();
    }

    /**
     * Reads {@code payload.data}, checks {@code payload.dataCrc32c} when present, and decodes the value from Base64
     * straight into a new secret.
     */
    private Secret payload(Secret body, String secretName) {
        return body.withSegment(json -> {
            Secret value = null;
            try {
                Json.Obj payload = Json.parse(json) instanceof Json.Obj object ? object.object("payload") : null;
                Json.Str data = payload == null ? null : payload.string("data");
                if (data == null) {
                    throw new SecretManagerException("No payload.data in the response for secret '" + secretName
                            + "'");
                }
                value = decode(json, data);
                Json.Str crc = payload.string("dataCrc32c");
                if (crc != null) {
                    long expected = Long.parseLong(Json.text(json, crc));
                    if (value.withSegment(Codec::crc32c) != expected) {
                        throw new SecretManagerException("Checksum mismatch in the response for secret '"
                                + secretName + "'");
                    }
                }
                Secret result = value;
                value = null;
                return result;
            } catch (Codec.MalformedException | NumberFormatException e) {
                // Not chained: nothing about the value may leave this method.
                throw new SecretManagerException("Cannot parse the response for secret '" + secretName + "' ("
                        + e.getClass().getSimpleName() + ")");
            } finally {
                if (value != null) {
                    value.close();
                }
            }
        });
    }

    /** Decodes the Base64 in a JSON string into a new secret; escaped content is unescaped in guarded memory first. */
    private Secret decode(MemorySegment json, Json.Str data) throws Codec.MalformedException {
        MemorySegment raw = data.raw(json);
        if (Codec.unescapedLength(raw) == raw.byteSize()) {
            return decodeBase64(raw);
        }
        try (Secret unescaped = AccessTokens.unescaped(memory, json, data)) {
            return unescaped.withSegment(segment -> {
                try {
                    return decodeBase64(segment);
                } catch (Codec.MalformedException e) {
                    throw new MalformedValue(e);
                }
            });
        } catch (MalformedValue e) {
            throw e.cause;
        }
    }

    private Secret decodeBase64(MemorySegment base64) throws Codec.MalformedException {
        long length = Codec.base64DecodedLength(base64);
        return memory.allocate(length, out -> Codec.base64Decode(base64, out));
    }

    /** Carries a {@link Codec.MalformedException} out of a callback. */
    private static final class MalformedValue extends RuntimeException {
        @java.io.Serial
        private static final long serialVersionUID = 1L;
        private final transient Codec.MalformedException cause;

        MalformedValue(Codec.MalformedException cause) {
            super(null, null, false, false);
            this.cause = cause;
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
     * An error with the status and Google's error status and message ({@code error.status}, {@code error.message});
     * Google's error responses do not contain secret values. Never the raw body.
     */
    private static SecretManagerException failure(Http.Response response, String action, String secretName) {
        StringBuilder text = new StringBuilder("Google Secret Manager returned HTTP ").append(response.status());
        String[] error = response.body().withSegment(GoogleSecretManagerClient::googleError);
        if (error[0] != null) {
            text.append(' ').append(error[0]);
        }
        text.append(" when ").append(action).append(" secret '").append(secretName).append('\'');
        if (error[1] != null) {
            text.append(": ").append(error[1]);
        }
        return new SecretManagerException(text.toString());
    }

    /** {@code error.status} and {@code error.message} when they are strings, else {@code null}s. */
    private static String[] googleError(MemorySegment json) {
        String[] result = new String[2];
        try {
            if (Json.parse(json) instanceof Json.Obj object && object.object("error") != null) {
                Json.Obj error = object.object("error");
                if (error.string("status") != null) {
                    result[0] = Json.text(json, error.string("status"));
                }
                if (error.string("message") != null) {
                    result[1] = Json.text(json, error.string("message"));
                }
            }
        } catch (Codec.MalformedException _) {
            // Not a Google error document; the HTTP status says enough.
        }
        return result;
    }
}
