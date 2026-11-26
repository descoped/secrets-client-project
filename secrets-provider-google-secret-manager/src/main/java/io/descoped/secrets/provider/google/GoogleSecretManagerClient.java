package io.descoped.secrets.provider.google;

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.json.JsonFactory;
import com.google.auth.oauth2.GoogleCredentials;
import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.zip.CRC32C;

/**
 * Google Secret Manager through its REST API (v1). Requests are authorized with the credentials' current access token,
 * which google-auth refreshes before it expires. Secret values travel as bytes, with a CRC32C checksum both ways, and
 * are never turned into strings. See {@link GoogleSecretManagerClientInitializer} for the configuration.
 */
final class GoogleSecretManagerClient implements SecretManagerClient {

    /**
     * Secret ids as Secret Manager accepts them.
     */
    static final Pattern SECRET_ID = Pattern.compile("[A-Za-z0-9_-]{1,255}");

    /**
     * Version ids: a version number or {@code latest}.
     */
    static final Pattern VERSION_ID = Pattern.compile("latest|[1-9]\\d{0,18}");

    private static final JsonFactory JSON = new JsonFactory();

    /**
     * What a client needs to make requests; {@code null} once closed, so the credentials and their token are dropped.
     */
    private record Session(HttpClient http, GoogleCredentials credentials) {
    }

    private final URI projectUri;
    private final List<String> replicationLocations;
    private final Duration requestTimeout;
    private final Map<String, String> memorySettings;
    private volatile Session session;
    /**
     * Guarded memory for {@link #read(String, String)}, created by its first call so that a client that never calls
     * it needs no native access; under {@code this}.
     */
    private SecretMemory memory;

    GoogleSecretManagerClient(URI endpoint, String projectId, GoogleCredentials credentials,
                              List<String> replicationLocations, Duration connectTimeout, Duration requestTimeout,
                              Map<String, String> memorySettings) {
        String base = endpoint.toString();
        int end = base.length();
        while (end > 0 && base.charAt(end - 1) == '/') {
            end--;
        }
        base = base.substring(0, end);
        this.projectUri = URI.create(base + "/v1/projects/" + projectId);
        this.replicationLocations = List.copyOf(replicationLocations);
        this.requestTimeout = requestTimeout;
        this.memorySettings = Map.copyOf(memorySettings);
        this.session = new Session(HttpClient.newBuilder().connectTimeout(connectTimeout).build(), credentials);
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        Objects.requireNonNull(secretName, "secretName");
        Session current = open();
        String version = secretVersion == null ? "latest" : secretVersion;
        // A name or version Secret Manager cannot hold does not exist; no request is sent for it.
        if (!SECRET_ID.matcher(secretName).matches() || !VERSION_ID.matcher(version).matches()) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        HttpResponse<byte[]> response = send(current, request(
                projectUri + "/secrets/" + secretName + "/versions/" + version + ":access").GET(), secretName,
                "reading");
        byte[] body = response.body();
        try {
            if (response.statusCode() == 404) {
                throw new SecretNotFoundException(secretName, secretVersion);
            }
            if (response.statusCode() != 200) {
                throw failure(response.statusCode(), body, "reading", secretName);
            }
            return payload(body, secretName);
        } finally {
            Arrays.fill(body, (byte) 0);
        }
    }

    /**
     * The value read as {@link #readBytes(String, String)} reads it, then copied into guarded memory and wiped from
     * the heap. The response body is wiped too; the HTTP client's own buffers are not reachable. Until this provider
     * is rebuilt on guarded memory, the value is on the heap on the way.
     */
    @Override
    public Secret read(String secretName, String secretVersion) {
        SecretMemory guarded = guardedMemory();
        return guarded.fromBytes(readBytes(secretName, secretVersion));
    }

    private synchronized SecretMemory guardedMemory() {
        open();
        if (memory == null) {
            memory = SecretMemory.create(memorySettings);
        }
        return memory;
    }

    /**
     * Adds a version, and creates the secret first if it does not exist, with the replication from the
     * configuration. Returns the new version number.
     */
    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        Objects.requireNonNull(secretName, "secretName");
        Objects.requireNonNull(secretValue, "secretValue");
        Session current = open();
        checkName(secretName);
        byte[] body = versionBody(secretValue);
        try {
            HttpResponse<byte[]> response = postVersion(current, secretName, body);
            if (response.statusCode() == 404) {
                createSecret(current, secretName);
                response = postVersion(current, secretName, body);
            }
            if (response.statusCode() != 200) {
                throw failure(response.statusCode(), response.body(), "adding a version to", secretName);
            }
            String name = field(response.body(), "name", secretName);
            return name.substring(name.lastIndexOf('/') + 1);
        } finally {
            Arrays.fill(body, (byte) 0);
        }
    }

    /**
     * Drops the HTTP client and the credentials with their access token, and closes the secrets
     * {@link #read(String, String)} returned. Idempotent.
     */
    @Override
    public void close() {
        session = null;
        SecretMemory guarded;
        synchronized (this) {
            guarded = memory;
            memory = null;
        }
        if (guarded != null) {
            guarded.close();
        }
    }

    private Session open() {
        Session current = session;
        if (current == null) {
            throw new IllegalStateException("Client is closed");
        }
        return current;
    }

    private static void checkName(String secretName) {
        if (!SECRET_ID.matcher(secretName).matches()) {
            throw new SecretManagerException("Invalid secret name '" + secretName
                    + "': Secret Manager allows 1 to 255 letters, digits, '-' and '_'");
        }
    }

    private HttpResponse<byte[]> postVersion(Session current, String secretName, byte[] body) {
        return send(current, request(projectUri + "/secrets/" + secretName + ":addVersion")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body)), secretName, "adding a version to");
    }

    private void createSecret(Session current, String secretName) {
        HttpResponse<byte[]> response = send(current, request(projectUri + "/secrets?secretId=" + secretName)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(secretBody())), secretName, "creating");
        // 409: created by someone else in the meantime, which is just as good.
        if (response.statusCode() != 200 && response.statusCode() != 409) {
            throw failure(response.statusCode(), response.body(), "creating", secretName);
        }
    }

    private HttpRequest.Builder request(String uri) {
        return HttpRequest.newBuilder(URI.create(uri)).timeout(requestTimeout);
    }

    private static HttpResponse<byte[]> send(Session current, HttpRequest.Builder builder, String secretName,
                                             String action) {
        try {
            HttpRequest unsigned = builder.copy().build();
            Map<String, List<String>> metadata = current.credentials().getRequestMetadata(unsigned.uri());
            metadata.forEach((name, values) -> values.forEach(value -> builder.header(name, value)));
            return current.http().send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SecretManagerException("Interrupted while " + action + " secret '" + secretName + "'", e);
        } catch (IOException e) {
            throw new SecretManagerException("Failed " + action + " secret '" + secretName + "': "
                    + e.getClass().getSimpleName(), e);
        }
    }

    /**
     * {@code {"payload":{"data":"<base64>","dataCrc32c":"<crc>"}}}, built as bytes so the value never becomes a
     * string.
     */
    private static byte[] versionBody(byte[] value) {
        byte[] encoded = Base64.getEncoder().encode(value);
        byte[] prefix = "{\"payload\":{\"data\":\"".getBytes(StandardCharsets.US_ASCII);
        byte[] suffix = ("\",\"dataCrc32c\":\"" + crc32c(value) + "\"}}").getBytes(StandardCharsets.US_ASCII);
        byte[] body = new byte[prefix.length + encoded.length + suffix.length];
        System.arraycopy(prefix, 0, body, 0, prefix.length);
        System.arraycopy(encoded, 0, body, prefix.length, encoded.length);
        System.arraycopy(suffix, 0, body, prefix.length + encoded.length, suffix.length);
        Arrays.fill(encoded, (byte) 0);
        return body;
    }

    /**
     * {@code {"replication":{"automatic":{}}}}, or {@code userManaged} with the configured locations.
     */
    private byte[] secretBody() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (JsonGenerator json = JSON.createGenerator(ObjectWriteContext.empty(), out)) {
            json.writeStartObject();
            json.writeObjectPropertyStart("replication");
            if (replicationLocations.isEmpty()) {
                json.writeObjectPropertyStart("automatic");
                json.writeEndObject();
            } else {
                json.writeObjectPropertyStart("userManaged");
                json.writeArrayPropertyStart("replicas");
                for (String location : replicationLocations) {
                    json.writeStartObject();
                    json.writeStringProperty("location", location);
                    json.writeEndObject();
                }
                json.writeEndArray();
                json.writeEndObject();
            }
            json.writeEndObject();
            json.writeEndObject();
        } catch (JacksonException e) {
            throw new SecretManagerException("Cannot build the request", e);
        }
        return out.toByteArray();
    }

    /**
     * Reads {@code payload.data} (and checks {@code payload.dataCrc32c} when present) with the streaming parser, so
     * the value is decoded from Base64 straight into bytes.
     */
    private static byte[] payload(byte[] body, String secretName) {
        Payload payload = new Payload();
        try (JsonParser json = JSON.createParser(ObjectReadContext.empty(), body)) {
            if (json.nextToken() != JsonToken.START_OBJECT) {
                throw malformed(secretName);
            }
            readObject(json, (field, value) -> {
                if ("payload".equals(field) && value.currentToken() == JsonToken.START_OBJECT) {
                    readObject(value, payload::read);
                } else {
                    value.skipChildren();
                }
            });
        } catch (JacksonException | NumberFormatException e) {
            wipe(payload.data);
            // Not chained: the parser's message can quote the token it stopped at, which may be part of the value.
            throw new SecretManagerException("Cannot parse the response for secret '" + secretName + "' ("
                    + e.getClass().getSimpleName() + ")");
        }
        if (payload.data == null) {
            throw malformed(secretName);
        }
        if (payload.crc32c != null && payload.crc32c != crc32c(payload.data)) {
            wipe(payload.data);
            throw new SecretManagerException("Checksum mismatch in the response for secret '" + secretName + "'");
        }
        return payload.data;
    }

    /**
     * The fields of {@code payload} that a secret version response is read for.
     */
    private static final class Payload {
        private byte[] data;
        private Long crc32c;

        void read(String field, JsonParser json) {
            if ("data".equals(field)) {
                wipe(data);
                data = json.getBinaryValue();
            } else if ("dataCrc32c".equals(field)) {
                crc32c = Long.parseLong(json.getValueAsString());
            } else {
                json.skipChildren();
            }
        }
    }

    /**
     * The fields of {@code error} in a Google error response.
     */
    private static final class GoogleError {
        private String status;
        private String message;

        void read(String field, JsonParser json) {
            if (json.currentToken().isStructStart()) {
                // Not the documented string: skip the whole value so the parser keeps its place.
                json.skipChildren();
            } else if ("status".equals(field)) {
                status = json.getValueAsString();
            } else if ("message".equals(field)) {
                message = json.getValueAsString();
            } else {
                json.skipChildren();
            }
        }
    }

    /**
     * Reads one field of a JSON object; the parser is at the field's value.
     */
    @FunctionalInterface
    private interface FieldReader {
        void read(String field, JsonParser json);
    }

    /**
     * Calls {@code reader} for every field of the object the parser has just entered, with the parser at the value.
     * The reader consumes the value, or skips it with {@link JsonParser#skipChildren()}.
     */
    private static void readObject(JsonParser json, FieldReader reader) {
        while (json.nextToken() == JsonToken.PROPERTY_NAME) {
            String field = json.currentName();
            json.nextToken();
            reader.read(field, json);
        }
    }

    private static SecretManagerException malformed(String secretName) {
        return new SecretManagerException("No payload.data in the response for secret '" + secretName + "'");
    }

    /**
     * A top-level string field of a JSON response that holds no secret.
     */
    private static String field(byte[] body, String name, String secretName) {
        String[] found = new String[1];
        try (JsonParser json = JSON.createParser(ObjectReadContext.empty(), body)) {
            if (json.nextToken() == JsonToken.START_OBJECT) {
                readObject(json, (field, value) -> {
                    if (found[0] == null && name.equals(field) && value.currentToken() == JsonToken.VALUE_STRING) {
                        found[0] = value.getString();
                    } else {
                        value.skipChildren();
                    }
                });
            }
        } catch (JacksonException e) {
            throw new SecretManagerException("Cannot parse the response for secret '" + secretName + "'", e);
        }
        if (found[0] == null) {
            throw new SecretManagerException("No " + name + " in the response for secret '" + secretName + "'");
        }
        return found[0];
    }

    /**
     * An error with the status and Google's error status and message ({@code error.status}, {@code error.message});
     * Google's error responses do not contain secret values. Never the raw body.
     */
    private static SecretManagerException failure(int statusCode, byte[] body, String action, String secretName) {
        GoogleError error = new GoogleError();
        try (JsonParser json = JSON.createParser(ObjectReadContext.empty(), body)) {
            if (json.nextToken() == JsonToken.START_OBJECT) {
                readObject(json, (field, value) -> {
                    if ("error".equals(field) && value.currentToken() == JsonToken.START_OBJECT) {
                        readObject(value, error::read);
                    } else {
                        value.skipChildren();
                    }
                });
            }
        } catch (JacksonException ignored) {
            // Not a Google error document; the HTTP status says enough.
        }
        StringBuilder text = new StringBuilder("Google Secret Manager returned HTTP ").append(statusCode);
        if (error.status != null) {
            text.append(' ').append(error.status);
        }
        text.append(" when ").append(action).append(" secret '").append(secretName).append('\'');
        if (error.message != null) {
            text.append(": ").append(error.message);
        }
        return new SecretManagerException(text.toString());
    }

    static long crc32c(byte[] data) {
        CRC32C crc = new CRC32C();
        crc.update(data);
        return crc.getValue();
    }

    private static void wipe(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }
}
