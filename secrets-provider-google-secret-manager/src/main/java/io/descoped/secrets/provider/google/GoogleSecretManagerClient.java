package io.descoped.secrets.provider.google;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.google.auth.oauth2.GoogleCredentials;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
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
    static final Pattern VERSION_ID = Pattern.compile("latest|[1-9][0-9]{0,18}");

    private static final JsonFactory JSON = new JsonFactory();

    /**
     * What a client needs to make requests; {@code null} once closed, so the credentials and their token are dropped.
     */
    private record Session(HttpClient http, GoogleCredentials credentials) {
    }

    private final URI projectUri;
    private final List<String> replicationLocations;
    private final Duration requestTimeout;
    private volatile Session session;

    GoogleSecretManagerClient(URI endpoint, String projectId, GoogleCredentials credentials,
                              List<String> replicationLocations, Duration connectTimeout, Duration requestTimeout) {
        String base = endpoint.toString().replaceAll("/+$", "");
        this.projectUri = URI.create(base + "/v1/projects/" + projectId);
        this.replicationLocations = List.copyOf(replicationLocations);
        this.requestTimeout = requestTimeout;
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
     * Drops the HTTP client and the credentials with their access token. Idempotent.
     */
    @Override
    public void close() {
        session = null;
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
        try (JsonGenerator json = JSON.createGenerator(out)) {
            json.writeStartObject();
            json.writeObjectFieldStart("replication");
            if (replicationLocations.isEmpty()) {
                json.writeObjectFieldStart("automatic");
                json.writeEndObject();
            } else {
                json.writeObjectFieldStart("userManaged");
                json.writeArrayFieldStart("replicas");
                for (String location : replicationLocations) {
                    json.writeStartObject();
                    json.writeStringField("location", location);
                    json.writeEndObject();
                }
                json.writeEndArray();
                json.writeEndObject();
            }
            json.writeEndObject();
            json.writeEndObject();
        } catch (IOException e) {
            throw new SecretManagerException("Cannot build the request", e);
        }
        return out.toByteArray();
    }

    /**
     * Reads {@code payload.data} (and checks {@code payload.dataCrc32c} when present) with the streaming parser, so
     * the value is decoded from Base64 straight into bytes.
     */
    private static byte[] payload(byte[] body, String secretName) {
        byte[] data = null;
        Long expectedCrc = null;
        try (JsonParser json = JSON.createParser(body)) {
            if (json.nextToken() != JsonToken.START_OBJECT) {
                throw malformed(secretName);
            }
            while (json.nextToken() == JsonToken.FIELD_NAME) {
                String field = json.currentName();
                json.nextToken();
                if ("payload".equals(field) && json.currentToken() == JsonToken.START_OBJECT) {
                    while (json.nextToken() == JsonToken.FIELD_NAME) {
                        String inner = json.currentName();
                        json.nextToken();
                        if ("data".equals(inner)) {
                            data = json.getBinaryValue();
                        } else if ("dataCrc32c".equals(inner)) {
                            expectedCrc = Long.parseLong(json.getValueAsString());
                        } else {
                            json.skipChildren();
                        }
                    }
                } else {
                    json.skipChildren();
                }
            }
        } catch (IOException | NumberFormatException e) {
            wipe(data);
            throw new SecretManagerException("Cannot parse the response for secret '" + secretName + "'", e);
        }
        if (data == null) {
            throw malformed(secretName);
        }
        if (expectedCrc != null && expectedCrc != crc32c(data)) {
            wipe(data);
            throw new SecretManagerException("Checksum mismatch in the response for secret '" + secretName + "'");
        }
        return data;
    }

    private static SecretManagerException malformed(String secretName) {
        return new SecretManagerException("No payload.data in the response for secret '" + secretName + "'");
    }

    /**
     * A top-level string field of a JSON response that holds no secret.
     */
    private static String field(byte[] body, String name, String secretName) {
        try (JsonParser json = JSON.createParser(body)) {
            if (json.nextToken() == JsonToken.START_OBJECT) {
                while (json.nextToken() == JsonToken.FIELD_NAME) {
                    String field = json.currentName();
                    json.nextToken();
                    if (name.equals(field) && json.currentToken() == JsonToken.VALUE_STRING) {
                        return json.getText();
                    }
                    json.skipChildren();
                }
            }
        } catch (IOException e) {
            throw new SecretManagerException("Cannot parse the response for secret '" + secretName + "'", e);
        }
        throw new SecretManagerException("No " + name + " in the response for secret '" + secretName + "'");
    }

    /**
     * An error with the status and Google's error status and message ({@code error.status}, {@code error.message});
     * Google's error responses do not contain secret values. Never the raw body.
     */
    private static SecretManagerException failure(int statusCode, byte[] body, String action, String secretName) {
        String status = null;
        String message = null;
        try (JsonParser json = JSON.createParser(body)) {
            if (json.nextToken() == JsonToken.START_OBJECT) {
                while (json.nextToken() == JsonToken.FIELD_NAME) {
                    String field = json.currentName();
                    json.nextToken();
                    if ("error".equals(field) && json.currentToken() == JsonToken.START_OBJECT) {
                        while (json.nextToken() == JsonToken.FIELD_NAME) {
                            String inner = json.currentName();
                            json.nextToken();
                            if ("status".equals(inner)) {
                                status = json.getValueAsString();
                            } else if ("message".equals(inner)) {
                                message = json.getValueAsString();
                            } else {
                                json.skipChildren();
                            }
                        }
                    } else {
                        json.skipChildren();
                    }
                }
            }
        } catch (IOException ignored) {
            // Not a Google error document; the HTTP status says enough.
        }
        StringBuilder text = new StringBuilder("Google Secret Manager returned HTTP ").append(statusCode);
        if (status != null) {
            text.append(' ').append(status);
        }
        text.append(" when ").append(action).append(" secret '").append(secretName).append('\'');
        if (message != null) {
            text.append(": ").append(message);
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
