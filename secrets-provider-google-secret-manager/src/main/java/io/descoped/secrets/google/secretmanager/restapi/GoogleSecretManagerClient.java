package io.descoped.secrets.google.secretmanager.restapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.ComputeEngineCredentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A client for Google Secret Manager, through its REST API.
 */
public class GoogleSecretManagerClient implements SecretManagerClient {

    static final ObjectMapper mapper = new ObjectMapper();
    private final String projectId;
    private final HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).build();
    private final AccessToken accessToken;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    // uses compute-engine
    /**
     * Authenticates with the Compute Engine credentials of the environment.
     *
     * @param projectId the Google Cloud project
     */
    public GoogleSecretManagerClient(String projectId) {
        this.projectId = projectId;
        GoogleCredentials credentials = ComputeEngineCredentials.create();
        GoogleCredentials scopedCredentials = credentials.createScoped("https://www.googleapis.com/auth/cloud-platform");
        this.accessToken = getAccessToken(scopedCredentials);
    }

    // uses service-account
    /**
     * Authenticates with a service-account key file.
     *
     * @param projectId             the Google Cloud project
     * @param serviceAccountKeyPath the service-account JSON key file
     */
    public GoogleSecretManagerClient(String projectId, String serviceAccountKeyPath) {
        this.projectId = projectId;
        GoogleCredentials credentials = getServiceAccountCredentials(serviceAccountKeyPath);
        GoogleCredentials scopedCredentials = credentials.createScoped("https://www.googleapis.com/auth/cloud-platform");
        this.accessToken = getAccessToken(scopedCredentials);
    }

    GoogleCredentials getServiceAccountCredentials(String serviceAccountKeyPath) {
        try (var in = Files.newInputStream(Paths.get(serviceAccountKeyPath), StandardOpenOption.READ)) {
            return ServiceAccountCredentials.fromStream(in);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read the service-account key " + serviceAccountKeyPath, e);
        }
    }

    AccessToken getAccessToken(GoogleCredentials scopedCredentials) {
        try {
            return scopedCredentials.refreshAccessToken();
        } catch (IOException e) {
            throw new SecretManagerException("Cannot get a Google access token", e);
        }
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        if (closed.get()) {
            throw new IllegalStateException("Client is closed");
        }
        Objects.requireNonNull(secretName, "secretName");
        try {
            String accessToken = String.format("Bearer %s", this.accessToken.getTokenValue());
            URI uri = URI.create(String.format("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/%s:access",
                    projectId, secretName, secretVersion == null ? "latest" : secretVersion));

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(uri)
                    .header("Authorization", accessToken)
                    .header("Content-Type", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404) {
                throw new SecretNotFoundException(secretName, secretVersion);
            }
            if (response.statusCode() != 200) {
                throw new SecretManagerException(String.format("Error (%s) reading secret '%s'", response.statusCode(), secretName));
            }

            try {
                JsonNode responseNode = mapper.readTree(response.body());
                if (!responseNode.has("payload") || !responseNode.get("payload").has("data")) {
                    throw new SecretManagerException("No payload.data in the response for secret '" + secretName + "'");
                }
                return responseNode.get("payload").get("data").binaryValue();

            } catch (IOException e) {
                throw new SecretManagerException("Cannot parse the response for secret '" + secretName + "'", e);
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SecretManagerException("Interrupted while reading secret '" + secretName + "'", e);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read secret '" + secretName + "'", e);
        }
    }

    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        if (closed.get()) {
            throw new IllegalStateException("Client is closed");
        }
        Objects.requireNonNull(secretName, "secretName");
        Objects.requireNonNull(secretValue, "secretValue");
        try {
            HttpResponse<String> checkSecretResponse;
            {
                String accessToken = String.format("Bearer %s", this.accessToken.getTokenValue());
                URI uri = URI.create(String.format("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s",
                        projectId, secretName));

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(uri)
                        .header("Authorization", accessToken)
                        .GET()
                        .build();

                checkSecretResponse = client.send(request, HttpResponse.BodyHandlers.ofString());
            }
            if (checkSecretResponse.statusCode() == 200) {
                // already exists, do nothing
            } else if (checkSecretResponse.statusCode() == 404) {
                ObjectNode secret = mapper.createObjectNode();
                ObjectNode replication = secret.putObject("replication");
                ObjectNode userManaged = replication.putObject("userManaged");
                ArrayNode arrayNode = userManaged.putArray("replicas");
                ObjectNode replica = arrayNode.addObject();
                replica.put("location", "europe-north1");

                String accessToken = String.format("Bearer %s", this.accessToken.getTokenValue());
                URI uri = URI.create(String.format("https://secretmanager.googleapis.com/v1/projects/%s/secrets?secretId=%s",
                        URLEncoder.encode(projectId, StandardCharsets.UTF_8),
                        URLEncoder.encode(secretName, StandardCharsets.UTF_8)
                ));

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(uri)
                        .header("Authorization", accessToken)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(secret.toString()))
                        .build();

                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new SecretManagerException(String.format("Error (%s) creating secret '%s'", response.statusCode(), secretName));
                }
            } else {
                throw new SecretManagerException(String.format("Error (%s) checking secret '%s'", checkSecretResponse.statusCode(), secretName));
            }
            {
                ObjectNode secretVersion = mapper.createObjectNode();
                ObjectNode payload = secretVersion.putObject("payload");
                payload.put("data", secretValue);

                String accessToken = String.format("Bearer %s", this.accessToken.getTokenValue());
                URI uri = URI.create(String.format("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s:addVersion",
                        URLEncoder.encode(projectId, StandardCharsets.UTF_8),
                        URLEncoder.encode(secretName, StandardCharsets.UTF_8)
                ));

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(uri)
                        .header("Authorization", accessToken)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(secretVersion.toString()))
                        .build();

                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new SecretManagerException(String.format("Error (%s) adding a version to secret '%s'", response.statusCode(), secretName));
                }

                JsonNode responseSecretVersion = mapper.readTree(response.body());
                String versionUrl = responseSecretVersion.get("name").textValue();
                String[] versionPathElements = versionUrl.split("/");
                return versionPathElements[versionPathElements.length - 1];
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SecretManagerException("Interrupted while adding a version to secret '" + secretName + "'", e);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot add a version to secret '" + secretName + "'", e);
        }
    }

    @Override
    public void close() {
        closed.compareAndSet(false, true);
    }
}
