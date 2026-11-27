package io.descoped.secrets.provider.aws.test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A local stand-in for AWS Secrets Manager, over http or https: {@code GetSecretValue}, {@code PutSecretValue} and
 * {@code CreateSecret} on an in-memory store with versions and staging labels, as AWS keeps them. Every request's
 * SigV4 signature is checked with {@link SigV4Reference}; a wrong one is refused as AWS refuses it.
 */
final class FakeAws implements AutoCloseable {

    static final String ACCESS_KEY_ID = "AKIDEXAMPLE";
    static final String REGION = "eu-north-1";

    /** A request the fake received. */
    record Request(String target, String body, Map<String, String> headers) {

        Map<String, Object> json() {
            return TestJson.object(body);
        }
    }

    /** A canned response, sent instead of the store's answer. */
    record Response(int status, String body, boolean chunked, long delayMillis) {

        Response(int status, String body) {
            this(status, body, false, 0);
        }

        Response asChunks() {
            return new Response(status, body, true, delayMillis);
        }

        Response delayed(long millis) {
            return new Response(status, body, chunked, millis);
        }
    }

    /** A version: a string or a binary value. */
    record Version(String id, String string, byte[] binary) {
    }

    /** A secret: its versions by ID, and which version each staging label is on. */
    static final class StoredSecret {
        final Map<String, Version> versions = new LinkedHashMap<>();
        final Map<String, String> stages = new HashMap<>();

        List<String> stagesOf(String versionId) {
            return stages.entrySet().stream().filter(e -> e.getValue().equals(versionId)).map(Map.Entry::getKey)
                    .sorted().toList();
        }
    }

    private static final Pattern AUTHORIZATION = Pattern.compile(
            "AWS4-HMAC-SHA256 Credential=([^/]+)/(\\d{8})/([^/]+)/([^/]+)/aws4_request, "
                    + "SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})");

    private final HttpServer server;
    private final boolean tls;
    private final ExecutorService executor = Executors.newFixedThreadPool(8);
    final Map<String, StoredSecret> secrets = new ConcurrentHashMap<>();
    final List<Request> requests = new CopyOnWriteArrayList<>();
    private final Map<String, List<Response>> canned = new ConcurrentHashMap<>();
    /** The secret access key the signatures must be made with. */
    volatile String secretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    /** The session token requests must carry and sign, or {@code null} for long-term keys. */
    volatile String sessionToken;
    /** Whether {@code /} in {@code SecretBinary} is sent escaped ({@code \/}), as JSON allows. */
    volatile boolean escapeSlashes;
    /** The authorization token the container endpoint requires, or {@code null} for none (the ECS task role). */
    volatile String containerToken;
    /** The session token IMDS issues. */
    volatile String instanceToken = "AQAEAInstanceToken==";
    /** A session token IMDS issues but does not accept, or {@code null} to issue the one it accepts. */
    volatile String issuedInstanceToken;
    /** How long the temporary credentials the container endpoint and IMDS issue are valid. */
    volatile Duration credentialsLifetime = Duration.ofHours(6);
    /** Whether the credentials document has an expiration that is not a timestamp. */
    volatile boolean malformedExpiration;
    /** The requests to the container endpoint and IMDS: method, path and the token header they carried. */
    final List<String> credentialRequests = new CopyOnWriteArrayList<>();

    static final String CONTAINER_PATH = "/v2/credentials/task-1";
    static final String ROLE = "app-role";
    private static final String IMDS_TOKEN = "/latest/api/token";
    private static final String IMDS_ROLES = "/latest/meta-data/iam/security-credentials/";

    FakeAws() throws IOException {
        this(null);
    }

    /** Serves https with {@code context} when it is not {@code null}. */
    FakeAws(SSLContext context) throws IOException {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        if (context == null) {
            server = HttpServer.create(address, 0);
        } else {
            HttpsServer https = HttpsServer.create(address, 0);
            https.setHttpsConfigurator(new HttpsConfigurator(context));
            server = https;
        }
        tls = context != null;
        server.createContext("/", this::handle);
        server.setExecutor(executor);
        server.start();
    }

    String endpoint() {
        return (tls ? "https" : "http") + "://127.0.0.1:" + server.getAddress().getPort();
    }

    /** Answers the operation (such as {@code GetSecretValue}) with these responses, one per request, the last repeated. */
    void on(String operation, Response... answers) {
        canned.put(operation, new ArrayList<>(List.of(answers)));
    }

    List<Request> requests(String operation) {
        return requests.stream().filter(r -> r.target().equals("secretsmanager." + operation)).toList();
    }

    /** Stores a version as {@code AWSCURRENT}, the previous current one becoming {@code AWSPREVIOUS}. */
    synchronized Version put(String name, String versionId, String string, byte[] binary) {
        StoredSecret secret = secrets.computeIfAbsent(name, n -> new StoredSecret());
        Version existing = secret.versions.get(versionId);
        if (existing != null) {
            return existing;
        }
        Version version = new Version(versionId, string, binary);
        secret.versions.put(versionId, version);
        String current = secret.stages.get("AWSCURRENT");
        if (current != null) {
            secret.stages.put("AWSPREVIOUS", current);
        }
        secret.stages.put("AWSCURRENT", versionId);
        return version;
    }

    /** Writes a shared credentials file with this fake's keys in {@code profile}, after another profile. */
    Path credentialsFile(Path dir, String profile) throws IOException {
        Path file = dir.resolve("credentials");
        String text = "# AWS credentials\n[other]\naws_access_key_id = AKIDOTHER\naws_secret_access_key = other\n\n"
                + "[" + profile + "]\r\naws_access_key_id=" + ACCESS_KEY_ID + "\r\n"
                + "  aws_secret_access_key =\t" + secretAccessKey + "  \r\n"
                + (sessionToken == null ? "" : "aws_session_token = " + sessionToken + "\n")
                + "region = " + REGION + "\n";
        Files.writeString(file, text);
        return file;
    }

    private void handle(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        Map<String, String> headers = new HashMap<>();
        exchange.getRequestHeaders().forEach((name, values) -> headers.put(name.toLowerCase(), values.get(0)));
        String path = exchange.getRequestURI().getRawPath();
        if (path.equals(CONTAINER_PATH) || path.startsWith("/latest/")) {
            send(exchange, credentials(exchange.getRequestMethod(), path, headers));
            return;
        }
        String target = headers.getOrDefault("x-amz-target", "");
        requests.add(new Request(target, new String(body, StandardCharsets.UTF_8), headers));
        String refusal = verify(exchange, headers, body);
        if (refusal != null) {
            send(exchange, error(403, "InvalidSignatureException", refusal));
            return;
        }
        String operation = target.substring(target.indexOf('.') + 1);
        List<Response> answers = canned.get(operation);
        if (answers != null && !answers.isEmpty()) {
            Response response;
            synchronized (answers) {
                response = answers.size() > 1 ? answers.remove(0) : answers.get(0);
            }
            send(exchange, response);
            return;
        }
        Map<String, Object> json = TestJson.object(new String(body, StandardCharsets.UTF_8));
        send(exchange, switch (operation) {
            case "GetSecretValue" -> get(json);
            case "PutSecretValue" -> putValue(json);
            case "CreateSecret" -> create(json);
            default -> error(400, "UnknownOperationException", "No operation " + operation);
        });
    }

    /** The container credentials endpoint and IMDSv2 (IMDSv1, without a token, is refused, as when it is off). */
    private Response credentials(String method, String path, Map<String, String> headers) {
        String imdsToken = headers.get("x-aws-ec2-metadata-token");
        credentialRequests.add(method + " " + path + " " + (path.equals(CONTAINER_PATH)
                ? headers.get("authorization") : imdsToken));
        if (path.equals(CONTAINER_PATH)) {
            if (containerToken != null && !containerToken.equals(headers.get("authorization"))) {
                return new Response(403, "{\"Message\":\"Forbidden\"}");
            }
            return new Response(200, credentialsDocument(false));
        }
        if (method.equals("PUT") && path.equals(IMDS_TOKEN)) {
            return headers.containsKey("x-aws-ec2-metadata-token-ttl-seconds")
                    ? new Response(200, issuedInstanceToken != null ? issuedInstanceToken : instanceToken)
                    : new Response(400, "Missing TTL");
        }
        if (!method.equals("GET") || !instanceToken.equals(imdsToken)) {
            return new Response(401, "Unauthorized");
        }
        if (path.equals(IMDS_ROLES)) {
            return new Response(200, ROLE + "\n");
        }
        if (path.equals(IMDS_ROLES + ROLE)) {
            return new Response(200, credentialsDocument(true));
        }
        return new Response(404, "Not Found");
    }

    private String credentialsDocument(boolean instance) {
        String expiration = malformedExpiration ? "soon" : Instant.now().plus(credentialsLifetime)
                .truncatedTo(ChronoUnit.SECONDS).toString();
        return "{" + (instance ? "\"Code\":\"Success\",\"Type\":\"AWS-HMAC\"," : "\"RoleArn\":\"arn:aws:iam::123456789012"
                + ":role/" + ROLE + "\",") + "\"AccessKeyId\":\"" + ACCESS_KEY_ID + "\",\"SecretAccessKey\":"
                + TestJson.quote(secretAccessKey).replace("/", "\\/") + ",\"Token\":" + TestJson.quote(sessionToken)
                + ",\"Expiration\":\"" + expiration + "\"}";
    }

    /** The reason the signature is refused, or {@code null} if it is right. */
    private String verify(HttpExchange exchange, Map<String, String> headers, byte[] body) {
        if (!exchange.getRequestMethod().equals("POST") || !exchange.getRequestURI().getRawPath().equals("/")) {
            return "Only POST / is served";
        }
        Matcher auth = AUTHORIZATION.matcher(headers.getOrDefault("authorization", ""));
        if (!auth.matches()) {
            return "Malformed Authorization header";
        }
        if (!auth.group(1).equals(ACCESS_KEY_ID) || !auth.group(3).equals(REGION)
                || !auth.group(4).equals("secretsmanager")) {
            return "Wrong credential scope";
        }
        String timestamp = headers.getOrDefault("x-amz-date", "");
        if (!timestamp.startsWith(auth.group(2))) {
            return "The date does not match the scope";
        }
        List<String> signed = List.of(auth.group(5).split(";"));
        List<String> required = new ArrayList<>(List.of("content-type", "host", "x-amz-date", "x-amz-target"));
        if (sessionToken != null) {
            required.add("x-amz-security-token");
            if (!sessionToken.equals(headers.get("x-amz-security-token"))) {
                return "The security token included in the request is invalid";
            }
        }
        if (!signed.containsAll(required)) {
            return "Headers not signed: " + required;
        }
        if (!"application/x-amz-json-1.1".equals(headers.get("content-type"))) {
            return "Wrong Content-Type";
        }
        Map<String, String> signedHeaders = new HashMap<>();
        for (String name : signed) {
            signedHeaders.put(name, headers.getOrDefault(name, ""));
        }
        String expected = SigV4Reference.signature(secretAccessKey, timestamp, REGION, "secretsmanager",
                SigV4Reference.canonicalRequest("POST", "/", signedHeaders, body));
        return expected.equals(auth.group(6)) ? null
                : "The request signature we calculated does not match the signature you provided";
    }

    private synchronized Response get(Map<String, Object> json) {
        String name = (String) json.get("SecretId");
        StoredSecret secret = secrets.get(name);
        String versionId = json.containsKey("VersionId") ? (String) json.get("VersionId")
                : secret == null ? null : secret.stages.get((String) json.getOrDefault("VersionStage", "AWSCURRENT"));
        Version version = secret == null || versionId == null ? null : secret.versions.get(versionId);
        if (version == null) {
            return error(400, "ResourceNotFoundException", "Secrets Manager can't find the specified secret.");
        }
        StringBuilder out = new StringBuilder("{\"ARN\":\"arn:aws:secretsmanager:" + REGION + ":123456789012:secret:")
                .append(name).append("-AbCdEf\",\"CreatedDate\":1.7329E9,\"Name\":\"").append(name).append('"');
        if (version.string() != null) {
            out.append(",\"SecretString\":").append(TestJson.quote(version.string()));
        } else {
            String base64 = Base64.getEncoder().encodeToString(version.binary());
            out.append(",\"SecretBinary\":\"").append(escapeSlashes ? base64.replace("/", "\\/") : base64)
                    .append('"');
        }
        out.append(",\"VersionId\":\"").append(version.id()).append("\",\"VersionStages\":[")
                .append(String.join(",", secret.stagesOf(version.id()).stream().map(s -> "\"" + s + "\"").toList()))
                .append("]}");
        return new Response(200, out.toString());
    }

    private synchronized Response putValue(Map<String, Object> json) {
        String name = (String) json.get("SecretId");
        if (!secrets.containsKey(name)) {
            return error(400, "ResourceNotFoundException", "Secrets Manager can't find the specified secret.");
        }
        Version version = store(name, json);
        return written(name, version);
    }

    private synchronized Response create(Map<String, Object> json) {
        String name = (String) json.get("Name");
        if (secrets.containsKey(name)) {
            return error(400, "ResourceExistsException", "The operation failed because the secret " + name
                    + " already exists.");
        }
        Version version = store(name, json);
        return written(name, version);
    }

    private Version store(String name, Map<String, Object> json) {
        String token = (String) json.get("ClientRequestToken");
        String string = (String) json.get("SecretString");
        String binary = (String) json.get("SecretBinary");
        return put(name, token, string, binary == null ? null : Base64.getDecoder().decode(binary));
    }

    private Response written(String name, Version version) {
        return new Response(200, "{\"ARN\":\"arn:aws:secretsmanager:" + REGION + ":123456789012:secret:" + name
                + "-AbCdEf\",\"Name\":\"" + name + "\",\"VersionId\":\"" + version.id()
                + "\",\"VersionStages\":[\"AWSCURRENT\"]}");
    }

    static Response error(int status, String type, String message) {
        return new Response(status, "{\"__type\":\"com.amazonaws.secretsmanager#" + type + "\",\"Message\":\""
                + message + "\"}");
    }

    private static void send(HttpExchange exchange, Response response) throws IOException {
        if (response.delayMillis() > 0) {
            try {
                new java.util.concurrent.CountDownLatch(1).await(response.delayMillis(),
                        java.util.concurrent.TimeUnit.MILLISECONDS);
            } catch (InterruptedException _) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        byte[] bytes = response.body().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/x-amz-json-1.1");
        long length = bytes.length == 0 ? -1 : bytes.length;
        exchange.sendResponseHeaders(response.status(), response.chunked() ? 0 : length);
        try (OutputStream out = exchange.getResponseBody()) {
            if (response.chunked()) {
                int step = Math.max(1, bytes.length / 3);
                for (int i = 0; i < bytes.length; i += step) {
                    out.write(bytes, i, Math.min(step, bytes.length - i));
                    out.flush();
                }
            } else {
                out.write(bytes);
            }
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}
