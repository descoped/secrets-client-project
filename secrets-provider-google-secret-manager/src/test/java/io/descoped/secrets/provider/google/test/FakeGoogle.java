package io.descoped.secrets.provider.google.test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A local stand-in for Google: the OAuth token endpoint (refresh-token grant), the metadata server's token, and
 * Secret Manager responses set per request, over http or https, so the provider runs its real code against it.
 */
final class FakeGoogle implements AutoCloseable {

    static final String REFRESH_TOKEN = "refresh-1/abc+def";
    static final String CLIENT_ID = "client-1.apps.googleusercontent.com";
    static final String CLIENT_SECRET = "client secret&=";

    /** A Secret Manager request the fake received. */
    record Request(String method, String path, String authorization, byte[] body) {

        String bodyText() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    /** A canned response: sent chunked, or after a delay, if asked. */
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

    private final HttpServer server;
    private final boolean tls;
    private final ExecutorService executor = Executors.newFixedThreadPool(8);
    private final Map<String, List<Response>> responses = new ConcurrentHashMap<>();
    final List<Request> requests = new CopyOnWriteArrayList<>();
    final List<Map<String, String>> tokenRequests = new CopyOnWriteArrayList<>();
    final List<String> metadataFlavors = new CopyOnWriteArrayList<>();
    final AtomicInteger tokens = new AtomicInteger();
    volatile int tokenLifetimeSeconds = 3600;
    /** The access token to issue; {@code token-<n>} when {@code null}. */
    volatile String accessToken;
    /** The refresh token the OAuth endpoint accepts. */
    volatile String refreshToken = REFRESH_TOKEN;

    FakeGoogle() throws IOException {
        this(null);
    }

    /** Serves https with {@code context} when it is not {@code null}. */
    FakeGoogle(SSLContext context) throws IOException {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        if (context == null) {
            server = HttpServer.create(address, 0);
        } else {
            HttpsServer https = HttpsServer.create(address, 0);
            https.setHttpsConfigurator(new HttpsConfigurator(context));
            server = https;
        }
        tls = context != null;
        server.createContext("/token", this::token);
        server.createContext("/computeMetadata/v1/instance/service-accounts/default/token", this::metadata);
        server.createContext("/v1/", this::secretManager);
        // Several threads, like a real server, so concurrent requests from a client overlap here too.
        server.setExecutor(executor);
        server.start();
    }

    String endpoint() {
        return (tls ? "https" : "http") + "://127.0.0.1:" + server.getAddress().getPort();
    }

    String tokenEndpoint() {
        return endpoint() + "/token";
    }

    /** Answers {@code method path} (path with query) with the given responses, one per request, the last repeated. */
    void on(String method, String path, Response... answers) {
        responses.put(method + " " + path, new ArrayList<>(List.of(answers)));
    }

    List<Request> requests(String method, String path) {
        return requests.stream().filter(r -> r.method().equals(method) && r.path().equals(path)).toList();
    }

    /** Writes an {@code authorized_user} credentials file, as gcloud does, for this fake's refresh token. */
    Path credentialsFile(Path dir) throws IOException {
        Path file = dir.resolve("application_default_credentials.json");
        Files.writeString(file, "{\n  \"account\": \"\",\n  \"client_id\": \"" + CLIENT_ID + "\",\n"
                + "  \"client_secret\": \"" + CLIENT_SECRET + "\",\n  \"quota_project_id\": \"test-project\",\n"
                + "  \"refresh_token\": \"" + refreshToken.replace("/", "\\/") + "\",\n"
                + "  \"type\": \"authorized_user\",\n  \"universe_domain\": \"googleapis.com\"\n}\n");
        return file;
    }

    private String issue() {
        int n = tokens.incrementAndGet();
        String token = accessToken != null ? accessToken : "token-" + n;
        return "{\"access_token\":\"" + token + "\",\"expires_in\":" + tokenLifetimeSeconds
                + ",\"scope\":\"https://www.googleapis.com/auth/cloud-platform\",\"token_type\":\"Bearer\"}";
    }

    private void token(HttpExchange exchange) throws IOException {
        Map<String, String> form = new HashMap<>();
        for (String pair : new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.US_ASCII)
                .split("&")) {
            int eq = pair.indexOf('=');
            form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        tokenRequests.add(form);
        if (!"refresh_token".equals(form.get("grant_type")) || !refreshToken.equals(form.get("refresh_token"))
                || !CLIENT_ID.equals(form.get("client_id")) || !CLIENT_SECRET.equals(form.get("client_secret"))) {
            send(exchange, new Response(400, "{\"error\":\"invalid_grant\",\"error_description\":\"Bad Request\"}"));
            return;
        }
        send(exchange, new Response(200, issue()));
    }

    private void metadata(HttpExchange exchange) throws IOException {
        String flavor = exchange.getRequestHeaders().getFirst("Metadata-Flavor");
        metadataFlavors.add(String.valueOf(flavor));
        if (!"Google".equals(flavor)) {
            send(exchange, new Response(403, "Missing Metadata-Flavor:Google header."));
            return;
        }
        send(exchange, new Response(200, issue()).asChunks());
    }

    private void secretManager(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getRawPath();
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null) {
            path += "?" + query;
        }
        byte[] body = exchange.getRequestBody().readAllBytes();
        requests.add(new Request(exchange.getRequestMethod(), path,
                exchange.getRequestHeaders().getFirst("Authorization"), body));
        List<Response> answers = responses.get(exchange.getRequestMethod() + " " + path);
        if (answers == null || answers.isEmpty()) {
            send(exchange, new Response(500, "{\"error\":{\"code\":500,\"status\":\"INTERNAL\","
                    + "\"message\":\"no fake for " + exchange.getRequestMethod() + " " + path + "\"}}"));
            return;
        }
        Response response;
        synchronized (answers) {
            response = answers.size() > 1 ? answers.remove(0) : answers.get(0);
        }
        send(exchange, response);
    }

    private static void send(HttpExchange exchange, Response response) throws IOException {
        if (response.delayMillis() > 0) {
            try {
                // A latch nobody counts down: a delay that an interrupt (the fake's shutdown) ends.
                new java.util.concurrent.CountDownLatch(1).await(response.delayMillis(),
                        java.util.concurrent.TimeUnit.MILLISECONDS);
            } catch (InterruptedException _) {
                Thread.currentThread().interrupt();
                return;
            }
        }
        byte[] bytes = response.body().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        // 0 asks the server for chunked encoding, -1 for an empty body with Content-Length: 0.
        long length = bytes.length == 0 ? -1 : bytes.length;
        exchange.sendResponseHeaders(response.status(), response.chunked() ? 0 : length);
        try (OutputStream out = exchange.getResponseBody()) {
            if (response.chunked()) {
                // Several chunks, so that a value spans them.
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

    static String accessResponse(byte[] value, long crc) {
        return "{\"name\":\"projects/123/secrets/s/versions/1\",\"payload\":{\"data\":\""
                + Base64.getEncoder().encodeToString(value) + "\",\"dataCrc32c\":\"" + crc + "\"}}";
    }

    static Response error(int status, String googleStatus, String message) {
        return new Response(status, "{\"error\":{\"code\":" + status + ",\"message\":\"" + message
                + "\",\"status\":\"" + googleStatus + "\"}}");
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}
