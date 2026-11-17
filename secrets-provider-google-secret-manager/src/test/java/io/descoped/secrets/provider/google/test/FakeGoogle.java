package io.descoped.secrets.provider.google.test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A local stand-in for Google: an OAuth token endpoint and Secret Manager responses set per request, so the provider
 * runs its real code, google-auth included, against it.
 */
final class FakeGoogle implements AutoCloseable {

    /**
     * A request the fake received.
     */
    record Request(String method, String path, String authorization, byte[] body) {

        String bodyText() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    /**
     * A canned response.
     */
    record Response(int status, String body) {
    }

    private final HttpServer server;
    private final ExecutorService executor = Executors.newFixedThreadPool(8);
    private final Map<String, List<Response>> responses = new ConcurrentHashMap<>();
    final List<Request> requests = new CopyOnWriteArrayList<>();
    final AtomicInteger tokens = new AtomicInteger();
    volatile int tokenLifetimeSeconds = 3600;

    FakeGoogle() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/token", this::token);
        server.createContext("/v1/", this::secretManager);
        // Several threads, like a real server, so concurrent requests from a client overlap here too.
        server.setExecutor(executor);
        server.start();
    }

    String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /**
     * Answers {@code method path} (path with query) with the given responses, one per request, the last repeated.
     */
    void on(String method, String path, Response... answers) {
        responses.put(method + " " + path, new ArrayList<>(List.of(answers)));
    }

    List<Request> requests(String method, String path) {
        return requests.stream().filter(r -> r.method().equals(method) && r.path().equals(path)).toList();
    }

    private void token(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
        int n = tokens.incrementAndGet();
        send(exchange, 200, "{\"access_token\":\"token-" + n + "\",\"expires_in\":" + tokenLifetimeSeconds
                + ",\"token_type\":\"Bearer\"}");
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
            send(exchange, 500, "{\"error\":{\"code\":500,\"status\":\"INTERNAL\",\"message\":\"no fake for "
                    + exchange.getRequestMethod() + " " + path + "\"}}");
            return;
        }
        Response response;
        synchronized (answers) {
            response = answers.size() > 1 ? answers.remove(0) : answers.get(0);
        }
        send(exchange, response.status(), response.body());
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    /**
     * Writes a service-account key file with a fresh RSA key whose token endpoint is this fake.
     */
    Path serviceAccountKey(Path dir) throws IOException {
        String pem;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            byte[] pkcs8 = generator.generateKeyPair().getPrivate().getEncoded();
            pem = "-----BEGIN PRIVATE KEY-----\\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                    .encodeToString(pkcs8).replace("\n", "\\n")
                    + "\\n-----END PRIVATE KEY-----\\n";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        String json = "{\"type\":\"service_account\",\"project_id\":\"test-project\",\"private_key_id\":\"k1\","
                + "\"private_key\":\"" + pem + "\",\"client_email\":\"tester@test-project.iam.gserviceaccount.com\","
                + "\"client_id\":\"1\",\"token_uri\":\"" + endpoint() + "/token\"}";
        Path file = dir.resolve("service-account.json");
        Files.writeString(file, json);
        return file;
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
