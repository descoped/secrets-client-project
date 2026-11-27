package io.descoped.secrets.provider.google;

import io.descoped.secrets.api.http.Codec;
import io.descoped.secrets.api.http.Http;
import io.descoped.secrets.api.http.Json;
import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;

/**
 * The current access token, in guarded memory, fetched from its {@link Source} when there is none or it expires
 * within {@value #MARGIN_MINUTES} minutes. Thread-safe: a token is replaced and closed only while nobody uses it.
 */
final class AccessTokens implements AutoCloseable {

    private static final long MARGIN_MINUTES = 3;
    private static final long MARGIN = TimeUnit.MINUTES.toNanos(MARGIN_MINUTES);

    /** An access token and when it expires ({@link System#nanoTime()}). */
    record Token(Secret value, long expiresAt) {
    }

    /** Where tokens come from. */
    sealed interface Source permits MetadataServer, AuthorizedUser {

        /**
         * A new token.
         *
         * @throws SecretManagerException if none can be had
         */
        Token fetch();
    }

    private final Source source;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private Token token;
    private boolean closed;

    AccessTokens(Source source) {
        this.source = source;
    }

    /**
     * Applies {@code action} to a valid token, fetching one first if needed.
     *
     * @throws IllegalStateException  if closed
     * @throws SecretManagerException if no token can be had
     */
    <R> R withToken(Function<? super MemorySegment, ? extends R> action) {
        lock.readLock().lock();
        try {
            if (valid()) {
                return token.value().withSegment(action);
            }
        } finally {
            lock.readLock().unlock();
        }
        lock.writeLock().lock();
        try {
            if (!valid()) {
                Token fresh = source.fetch();
                Token old = token;
                token = fresh;
                if (old != null) {
                    old.value().close();
                }
            }
            // Downgrade: the token cannot be replaced while it is used.
            lock.readLock().lock();
        } finally {
            lock.writeLock().unlock();
        }
        try {
            return token.value().withSegment(action);
        } finally {
            lock.readLock().unlock();
        }
    }

    private boolean valid() {
        if (closed) {
            throw new IllegalStateException("Client is closed");
        }
        return token != null && System.nanoTime() - (token.expiresAt() - MARGIN) < 0;
    }

    /** Closes the current token. Idempotent. */
    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            closed = true;
            if (token != null) {
                token.value().close();
                token = null;
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Reads an OAuth token response, {@code {"access_token":"...","expires_in":3599,...}}: the token into guarded
     * memory, never through the heap.
     */
    static Token parse(Http.Response response, SecretMemory memory, String from) {
        return response.body().withSegment(json -> {
            try {
                if (!(Json.parse(json) instanceof Json.Obj object)) {
                    throw new Codec.MalformedException("not an object");
                }
                Json.Str value = object.string("access_token");
                if (value == null) {
                    throw new SecretManagerException("No access_token in the response from " + from);
                }
                long seconds = 3600;
                if (object.fields().get("expires_in") instanceof Json.Num expires) {
                    seconds = Long.parseLong(Json.text(json, expires));
                }
                return new Token(unescaped(memory, json, value), System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds));
            } catch (Codec.MalformedException | NumberFormatException _) {
                throw new SecretManagerException("Cannot parse the access token response from " + from);
            }
        });
    }

    /**
     * The content of a JSON string in {@code json}, unescaped into a new secret.
     *
     * @throws Codec.MalformedException if an escape is invalid
     */
    static Secret unescaped(SecretMemory memory, MemorySegment json, Json.Str string)
            throws Codec.MalformedException {
        MemorySegment raw = string.raw(json);
        long length = Codec.unescapedLength(raw);
        return memory.allocate(length, out -> {
            try {
                Codec.unescape(raw, out);
            } catch (Codec.MalformedException e) {
                // Measured above, so it cannot fail here.
                throw new IllegalStateException(e);
            }
        });
    }

    private static SecretManagerException failed(String from, IOException e) {
        return new SecretManagerException("Cannot get an access token from " + from + ": "
                + e.getClass().getSimpleName(), e);
    }

    /**
     * The metadata server of Compute Engine, Cloud Run and GKE (Workload Identity): the token of the attached service
     * account, over plain HTTP to a link-local address.
     */
    record MetadataServer(Http.Target target, Http.Timeouts timeouts, SecretMemory memory) implements Source {

        /** The metadata server's fixed path for the attached service account's token; not configurable by design. */
        @SuppressWarnings("java:S1075")
        static final String PATH = "/computeMetadata/v1/instance/service-accounts/default/token";

        @Override
        public Token fetch() {
            String from = "the metadata server " + target.hostHeader();
            Secret request = Http.request(memory, target, "GET", PATH, List.of("Metadata-Flavor: Google"),
                    List.of(), null);
            try (request; Http.Response response = Http.exchange(target, request, timeouts, memory)) {
                if (response.status() != 200) {
                    throw new SecretManagerException("Cannot get an access token from " + from + ": HTTP "
                            + response.status());
                }
                return parse(response, memory, from);
            } catch (IOException e) {
                throw failed(from, e);
            }
        }
    }

    /**
     * A user's credentials, as {@code gcloud auth application-default login} writes them: the refresh token is
     * exchanged for an access token at Google's OAuth endpoint. For local development.
     */
    record AuthorizedUser(Http.Target target, Http.Timeouts timeouts, SecretMemory memory, String clientId,
                          Secret clientSecret, Secret refreshToken) implements Source {

        private static final byte[] GRANT = "grant_type=refresh_token&client_id=".getBytes(StandardCharsets.US_ASCII);
        private static final byte[] CLIENT_SECRET = "&client_secret=".getBytes(StandardCharsets.US_ASCII);
        private static final byte[] REFRESH_TOKEN = "&refresh_token=".getBytes(StandardCharsets.US_ASCII);

        @Override
        public Token fetch() {
            String from = "the OAuth endpoint " + target.hostHeader();
            MemorySegment id = MemorySegment.ofArray(clientId.getBytes(StandardCharsets.UTF_8));
            Secret request = clientSecret.withSegment(secret -> refreshToken.withSegment(refresh -> {
                long length = GRANT.length + Codec.formEncodedLength(id) + CLIENT_SECRET.length
                        + Codec.formEncodedLength(secret) + REFRESH_TOKEN.length + Codec.formEncodedLength(refresh);
                try (Secret form = memory.allocate(length, out -> {
                    long pos = Codec.putBytes(out, 0, GRANT);
                    pos = Codec.formEncode(id, out, pos);
                    pos = Codec.putBytes(out, pos, CLIENT_SECRET);
                    pos = Codec.formEncode(secret, out, pos);
                    pos = Codec.putBytes(out, pos, REFRESH_TOKEN);
                    Codec.formEncode(refresh, out, pos);
                })) {
                    return form.withSegment(body -> Http.request(memory, target, "POST", "",
                            List.of("Content-Type: application/x-www-form-urlencoded"), List.of(), body));
                }
            }));
            try (request; Http.Response response = Http.exchange(target, request, timeouts, memory)) {
                if (response.status() != 200) {
                    throw new SecretManagerException("Cannot get an access token from " + from + ": HTTP "
                            + response.status() + oauthError(response));
                }
                return parse(response, memory, from);
            } catch (IOException e) {
                throw failed(from, e);
            }
        }

        /** {@code error} of an OAuth error response, such as {@code invalid_grant}; it holds no secret. */
        private static String oauthError(Http.Response response) {
            return response.body().withSegment(json -> {
                try {
                    if (Json.parse(json) instanceof Json.Obj object && object.string("error") != null) {
                        String error = Json.text(json, object.string("error"));
                        return error.matches("[a-z_]{1,64}") ? " " + error : "";
                    }
                } catch (Codec.MalformedException _) {
                    // Not an OAuth error document; the status says enough.
                }
                return "";
            });
        }

        /**
         * Loads a credentials file, read into guarded memory and parsed there.
         *
         * @throws SecretManagerException if it cannot be read, or is not an {@code authorized_user} file
         */
        static AuthorizedUser load(Path file, Http.Target target, Http.Timeouts timeouts, SecretMemory memory) {
            try (Secret content = read(file, memory)) {
                return content.withSegment(json -> fromJson(json, file, target, timeouts, memory));
            }
        }

        private static AuthorizedUser fromJson(MemorySegment json, Path file, Http.Target target,
                                               Http.Timeouts timeouts, SecretMemory memory) {
            Json.Obj object;
            String type;
            try {
                object = Json.parse(json) instanceof Json.Obj o ? o : null;
                type = object == null || object.string("type") == null ? "" : Json.text(json, object.string("type"));
            } catch (Codec.MalformedException _) {
                throw new SecretManagerException("The Google credentials file " + file + " is not valid JSON");
            }
            if (object == null || !type.equals("authorized_user")) {
                throw new SecretManagerException("The Google credentials file " + file + " is "
                        + (type.matches("[a-z_]{1,64}") ? "of type '" + type + "'" : "of no known type")
                        + ": this provider reads only authorized_user credentials (gcloud auth"
                        + " application-default login), and on Google Cloud the metadata server. Keys"
                        + " (service_account) are refused: signing with them would put the key on the Java heap.");
            }
            Json.Str id = required(object, "client_id", file);
            Json.Str secret = required(object, "client_secret", file);
            Json.Str refresh = required(object, "refresh_token", file);
            Secret clientSecret = null;
            try {
                clientSecret = unescaped(memory, json, secret);
                return new AuthorizedUser(target, timeouts, memory, Json.text(json, id), clientSecret,
                        unescaped(memory, json, refresh));
            } catch (Codec.MalformedException _) {
                if (clientSecret != null) {
                    clientSecret.close();
                }
                throw new SecretManagerException("The Google credentials file " + file + " is not valid JSON");
            }
        }

        private static Json.Str required(Json.Obj object, String field, Path file) {
            Json.Str value = object.string(field);
            if (value == null) {
                throw new SecretManagerException("The Google credentials file " + file + " has no " + field);
            }
            return value;
        }

        /** The largest credentials file read. */
        private static final long MAX_FILE = 1024L * 1024;

        private static Secret read(Path file, SecretMemory memory) {
            try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
                Secret content = memory.read(channel, MAX_FILE + 1);
                if (content.length() > MAX_FILE) {
                    content.close();
                    throw new SecretManagerException("The Google credentials file " + file + " is too large");
                }
                return content;
            } catch (IOException e) {
                throw new SecretManagerException("Cannot read the Google credentials file " + file, e);
            }
        }
    }
}
