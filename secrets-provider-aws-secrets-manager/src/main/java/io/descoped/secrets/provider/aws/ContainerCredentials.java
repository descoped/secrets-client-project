package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.http.Http;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.List;

/**
 * Temporary credentials from the container credentials endpoint: the ECS task role
 * ({@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}, on {@code 169.254.170.2}) and EKS Pod Identity
 * ({@code AWS_CONTAINER_CREDENTIALS_FULL_URI} with {@code AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE}). The authorization
 * token is read from its file into guarded memory on each fetch (the platform rotates it) and sent from there; the
 * response is parsed in guarded memory ({@link CredentialsDocument}).
 */
final class ContainerCredentials implements CredentialsProvider.Source {

    static final String SOURCE = "the container credentials endpoint";

    /** Larger than any authorization token. */
    private static final long MAX_TOKEN = 64L * 1024;

    private final SecretMemory memory;
    private final Http.Target target;
    private final Path tokenFile;
    private final Http.Timeouts timeouts;

    /**
     * @param target    the endpoint, its path included
     * @param tokenFile the authorization token's file, or {@code null} for none (the ECS task role)
     */
    ContainerCredentials(SecretMemory memory, Http.Target target, Path tokenFile, Http.Timeouts timeouts) {
        this.memory = memory;
        this.target = target;
        this.tokenFile = tokenFile;
        this.timeouts = timeouts;
    }

    @Override
    public Credentials fetch() {
        Secret request = tokenFile == null
                ? Http.request(memory, target, "GET", "", List.of(), List.of(), null)
                : withToken();
        try (request; Http.Response response = Http.exchange(target, request, timeouts, memory)) {
            if (response.status() != 200) {
                throw new SecretManagerException(capitalized() + " returned HTTP " + response.status());
            }
            return CredentialsDocument.parse(memory, response.body(), SOURCE);
        } catch (IOException e) {
            throw new SecretManagerException("Cannot reach " + SOURCE + ": " + e.getClass().getSimpleName(), e);
        }
    }

    /** The request with {@code Authorization: <token>}, the token read from its file without trailing whitespace. */
    private Secret withToken() {
        try (FileChannel channel = FileChannel.open(tokenFile); Secret token = memory.read(channel, MAX_TOKEN)) {
            return token.withSegment(t -> {
                MemorySegment trimmed = t.asSlice(0, trimmedLength(t));
                return Http.request(memory, target, "GET", "", List.of(),
                        List.of(new Http.SecretHeader("Authorization", "", trimmed)), null);
            });
        } catch (IOException e) {
            throw new SecretManagerException("Cannot read the container authorization token file " + tokenFile + ": "
                    + e.getClass().getSimpleName(), e);
        }
    }

    private static long trimmedLength(MemorySegment token) {
        long end = token.byteSize();
        while (end > 0 && token.get(ValueLayout.JAVA_BYTE, end - 1) <= ' ') {
            end--;
        }
        return end;
    }

    private static String capitalized() {
        return "T" + SOURCE.substring(1);
    }
}
