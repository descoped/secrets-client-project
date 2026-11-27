package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.Secret;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * AWS credentials: the access key ID, which is an identifier and not secret, and the secret access key and session
 * token, which are kept in guarded memory. Closing wipes them.
 *
 * @param accessKeyId     the access key ID
 * @param secretAccessKey the secret access key
 * @param sessionToken    the session token of temporary credentials, or {@code null}
 * @param expiration      when temporary credentials expire, or {@code null} for long-term ones
 */
record Credentials(String accessKeyId, Secret secretAccessKey, Secret sessionToken, Instant expiration)
        implements AutoCloseable {

    Credentials {
        Objects.requireNonNull(accessKeyId, "accessKeyId");
        Objects.requireNonNull(secretAccessKey, "secretAccessKey");
    }

    /** Whether they expire within {@code margin} of {@code now}. */
    boolean expiresWithin(Duration margin, Instant now) {
        return expiration != null && !now.plus(margin).isBefore(expiration);
    }

    @Override
    public void close() {
        try {
            secretAccessKey.close();
        } finally {
            if (sessionToken != null) {
                sessionToken.close();
            }
        }
    }

    /** Never the secret parts. */
    @Override
    public String toString() {
        return "Credentials[" + accessKeyId + (sessionToken == null ? "" : ", temporary") + "]";
    }
}
