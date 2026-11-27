package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.http.Codec;
import io.descoped.secrets.api.http.Json;

import java.lang.foreign.MemorySegment;
import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * The credentials document that the ECS container endpoint and EC2 instance metadata return:
 * {@code {"AccessKeyId": ..., "SecretAccessKey": ..., "Token": ..., "Expiration": "2026-11-27T12:00:00Z"}}. It is
 * parsed in guarded memory, and the secret access key and the token are unescaped from it straight into their own
 * guarded memory; only the access key ID and the expiration become {@code String}s.
 */
final class CredentialsDocument {

    private CredentialsDocument() {
    }

    /**
     * The credentials in {@code body}.
     *
     * @param memory where the secret parts go
     * @param body   the response body
     * @param source the source's name, for messages
     * @return the credentials, which the caller owns
     */
    static Credentials parse(SecretMemory memory, Secret body, String source) {
        return body.withSegment(json -> {
            try {
                return parse(memory, json, source);
            } catch (Codec.MalformedException | DateTimeParseException e) {
                // Not chained: nothing about the keys may leave this method.
                throw new SecretManagerException("Cannot parse the credentials from " + source + " ("
                        + e.getClass().getSimpleName() + ")");
            }
        });
    }

    private static Credentials parse(SecretMemory memory, MemorySegment json, String source)
            throws Codec.MalformedException {
        if (!(Json.parse(json) instanceof Json.Obj document)) {
            throw lacking(source);
        }
        Json.Str id = document.string("AccessKeyId");
        Json.Str key = document.string("SecretAccessKey");
        Json.Str token = document.string("Token");
        Json.Str expiration = document.string("Expiration");
        if (id == null || key == null || token == null || expiration == null) {
            throw lacking(source);
        }
        Instant expires = Instant.parse(Json.text(json, expiration));
        String accessKeyId = Json.text(json, id);
        Secret secretAccessKey = unescaped(memory, json, key);
        Secret sessionToken;
        try {
            sessionToken = unescaped(memory, json, token);
        } catch (Codec.MalformedException | RuntimeException e) {
            secretAccessKey.close();
            throw e;
        }
        return new Credentials(accessKeyId, secretAccessKey, sessionToken, expires);
    }

    private static SecretManagerException lacking(String source) {
        return new SecretManagerException("The credentials from " + source
                + " lack AccessKeyId, SecretAccessKey, Token or Expiration");
    }

    private static Secret unescaped(SecretMemory memory, MemorySegment json, Json.Str string)
            throws Codec.MalformedException {
        MemorySegment raw = string.raw(json);
        long length = Codec.unescapedLength(raw);
        return memory.allocate(length, out -> {
            try {
                Codec.unescape(raw, out);
            } catch (Codec.MalformedException e) {
                // Not reached: unescapedLength checked the same input.
                throw new IllegalStateException(e.getClass().getSimpleName());
            }
        });
    }
}
