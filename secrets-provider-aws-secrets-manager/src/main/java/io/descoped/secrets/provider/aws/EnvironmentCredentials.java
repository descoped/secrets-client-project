package io.descoped.secrets.provider.aws;

import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretMemory;

import java.util.function.UnaryOperator;

/**
 * Credentials from {@code AWS_ACCESS_KEY_ID}, {@code AWS_SECRET_ACCESS_KEY} and {@code AWS_SESSION_TOKEN}, only when
 * {@code secrets.credentials=environment} is set: the JVM holds its environment as {@code String}s on the heap for
 * its whole life, so these are outside the guarantee, whatever this class does. It copies them into guarded memory
 * for signing, like any other credentials. For platforms that offer nothing else, such as AWS Lambda.
 */
final class EnvironmentCredentials implements CredentialsProvider.Source {

    static final String ACCESS_KEY_ID = "AWS_ACCESS_KEY_ID";
    static final String SECRET_ACCESS_KEY = "AWS_SECRET_ACCESS_KEY";
    static final String SESSION_TOKEN = "AWS_SESSION_TOKEN";

    private final SecretMemory memory;
    private final UnaryOperator<String> environment;

    EnvironmentCredentials(SecretMemory memory, UnaryOperator<String> environment) {
        this.memory = memory;
        this.environment = environment;
    }

    @Override
    public Credentials fetch() {
        String id = environment.apply(ACCESS_KEY_ID);
        String key = environment.apply(SECRET_ACCESS_KEY);
        if (id == null || id.isBlank() || key == null || key.isBlank()) {
            throw new SecretManagerException(ACCESS_KEY_ID + " and " + SECRET_ACCESS_KEY + " are not both set");
        }
        String token = environment.apply(SESSION_TOKEN);
        Secret secretAccessKey = memory.fromChars(key.toCharArray());
        try {
            Secret sessionToken = token == null || token.isBlank() ? null : memory.fromChars(token.toCharArray());
            return new Credentials(id, secretAccessKey, sessionToken, null);
        } catch (RuntimeException e) {
            secretAccessKey.close();
            throw e;
        }
    }
}
