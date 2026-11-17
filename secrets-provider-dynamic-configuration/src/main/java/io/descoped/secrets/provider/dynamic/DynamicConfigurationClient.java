package io.descoped.secrets.provider.dynamic;

import io.descoped.config.DynamicConfiguration;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretNotFoundException;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Read-only secrets from a {@link DynamicConfiguration}. The configuration holds its values as strings, which cannot
 * be wiped; that is why this provider is for tests and migration only.
 */
final class DynamicConfigurationClient implements SecretManagerClient {

    /**
     * The only version this provider has.
     */
    static final String LATEST = "latest";

    private volatile DynamicConfiguration configuration;

    DynamicConfigurationClient(DynamicConfiguration configuration) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        Objects.requireNonNull(secretName, "secretName");
        DynamicConfiguration current = open();
        if (!(secretVersion == null || LATEST.equals(secretVersion))) {
            throw new SecretNotFoundException(secretName, secretVersion);
        }
        return current.find(secretName)
                .map(value -> value.getBytes(StandardCharsets.UTF_8))
                .orElseThrow(() -> new SecretNotFoundException(secretName, secretVersion));
    }

    /**
     * Always fails: this provider is read-only.
     *
     * @throws UnsupportedOperationException always, or {@link IllegalStateException} if the client is closed
     */
    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        Objects.requireNonNull(secretName, "secretName");
        Objects.requireNonNull(secretValue, "secretValue");
        open();
        throw new UnsupportedOperationException("The dynamic-configuration secrets provider is read-only");
    }

    /**
     * Drops the configuration. Its strings cannot be wiped; they are left to the garbage collector.
     */
    @Override
    public void close() {
        configuration = null;
    }

    private DynamicConfiguration open() {
        DynamicConfiguration current = configuration;
        if (current == null) {
            throw new IllegalStateException("Client is closed");
        }
        return current;
    }
}
