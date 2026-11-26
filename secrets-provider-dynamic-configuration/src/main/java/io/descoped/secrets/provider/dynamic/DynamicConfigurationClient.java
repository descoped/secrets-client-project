package io.descoped.secrets.provider.dynamic;

import io.descoped.config.DynamicConfiguration;
import io.descoped.secrets.api.Secret;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretMemory;
import io.descoped.secrets.api.SecretNotFoundException;

import java.nio.charset.StandardCharsets;
import java.util.Map;
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

    private final Map<String, String> settings;
    private volatile DynamicConfiguration configuration;
    /**
     * Guarded memory for {@link #read(String, String)}, created by its first call so that a client that never calls
     * it needs no native access; under {@code this}.
     */
    private SecretMemory memory;

    DynamicConfigurationClient(DynamicConfiguration configuration, Map<String, String> settings) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.settings = Map.copyOf(settings);
    }

    /**
     * The value copied into guarded memory. It is on the heap before that, as a {@code String} in the configuration
     * that cannot be wiped.
     */
    @Override
    public Secret read(String secretName, String secretVersion) {
        SecretMemory current = memory();
        return current.fromBytes(readBytes(secretName, secretVersion));
    }

    private synchronized SecretMemory memory() {
        open();
        if (memory == null) {
            memory = SecretMemory.create(settings);
        }
        return memory;
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
     * Drops the configuration, and closes the secrets {@link #read(String, String)} returned. The configuration's
     * strings cannot be wiped; they are left to the garbage collector.
     */
    @Override
    public void close() {
        configuration = null;
        synchronized (this) {
            if (memory != null) {
                memory.close();
                memory = null;
            }
        }
    }

    private DynamicConfiguration open() {
        DynamicConfiguration current = configuration;
        if (current == null) {
            throw new IllegalStateException("Client is closed");
        }
        return current;
    }
}
