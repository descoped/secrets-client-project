package io.descoped.secrets.dynamic.configuration;

import io.descoped.config.StoreBasedDynamicConfiguration;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.secrets.api.SecretNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Optional.ofNullable;

/**
 * A client that reads secrets from dynamic-configuration. For tests and migration only: values are
 * held as strings in memory.
 */
public class DynamicSecretConfigurationClient implements SecretManagerClient {

    static final Logger LOG = LoggerFactory.getLogger(DynamicSecretConfigurationClient.class);
    final Map<String, String> map = new ConcurrentHashMap<>();
    final String propertyResourcePath;
    final Object lock = new Object();
    private final AtomicBoolean closed = new AtomicBoolean();

    /**
     * Reads the secrets from a properties resource.
     *
     * @param propertyResourcePath the properties file or class-path resource
     */
    public DynamicSecretConfigurationClient(String propertyResourcePath) {
        new StoreBasedDynamicConfiguration.Builder()
                .propertiesResource(propertyResourcePath)
                .build()
                .asMap()
                .forEach((key, value) -> map.put(key, Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8))));
        this.propertyResourcePath = propertyResourcePath;
    }

    /**
     * Uses the given map as the secrets.
     *
     * @param configuration the secrets by name
     */
    public DynamicSecretConfigurationClient(Map<String, String> configuration) {
        configuration.forEach((key, value) -> map.put(key, Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8))));
        this.propertyResourcePath = null;
    }

    @Override
    public byte[] readBytes(String secretName, String secretVersion) {
        if (closed.get()) {
            throw new IllegalStateException("Client is closed");
        }
        return ofNullable(map.get(Objects.requireNonNull(secretName, "secretName")))
                .map(s -> Base64.getDecoder().decode(s))
                .orElseThrow(() -> new SecretNotFoundException(secretName, secretVersion));
    }

    @Override
    public String addVersion(String secretName, byte[] secretValue) {
        if (closed.get()) {
            throw new IllegalStateException("Client is closed");
        }
        Objects.requireNonNull(secretName, "secretName");
        Objects.requireNonNull(secretValue, "secretValue");
        if (propertyResourcePath == null) {
            throw new UnsupportedOperationException("No 'secrets.property-resource-path' to write to");
        }
        String encodedSecretValue = Base64.getEncoder().encodeToString(secretValue);
        map.put(secretName, encodedSecretValue);
        Path path = Path.of(propertyResourcePath);
        if (!Files.isWritable(path)) {
            LOG.warn("Secret configuration is NOT writable: {}", path.normalize().toAbsolutePath());
            return "latest";
        }
        synchronized (lock) {
            try {
                String secretResources = Files.readString(path);
                Properties props = new Properties();
                props.load(new StringReader(secretResources));
                props.put(secretName, encodedSecretValue);
                try (FileOutputStream out = new FileOutputStream(path.toFile())) {
                    props.store(out, null);
                }
            } catch (IOException e) {
                throw new SecretManagerException("Cannot write secret '" + secretName + "' to " + path, e);
            }
        }
        return "latest";
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            map.clear();
        }
    }
}
