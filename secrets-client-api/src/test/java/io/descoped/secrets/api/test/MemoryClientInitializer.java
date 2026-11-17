package io.descoped.secrets.api.test;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerClientInitializer;
import io.descoped.service.provider.api.ProviderName;

import java.util.Map;
import java.util.Set;

/**
 * A test provider, {@code memory}, that requires the key {@code memory.required}.
 */
@ProviderName("memory")
public final class MemoryClientInitializer implements SecretManagerClientInitializer {

    /**
     * The configuration the last client was created with.
     */
    static volatile Map<String, String> lastConfiguration;

    @Override
    public Set<String> configurationKeys() {
        return Set.of("memory.required");
    }

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        lastConfiguration = configuration;
        return new MemoryClient();
    }
}
