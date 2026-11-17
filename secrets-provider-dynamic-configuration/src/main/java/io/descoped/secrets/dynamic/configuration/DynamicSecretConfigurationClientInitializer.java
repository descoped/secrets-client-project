package io.descoped.secrets.dynamic.configuration;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerClientInitializer;
import io.descoped.service.provider.api.ProviderName;

import java.util.Map;

/**
 * The provider {@code dynamic-secret-configuration}.
 */
@ProviderName("dynamic-secret-configuration")
public class DynamicSecretConfigurationClientInitializer implements SecretManagerClientInitializer {

    /**
     * Creates the initializer; called by {@link java.util.ServiceLoader}.
     */
    public DynamicSecretConfigurationClientInitializer() {
    }

    // Optional: "secrets.property-resource-path"

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        String propertyResourcePath = configuration.get("secrets.property-resource-path");
        if (propertyResourcePath != null) {
            return new DynamicSecretConfigurationClient(propertyResourcePath);
        } else {
            return new DynamicSecretConfigurationClient(configuration);
        }
    }
}
