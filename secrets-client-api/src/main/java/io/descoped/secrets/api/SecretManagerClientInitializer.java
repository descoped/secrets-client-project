package io.descoped.secrets.api;

import io.descoped.service.provider.api.ProviderInitializer;

/**
 * The service a secrets provider implements: names the provider and creates its {@link SecretManagerClient}.
 */
public interface SecretManagerClientInitializer extends ProviderInitializer<SecretManagerClient> {
}
