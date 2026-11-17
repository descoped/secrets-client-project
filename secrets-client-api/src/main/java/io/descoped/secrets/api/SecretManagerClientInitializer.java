package io.descoped.secrets.api;

import io.descoped.service.provider.api.ProviderInitializer;

/**
 * The service a secrets provider implements. Annotate the implementation with
 * {@link io.descoped.service.provider.api.ProviderName} and register it with {@code provides} in its
 * {@code module-info.java} and in {@code META-INF/services/io.descoped.secrets.api.SecretManagerClientInitializer}.
 * {@link SecretManagerClient#create(java.util.Map)} selects it by that name.
 */
public interface SecretManagerClientInitializer extends ProviderInitializer<SecretManagerClient> {
}
