/**
 * The secrets client API. Start with {@link io.descoped.secrets.api.SecretManagerClient}; providers implement
 * {@link io.descoped.secrets.api.SecretManagerClientInitializer}.
 *
 * <p>The module declares {@code uses} for the provider service, so a provider module on the module path is resolved
 * at startup without the application requiring it.
 */
module io.descoped.secrets.api {
    requires transitive io.descoped.service.provider.api;

    exports io.descoped.secrets.api;

    uses io.descoped.secrets.api.SecretManagerClientInitializer;
}
