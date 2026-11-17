/**
 * The secrets client API: {@link io.descoped.secrets.api.SecretManagerClient} and the provider service
 * {@link io.descoped.secrets.api.SecretManagerClientInitializer}.
 */
module io.descoped.secrets.client.api {

    requires transitive io.descoped.service.provider.api;

    exports io.descoped.secrets.api;
}