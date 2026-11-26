/**
 * The {@code google-secret-manager} secrets provider. See
 * {@link io.descoped.secrets.provider.google.GoogleSecretManagerClientInitializer}.
 */
module io.descoped.secrets.provider.google {
    requires transitive io.descoped.secrets.api;

    exports io.descoped.secrets.provider.google;

    provides io.descoped.secrets.api.SecretManagerClientInitializer with
            io.descoped.secrets.provider.google.GoogleSecretManagerClientInitializer;
}
