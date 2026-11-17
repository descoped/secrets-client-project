/**
 * The {@code safe-configuration} secrets provider: secrets in a local file. See
 * {@link io.descoped.secrets.provider.safe.SafeConfigurationClientInitializer}.
 */
module io.descoped.secrets.provider.safe {
    requires transitive io.descoped.secrets.api;

    exports io.descoped.secrets.provider.safe;

    provides io.descoped.secrets.api.SecretManagerClientInitializer with
            io.descoped.secrets.provider.safe.SafeConfigurationClientInitializer;
}
