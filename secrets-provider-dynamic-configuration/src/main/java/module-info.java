/**
 * The {@code dynamic-configuration} secrets provider, for tests and migration. See
 * {@link io.descoped.secrets.provider.dynamic.DynamicConfigurationClientInitializer}.
 */
module io.descoped.secrets.provider.dynamic {
    requires transitive io.descoped.secrets.api;
    requires io.descoped.dynamic.config;

    exports io.descoped.secrets.provider.dynamic;

    provides io.descoped.secrets.api.SecretManagerClientInitializer with
            io.descoped.secrets.provider.dynamic.DynamicConfigurationClientInitializer;
}
