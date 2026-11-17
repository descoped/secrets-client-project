import io.descoped.secrets.api.SecretManagerClientInitializer;

/**
 * The dynamic-configuration secrets provider. For tests and migration only.
 */
module io.descoped.secrets.provider.dynamic.configuration {

    requires io.descoped.service.provider.api;
    requires io.descoped.dynamic.config;

    requires transitive io.descoped.secrets.api;

    requires org.slf4j;

    provides SecretManagerClientInitializer with io.descoped.secrets.dynamic.configuration.DynamicSecretConfigurationClientInitializer;

    exports io.descoped.secrets.dynamic.configuration;

}