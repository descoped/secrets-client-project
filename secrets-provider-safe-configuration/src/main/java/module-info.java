import io.descoped.secrets.api.SecretManagerClientInitializer;

/**
 * The safe-configuration secrets provider, for a local secrets file.
 */
module io.descoped.secrets.provider.safe.configuration {

    requires io.descoped.service.provider.api;
    requires transitive io.descoped.secrets.api;

    requires org.slf4j;

    provides SecretManagerClientInitializer with io.descoped.secrets.secure.configuration.SafeConfigurationClientInitializer;

    exports io.descoped.secrets.secure.configuration;

}
