package io.descoped.secrets.provider.dynamic;

import io.descoped.config.ConfigurationException;
import io.descoped.config.DynamicConfiguration;
import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerClientInitializer;
import io.descoped.secrets.api.SecretManagerException;
import io.descoped.service.provider.api.ProviderConfigurator;
import io.descoped.service.provider.api.ProviderName;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * The provider {@code dynamic-configuration}: read-only secrets from
 * <a href="https://github.com/descoped/dynamic-configuration">dynamic-configuration</a>. <b>For tests and migration
 * only</b>: values are held as strings, which cannot be wiped.
 *
 * <table>
 *     <caption>Configuration (at least one source is required)</caption>
 *     <tr><th>Key</th><th>Value</th></tr>
 *     <tr><td>{@code secrets.provider}</td><td>{@code dynamic-configuration}</td></tr>
 *     <tr><td>{@value #PATH_KEY}</td><td>a properties file, which must exist</td></tr>
 *     <tr><td>{@value #DIRECTORY_KEY}</td><td>a directory of secret files, one file per secret (Kubernetes secret
 *     volumes, Docker secrets), which must exist</td></tr>
 *     <tr><td>{@value #VALUES_PREFIX}{@code <name>}</td><td>a secret given inline, for tests</td></tr>
 * </table>
 *
 * <p>The sources are layered in that order, a later one overriding an earlier one. The properties file follows
 * dynamic-configuration's rules: {@link java.util.Properties} escapes, and {@code ${key}} references between values
 * (<code>$${</code> for a literal <code>${</code>). Values from the directory are taken literally, except that one
 * trailing LF or CRLF is removed; hidden entries, such as Kubernetes' {@code ..data}, are skipped. The sources are read once,
 * when the client is created. The only version is {@code latest}; {@code addVersion} throws
 * {@link UnsupportedOperationException}.
 */
@ProviderName("dynamic-configuration")
public final class DynamicConfigurationClientInitializer implements SecretManagerClientInitializer {

    /**
     * The configuration key for the properties file.
     */
    public static final String PATH_KEY = "secrets.property-resource-path";

    /**
     * The configuration key for the directory of secret files.
     */
    public static final String DIRECTORY_KEY = "secrets.directory";

    /**
     * The prefix of configuration keys that give secrets inline.
     */
    public static final String VALUES_PREFIX = "secrets.values.";

    /**
     * Creates the initializer; called by {@link java.util.ServiceLoader}.
     */
    public DynamicConfigurationClientInitializer() {
    }

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        String file = configuration.get(PATH_KEY);
        String directory = configuration.get(DIRECTORY_KEY);
        Map<String, String> values = ProviderConfigurator.subset(configuration, VALUES_PREFIX);
        if (file == null && directory == null && values.isEmpty()) {
            throw new IllegalArgumentException("The dynamic-configuration provider needs at least one of '" + PATH_KEY
                    + "', '" + DIRECTORY_KEY + "' or '" + VALUES_PREFIX + "<name>'");
        }
        DynamicConfiguration.Builder builder = DynamicConfiguration.builder();
        if (file != null) {
            builder.requiredFile(Path.of(file));
        }
        if (directory != null) {
            Path dir = Path.of(directory);
            if (!Files.isDirectory(dir)) {
                throw new SecretManagerException("The secrets directory " + dir + " does not exist");
            }
            builder.directory(dir);
        }
        builder.values(values);
        try {
            return new DynamicConfigurationClient(builder.build());
        } catch (ConfigurationException e) {
            throw new SecretManagerException("Cannot load the secrets", e);
        }
    }
}
