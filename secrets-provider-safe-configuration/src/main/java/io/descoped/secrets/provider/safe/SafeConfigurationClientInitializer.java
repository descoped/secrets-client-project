package io.descoped.secrets.provider.safe;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerClientInitializer;
import io.descoped.service.provider.api.ProviderName;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/**
 * The provider {@code safe-configuration}: secrets in a local file, held in memory as bytes and wiped on close.
 *
 * <table>
 *     <caption>Configuration</caption>
 *     <tr><th>Key</th><th>Value</th></tr>
 *     <tr><td>{@code secrets.provider}</td><td>{@code safe-configuration}</td></tr>
 *     <tr><td>{@value #PATH_KEY}</td><td>path of the secrets file (required)</td></tr>
 * </table>
 *
 * <h2>File format</h2>
 * <ul>
 *     <li>UTF-8 (a leading byte-order mark is skipped), lines end with LF or CRLF.</li>
 *     <li>One {@code key=value} per line. The first {@code =} separates key and value; the key is trimmed, the value
 *     is taken byte for byte, including surrounding whitespace and further {@code =}. There are no escapes, so
 *     values cannot contain line breaks.</li>
 *     <li>Blank lines and lines whose first non-blank character is {@code #} are ignored.</li>
 *     <li>A line without {@code =}, an empty key and a duplicate key are errors, reported with the line number.</li>
 * </ul>
 *
 * <p>This is not the {@link java.util.Properties} format: {@code \}, {@code :} and {@code !} have no special meaning.
 *
 * <p>The file is read once, when the client is created. {@code addVersion} writes the value to the file (see
 * {@code SafeConfigurationClient#addVersion}); the only version is {@code latest}.
 */
@ProviderName("safe-configuration")
public final class SafeConfigurationClientInitializer implements SecretManagerClientInitializer {

    /**
     * The configuration key for the path of the secrets file.
     */
    public static final String PATH_KEY = "secrets.property-resource-path";

    /**
     * Creates the initializer; called by {@link java.util.ServiceLoader}.
     */
    public SafeConfigurationClientInitializer() {
    }

    @Override
    public Set<String> configurationKeys() {
        return Set.of(PATH_KEY);
    }

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        return new SafeConfigurationClient(Path.of(configuration.get(PATH_KEY)));
    }
}
