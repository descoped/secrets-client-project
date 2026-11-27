package io.descoped.secrets.provider.safe;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerClientInitializer;
import io.descoped.service.provider.api.ProviderName;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/**
 * The provider {@code safe-configuration}: secrets in a local file, for local development and tests. It is not meant
 * for production: a file of secrets on disk is only as safe as the disk and its permissions. Use the Google Secret
 * Manager provider there.
 *
 * <p>The file is read, parsed and rewritten in guarded memory ({@link io.descoped.secrets.api.SecretMemory}), and
 * every value is held there: no value is on the Java heap unless the caller asks for a heap copy (the hand-over
 * callbacks of {@link io.descoped.secrets.api.Secret}). This needs native access
 * ({@code --enable-native-access=io.descoped.secrets.api}); without it, creating the client fails unless
 * {@value io.descoped.secrets.api.SecretMemory#GUARD_KEY} is {@code off}.
 *
 * <table>
 *     <caption>Configuration</caption>
 *     <tr><th>Key</th><th>Value</th></tr>
 *     <tr><td>{@code secrets.provider}</td><td>{@code safe-configuration}</td></tr>
 *     <tr><td>{@value #PATH_KEY}</td><td>path of the secrets file (required)</td></tr>
 *     <tr><td>{@value io.descoped.secrets.api.SecretMemory#GUARD_KEY},
 *     {@value io.descoped.secrets.api.SecretMemory#LOCK_KEY}</td><td>the guarded memory, see
 *     {@link io.descoped.secrets.api.SecretMemory}</td></tr>
 * </table>
 *
 * <h2>File format</h2>
 * <ul>
 *     <li>UTF-8 (a leading byte-order mark is skipped), lines end with LF or CRLF.</li>
 *     <li>One {@code key=value} per line. The first {@code =} separates key and value; blanks (space, tab, form
 *     feed, vertical tab) around the key are removed, the value is taken byte for byte, including surrounding
 *     blanks and further {@code =}. There are no escapes, so values cannot contain line breaks.</li>
 *     <li>Empty lines, lines of blanks and lines whose first non-blank character is {@code #} are ignored.</li>
 *     <li>A line without {@code =}, an empty key and a duplicate key are errors, reported with the line number.</li>
 * </ul>
 *
 * <p>This is not the {@link java.util.Properties} format: {@code \}, {@code :} and {@code !} have no special meaning.
 *
 * <p>The file is read once, when the client is created; the only version is {@code latest}. {@code addVersion}
 * replaces the key's line in place, or appends one, and keeps every other line. It replaces the file (the target of
 * a symbolic link) atomically by a new file, which is owned by the writing user and readable and writable by that
 * user only: a file that others were allowed to read, by group or otherwise, is not after a write. A file system that
 * cannot move atomically, a name the format cannot hold and a value with a line break are
 * {@link io.descoped.secrets.api.SecretManagerException}s.
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
        // No state: ServiceLoader needs a public no-argument constructor, the work is done in initialize.
    }

    @Override
    public Set<String> configurationKeys() {
        return Set.of(PATH_KEY);
    }

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        return new SafeConfigurationClient(Path.of(configuration.get(PATH_KEY)), configuration);
    }
}
