package io.descoped.secrets.provider.mounted;

import io.descoped.secrets.api.SecretManagerClient;
import io.descoped.secrets.api.SecretManagerClientInitializer;
import io.descoped.service.provider.api.ProviderName;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/**
 * The provider {@code mounted}: secrets that the platform mounts as files, read-only. Cloud Run mounts Secret Manager
 * secrets as a volume, GKE and EKS have the Secrets Store CSI driver (with the Google and AWS providers), and
 * Kubernetes mounts its own secrets as a volume. The process holds no credential and has no network code for its
 * secrets: the platform fetches them.
 *
 * <p>Each read opens the file and reads it with a {@link java.nio.channels.FileChannel} straight into guarded memory
 * ({@link io.descoped.secrets.api.SecretMemory}): the value is never on the Java heap unless the caller asks for a
 * heap copy. A value is the file's bytes exactly, a trailing line break included. Files are read on every
 * {@code read}, never cached, so a value the platform rotates in place (Kubernetes) is seen at the next read. This
 * needs native access ({@code --enable-native-access=io.descoped.secrets.api}); without it, creating the client fails
 * unless {@value io.descoped.secrets.api.SecretMemory#GUARD_KEY} is {@code off}.
 *
 * <table>
 *     <caption>Configuration</caption>
 *     <tr><th>Key</th><th>Value</th></tr>
 *     <tr><td>{@code secrets.provider}</td><td>{@code mounted}</td></tr>
 *     <tr><td>{@value #DIRECTORY_KEY}</td><td>the directory the secrets are mounted under (required); it must
 *     exist when the client is created</td></tr>
 *     <tr><td>{@value io.descoped.secrets.api.SecretMemory#GUARD_KEY},
 *     {@value io.descoped.secrets.api.SecretMemory#LOCK_KEY}</td><td>the guarded memory, see
 *     {@link io.descoped.secrets.api.SecretMemory}</td></tr>
 * </table>
 *
 * <h2>Names</h2>
 * A secret's name is its file's path relative to the directory: {@code api-key} is {@code <directory>/api-key}, and
 * {@code db/password} is {@code <directory>/db/password} (Cloud Run mounts each secret in a directory of its own).
 * Each segment starts with a letter, digit or {@code _} and goes on with letters, digits, {@code _}, {@code -} and
 * {@code .}; a name that is not of this form, absolute, or with an empty segment is
 * {@link io.descoped.secrets.api.SecretNotFoundException}. Symbolic links are followed (Kubernetes links each file
 * into a {@code ..data} directory), but the file they lead to must be inside the directory; one outside it is a
 * {@link io.descoped.secrets.api.SecretManagerException}.
 *
 * <p>The only version is {@code latest} (or {@code null}): which version a file holds is the platform's choice,
 * made when the volume is mounted. A missing file, a directory and another version are
 * {@link io.descoped.secrets.api.SecretNotFoundException}. A file larger than 4 MiB is an error. {@code addVersion}
 * throws {@link UnsupportedOperationException}: the platform owns the files. A file that does not end (a FIFO without
 * a writer, a mount that hangs) blocks the read, and {@code close()} waits for reads in progress.
 */
@ProviderName("mounted")
public final class MountedClientInitializer implements SecretManagerClientInitializer {

    /**
     * The configuration key for the directory the secrets are mounted under.
     */
    public static final String DIRECTORY_KEY = "secrets.mounted.directory";

    /**
     * Creates the initializer; called by {@link java.util.ServiceLoader}.
     */
    public MountedClientInitializer() {
        // No state: ServiceLoader needs a public no-argument constructor, the work is done in initialize.
    }

    @Override
    public Set<String> configurationKeys() {
        return Set.of(DIRECTORY_KEY);
    }

    @Override
    public SecretManagerClient initialize(Map<String, String> configuration) {
        String directory = configuration.get(DIRECTORY_KEY);
        if (directory == null || directory.isBlank()) {
            throw new IllegalArgumentException("'" + DIRECTORY_KEY + "' is required");
        }
        return new MountedClient(Path.of(directory), configuration);
    }
}
