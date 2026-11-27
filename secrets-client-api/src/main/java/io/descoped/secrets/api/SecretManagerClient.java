package io.descoped.secrets.api;

import io.descoped.service.provider.api.ProviderConfigurator;

import java.util.Map;
import java.util.Objects;

/**
 * Reads and writes secrets through a provider chosen by configuration.
 *
 * <pre>{@code
 * try (SecretManagerClient client = SecretManagerClient.create(Map.of(
 *         "secrets.provider", "safe-configuration",
 *         "secrets.property-resource-path", "/run/secrets/app.properties"))) {
 *     try (Secret password = client.read("db.password")) {
 *         password.withChars(chars -> {
 *             connect(chars);
 *             return null;
 *         });
 *     }
 * }
 * }</pre>
 *
 * <h2>Contract</h2>
 * Every provider behaves the same way:
 * <ul>
 *     <li>A secret or version that does not exist throws {@link SecretNotFoundException}.</li>
 *     <li>Any other failure throws {@link SecretManagerException}. Messages name the secret, never its value.</li>
 *     <li>{@link #read(String, String)} returns a new {@link Secret} that the caller owns and closes; closing the
 *     client closes it too. The client never keeps a reference to it, nor to a value passed to
 *     {@link #addVersion(String, Secret)}.</li>
 *     <li>A provider that cannot write throws {@link UnsupportedOperationException} from
 *     {@link #addVersion(String, Secret)}.</li>
 *     <li>After {@link #close()}, every method except {@code close()} throws {@link IllegalStateException}.
 *     {@code close()} is idempotent and wipes what the client holds in memory.</li>
 *     <li>Clients are thread-safe.</li>
 * </ul>
 *
 * <p>Values are only ever handed over as a {@link Secret}, in guarded memory off the Java heap. The caller uses the
 * value with {@link Secret#withSegment}, or with {@link Secret#withBytes} or {@link Secret#withChars}, whose heap copies
 * are wiped when the call returns.
 */
public interface SecretManagerClient extends AutoCloseable {

    /**
     * The configuration key that names the provider, e.g. {@code safe-configuration}.
     */
    String PROVIDER_KEY = "secrets.provider";

    /**
     * Reads a version of a secret into guarded memory. The secret is the caller's: close it when it is no longer
     * needed. Closing the client closes it too.
     *
     * @param secretName    the name of the secret
     * @param secretVersion the version to read, or {@code null} for the latest
     * @return the value, to close when it is no longer needed
     * @throws SecretNotFoundException if the secret or the version does not exist
     * @throws SecretManagerException  if the secret cannot be read, or guarded memory is not available (see
     *                                 {@link SecretMemory})
     * @throws IllegalStateException   if the client is closed
     * @throws NullPointerException    if {@code secretName} is {@code null}
     */
    Secret read(String secretName, String secretVersion);

    /**
     * Reads the latest version of a secret into guarded memory; see {@link #read(String, String)}.
     *
     * @param secretName the name of the secret
     * @return the value, to close when it is no longer needed
     * @throws SecretNotFoundException if the secret does not exist
     * @throws SecretManagerException  if the secret cannot be read, or guarded memory is not available
     * @throws IllegalStateException   if the client is closed
     * @throws NullPointerException    if {@code secretName} is {@code null}
     */
    default Secret read(String secretName) {
        return read(secretName, null);
    }

    /**
     * Adds a new version of a secret from guarded memory, creating the secret if it does not exist. The client
     * copies the value; the caller still owns {@code secretValue} and closes it. To write a value the caller holds
     * as bytes or characters, copy it into guarded memory first with {@link SecretMemory#fromBytes} or
     * {@link SecretMemory#fromChars}, which wipe the array.
     *
     * @param secretName  the name of the secret
     * @param secretValue the value of the new version
     * @return the id of the new version, as {@link #read(String, String)} accepts it
     * @throws SecretManagerException        if the version cannot be added
     * @throws UnsupportedOperationException if the provider is read-only
     * @throws IllegalStateException         if the client or {@code secretValue} is closed
     * @throws NullPointerException          if an argument is {@code null}
     */
    String addVersion(String secretName, Secret secretValue);

    /**
     * Closes the client and wipes what it holds in memory, including the secrets {@link #read(String, String)}
     * returned, after the callbacks running on them in other threads. Idempotent.
     *
     * @throws IllegalStateException if called inside a callback of a secret the client returned: the client is closed
     *                               then, and a later {@code close()} wipes the memory
     */
    @Override
    void close();

    /**
     * Creates a client for the provider named by {@value #PROVIDER_KEY}. The whole map is passed to the provider;
     * each provider documents the keys it reads.
     *
     * <p>Providers are found with {@link java.util.ServiceLoader}. This module declares {@code uses} for
     * {@link SecretManagerClientInitializer}, so a provider module on the module path is resolved without anyone
     * requiring it.
     *
     * @param configuration the configuration, including {@value #PROVIDER_KEY}
     * @return a new client
     * @throws IllegalArgumentException if {@value #PROVIDER_KEY} is missing or blank, or the provider lacks a required
     *                                  key
     * @throws io.descoped.service.provider.api.ProviderException if no provider, or more than one, has that name
     * @throws SecretManagerException   if the provider cannot be initialized
     * @throws NullPointerException     if {@code configuration}, or a key or value in it, is {@code null}
     */
    static SecretManagerClient create(Map<String, String> configuration) {
        Objects.requireNonNull(configuration, "configuration");
        String provider = configuration.get(PROVIDER_KEY);
        if (provider == null || provider.isBlank()) {
            throw new IllegalArgumentException("Missing configuration '" + PROVIDER_KEY + "'");
        }
        return ProviderConfigurator.configure(SecretManagerClientInitializer.class, provider, configuration);
    }
}
