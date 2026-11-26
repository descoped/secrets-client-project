package io.descoped.secrets.api;

import io.descoped.service.provider.api.ProviderConfigurator;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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
 *         password.withChars(chars -> connect(chars));
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
 *     client closes it too. {@link #readBytes(String, String)} returns a new array that the caller owns and should
 *     wipe after use. The client never keeps a reference to either, nor to a value passed to {@code addVersion}.</li>
 *     <li>A provider that cannot write throws {@link UnsupportedOperationException} from
 *     {@link #addVersion(String, byte[])}.</li>
 *     <li>After {@link #close()}, every method except {@code close()} throws {@link IllegalStateException}.
 *     {@code close()} is idempotent and wipes what the client holds in memory.</li>
 *     <li>Clients are thread-safe.</li>
 * </ul>
 *
 * <p>{@link #read(String)} keeps the value off the Java heap: use it, and hand the value over with
 * {@link Secret#withSegment}, {@link Secret#withBytes} or {@link Secret#withChars}, whose heap copies are wiped when
 * the call returns. {@link #readBytes(String)} and {@link #readChars(String)} return heap copies for the caller to
 * wipe; {@link #readString(String)} is a convenience for values that are not sensitive or end up in a {@link String}
 * anyway: a {@code String} is immutable and cannot be wiped.
 */
public interface SecretManagerClient extends AutoCloseable {

    /**
     * The configuration key that names the provider, e.g. {@code safe-configuration}.
     */
    String PROVIDER_KEY = "secrets.provider";

    /**
     * Reads a version of a secret.
     *
     * @param secretName    the name of the secret
     * @param secretVersion the version to read, or {@code null} for the latest
     * @return a new array with the value, owned by the caller
     * @throws SecretNotFoundException if the secret or the version does not exist
     * @throws SecretManagerException  if the secret cannot be read
     * @throws IllegalStateException   if the client is closed
     * @throws NullPointerException    if {@code secretName} is {@code null}
     */
    byte[] readBytes(String secretName, String secretVersion);

    /**
     * Reads the latest version of a secret.
     *
     * @param secretName the name of the secret
     * @return a new array with the value, owned by the caller
     * @throws SecretNotFoundException if the secret does not exist
     * @throws SecretManagerException  if the secret cannot be read
     * @throws IllegalStateException   if the client is closed
     * @throws NullPointerException    if {@code secretName} is {@code null}
     */
    default byte[] readBytes(String secretName) {
        return readBytes(secretName, null);
    }

    /**
     * Reads a version of a secret as UTF-8 characters. The intermediate bytes are wiped.
     *
     * @param secretName    the name of the secret
     * @param secretVersion the version to read, or {@code null} for the latest
     * @return a new array with the value, owned by the caller
     * @throws SecretNotFoundException if the secret or the version does not exist
     * @throws SecretManagerException  if the secret cannot be read or is not valid UTF-8
     * @throws IllegalStateException   if the client is closed
     * @throws NullPointerException    if {@code secretName} is {@code null}
     */
    default char[] readChars(String secretName, String secretVersion) {
        byte[] bytes = readBytes(secretName, secretVersion);
        try {
            return decodeUtf8(bytes);
        } catch (CharacterCodingException e) {
            throw new SecretManagerException("Secret '" + secretName + "' is not valid UTF-8", e);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Reads the latest version of a secret as UTF-8 characters. The intermediate bytes are wiped.
     *
     * @param secretName the name of the secret
     * @return a new array with the value, owned by the caller
     * @throws SecretNotFoundException if the secret does not exist
     * @throws SecretManagerException  if the secret cannot be read or is not valid UTF-8
     * @throws IllegalStateException   if the client is closed
     * @throws NullPointerException    if {@code secretName} is {@code null}
     */
    default char[] readChars(String secretName) {
        return readChars(secretName, null);
    }

    /**
     * Reads a version of a secret as a UTF-8 string. A {@code String} cannot be wiped; see the class description.
     *
     * @param secretName    the name of the secret
     * @param secretVersion the version to read, or {@code null} for the latest
     * @return the value
     * @throws SecretNotFoundException if the secret or the version does not exist
     * @throws SecretManagerException  if the secret cannot be read or is not valid UTF-8
     * @throws IllegalStateException   if the client is closed
     * @throws NullPointerException    if {@code secretName} is {@code null}
     */
    default String readString(String secretName, String secretVersion) {
        char[] chars = readChars(secretName, secretVersion);
        try {
            return new String(chars);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Reads the latest version of a secret as a UTF-8 string. A {@code String} cannot be wiped; see the class
     * description.
     *
     * @param secretName the name of the secret
     * @return the value
     * @throws SecretNotFoundException if the secret does not exist
     * @throws SecretManagerException  if the secret cannot be read or is not valid UTF-8
     * @throws IllegalStateException   if the client is closed
     * @throws NullPointerException    if {@code secretName} is {@code null}
     */
    default String readString(String secretName) {
        return readString(secretName, null);
    }

    /**
     * Reads a version of a secret into guarded memory. The secret is the caller's: close it when it is no longer
     * needed. Closing the client closes it too.
     *
     * <p>A provider built on guarded memory never puts the value on the Java heap on the way: safe-configuration
     * does. A provider not rebuilt yet (Google Secret Manager, dynamic-configuration) reads it as
     * {@link #readBytes(String, String)} does and copies it into guarded memory, wiping its own array.
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
     * copies the value; the caller still owns {@code secretValue} and closes it.
     *
     * <p>A provider built on guarded memory never puts the value on the Java heap on the way: safe-configuration
     * does. This default, for providers not rebuilt yet, hands a heap copy to
     * {@link #addVersion(String, byte[])} and wipes it when that returns.
     *
     * @param secretName  the name of the secret
     * @param secretValue the value of the new version
     * @return the id of the new version
     * @throws SecretManagerException        if the version cannot be added
     * @throws UnsupportedOperationException if the provider is read-only
     * @throws IllegalStateException         if the client or {@code secretValue} is closed
     * @throws NullPointerException          if an argument is {@code null}
     */
    default String addVersion(String secretName, Secret secretValue) {
        Objects.requireNonNull(secretName, "secretName");
        Objects.requireNonNull(secretValue, "secretValue");
        return secretValue.withBytes(bytes -> addVersion(secretName, bytes));
    }

    /**
     * Adds a new version of a secret, creating the secret if it does not exist. The client copies
     * {@code secretValue}; the caller still owns it and may wipe it afterwards.
     *
     * @param secretName  the name of the secret
     * @param secretValue the value of the new version
     * @return the id of the new version, as {@link #readBytes(String, String)} accepts it
     * @throws SecretManagerException        if the version cannot be added
     * @throws UnsupportedOperationException if the provider is read-only
     * @throws IllegalStateException         if the client is closed
     * @throws NullPointerException          if an argument is {@code null}
     */
    String addVersion(String secretName, byte[] secretValue);

    /**
     * Adds a new version of a secret from characters, encoded as UTF-8. The intermediate bytes are wiped.
     *
     * @param secretName  the name of the secret
     * @param secretValue the value of the new version
     * @return the id of the new version
     * @throws SecretManagerException        if the version cannot be added, or the value has an unpaired surrogate
     * @throws UnsupportedOperationException if the provider is read-only
     * @throws IllegalStateException         if the client is closed
     * @throws NullPointerException          if an argument is {@code null}
     */
    default String addVersion(String secretName, char[] secretValue) {
        Objects.requireNonNull(secretValue, "secretValue");
        ByteBuffer encoded;
        try {
            encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(secretValue));
        } catch (CharacterCodingException e) {
            throw new SecretManagerException("The value for secret '" + secretName + "' is not valid UTF-16", e);
        }
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        wipe(encoded);
        try {
            return addVersion(secretName, bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Adds a new version of a secret from a string, as UTF-8.
     *
     * @param secretName  the name of the secret
     * @param secretValue the value of the new version
     * @return the id of the new version
     * @throws SecretManagerException        if the version cannot be added, or the value has an unpaired surrogate
     * @throws UnsupportedOperationException if the provider is read-only
     * @throws IllegalStateException         if the client is closed
     * @throws NullPointerException          if an argument is {@code null}
     */
    default String addVersion(String secretName, String secretValue) {
        Objects.requireNonNull(secretValue, "secretValue");
        char[] chars = secretValue.toCharArray();
        try {
            return addVersion(secretName, chars);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    /**
     * Closes the client and wipes what it holds in memory. Idempotent.
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

    private static char[] decodeUtf8(byte[] bytes) throws CharacterCodingException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        // UTF-8 never decodes to more chars than it has bytes.
        char[] buffer = new char[bytes.length];
        try {
            CharBuffer out = CharBuffer.wrap(buffer);
            ByteBuffer in = ByteBuffer.wrap(bytes);
            check(decoder.decode(in, out, true));
            check(decoder.flush(out));
            return Arrays.copyOf(buffer, out.position());
        } finally {
            Arrays.fill(buffer, '\0');
        }
    }

    private static void check(CoderResult result) throws CharacterCodingException {
        if (result.isError()) {
            result.throwException();
        }
    }

    private static void wipe(ByteBuffer buffer) {
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), (byte) 0);
        } else {
            buffer.clear();
            while (buffer.hasRemaining()) {
                buffer.put((byte) 0);
            }
        }
    }
}
