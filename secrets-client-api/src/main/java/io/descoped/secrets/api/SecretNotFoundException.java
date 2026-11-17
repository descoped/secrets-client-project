package io.descoped.secrets.api;

import java.io.Serial;

/**
 * The secret, or the requested version of it, does not exist.
 */
public class SecretNotFoundException extends SecretManagerException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * The name of the secret.
     */
    private final String secretName;

    /**
     * The requested version, or {@code null} for the latest.
     */
    private final String secretVersion;

    /**
     * Creates the exception.
     *
     * @param secretName    the name of the secret
     * @param secretVersion the requested version, or {@code null} for the latest
     */
    public SecretNotFoundException(String secretName, String secretVersion) {
        this(secretName, secretVersion, null);
    }

    /**
     * Creates the exception with a cause.
     *
     * @param secretName    the name of the secret
     * @param secretVersion the requested version, or {@code null} for the latest
     * @param cause         the cause, or {@code null}
     */
    public SecretNotFoundException(String secretName, String secretVersion, Throwable cause) {
        super(secretVersion == null
                ? "Secret '" + secretName + "' not found"
                : "Secret '" + secretName + "' version '" + secretVersion + "' not found", cause);
        this.secretName = secretName;
        this.secretVersion = secretVersion;
    }

    /**
     * Returns the name of the secret.
     *
     * @return the name of the secret
     */
    public String secretName() {
        return secretName;
    }

    /**
     * Returns the requested version.
     *
     * @return the requested version, or {@code null} for the latest
     */
    public String secretVersion() {
        return secretVersion;
    }
}
