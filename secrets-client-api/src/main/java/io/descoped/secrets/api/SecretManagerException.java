package io.descoped.secrets.api;

import java.io.Serial;

/**
 * A secret could not be read or written. The message names the secret, never its value.
 */
public class SecretManagerException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Creates the exception.
     *
     * @param message what failed; must not contain a secret value
     */
    public SecretManagerException(String message) {
        super(message);
    }

    /**
     * Creates the exception with a cause.
     *
     * @param message what failed; must not contain a secret value
     * @param cause   the cause
     */
    public SecretManagerException(String message, Throwable cause) {
        super(message, cause);
    }
}
