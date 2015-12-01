package com.securepreferences;

/**
 * Exception thrown when anything fails inside the {@link SecurePreferences}.
 *
 * @author Ondrej Cermak (cermak)
 */
public class SecurePreferencesException extends RuntimeException {
    /**
     * Constructs a new {@code Exception} with the current stack trace, the
     * specified detail message and the specified cause.
     *
     * @param detailMessage
     *            the detail message for this exception.
     * @param throwable
     *            the cause of this exception.
     */
    public SecurePreferencesException(String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
    }
}
