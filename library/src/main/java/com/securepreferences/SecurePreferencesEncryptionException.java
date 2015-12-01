package com.securepreferences;

/**
 * Internal exception thrown when encyption/decryption fails inside the {@link SecurePreferences}.
 *
 * @author Ondrej Cermak (cermak)
 */
class SecurePreferencesEncryptionException extends Exception {
    /**
     * Constructs a new {@code Exception} with the current stack trace, the
     * specified detail message and the specified cause.
     *
     * @param detailMessage
     *            the detail message for this exception.
     * @param throwable
     *            the cause of this exception.
     */
    public SecurePreferencesEncryptionException(String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
    }
}
