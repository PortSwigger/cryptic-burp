package com.crypticburp.crypto;

/**
 * Thrown when we can't finish an encrypt or decrypt. Holds a short message that's
 * safe to show the user. Never contains the key.
 */
public class CryptoException extends Exception {
    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
