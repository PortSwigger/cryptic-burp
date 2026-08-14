package com.crypticburp.crypto;

/**
 * Where the IV comes from for each operation.
 */
public enum IvMode {
    /** One fixed IV: the IV field, or the key itself when "same as key" is on. */
    FIXED("Fixed"),
    /**
     * A fresh random IV for every message, stuck on the front of the ciphertext
     * before encoding: {@code encode(IV || ciphertext)}. Lots of apps that build
     * their own AES-CBC/CTR/GCM do it this way.
     */
    PREPENDED("Prepended to ciphertext");

    private final String displayName;

    IvMode(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }

    /** Find one by its display name, ignoring case. Returns the fallback if nothing matches. */
    public static IvMode fromDisplayName(String name, IvMode fallback) {
        if (name != null) {
            for (IvMode m : values()) {
                if (m.displayName.equalsIgnoreCase(name) || m.name().equalsIgnoreCase(name)) {
                    return m;
                }
            }
        }
        return fallback;
    }
}
