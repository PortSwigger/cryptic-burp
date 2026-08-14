package com.crypticburp.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * How to read the key/IV text from the UI into raw bytes.
 */
public enum KeyFormat {
    ASCII("ASCII"),
    HEX("Hex"),
    BASE64("Base64");

    private final String displayName;

    KeyFormat(String displayName) {
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
    public static KeyFormat fromDisplayName(String name, KeyFormat fallback) {
        if (name != null) {
            for (KeyFormat k : values()) {
                if (k.displayName.equalsIgnoreCase(name) || k.name().equalsIgnoreCase(name)) {
                    return k;
                }
            }
        }
        return fallback;
    }

    public byte[] toBytes(String value) throws CryptoException {
        try {
            switch (this) {
                case HEX:
                    return hexToBytes(value.replaceAll("\\s", ""));
                case BASE64:
                    return Base64.getDecoder().decode(value.trim());
                case ASCII:
                default:
                    return value.getBytes(StandardCharsets.UTF_8);
            }
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("key/IV is not valid " + displayName);
        }
    }

    private static byte[] hexToBytes(String hex) throws CryptoException {
        if (hex.length() % 2 != 0) {
            throw new CryptoException("hex key has an odd number of digits");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new CryptoException("hex key contains a non-hex character");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
