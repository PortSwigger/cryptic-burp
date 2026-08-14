package com.crypticburp.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * How the ciphertext bytes are written as text on the wire.
 */
public enum Encoding {
    BASE64("Base64"),
    BASE64_URLSAFE("Base64-URLSafe"),
    HEX("Hex"),
    NONE("None");

    private final String displayName;

    Encoding(String displayName) {
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
    public static Encoding fromDisplayName(String name, Encoding fallback) {
        if (name != null) {
            for (Encoding e : values()) {
                if (e.displayName.equalsIgnoreCase(name) || e.name().equalsIgnoreCase(name)) {
                    return e;
                }
            }
        }
        return fallback;
    }

    public byte[] decode(String text) throws CryptoException {
        String trimmed = text.trim();
        try {
            switch (this) {
                case BASE64:
                    return Base64.getDecoder().decode(stripWhitespace(trimmed));
                case BASE64_URLSAFE:
                    return Base64.getUrlDecoder().decode(stripWhitespace(trimmed));
                case HEX:
                    return hexToBytes(trimmed);
                case NONE:
                default:
                    return trimmed.getBytes(StandardCharsets.ISO_8859_1);
            }
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("not valid " + displayName + " input");
        }
    }

    public String encode(byte[] data) {
        switch (this) {
            case BASE64:
                return Base64.getEncoder().encodeToString(data);
            case BASE64_URLSAFE:
                return Base64.getUrlEncoder().encodeToString(data);
            case HEX:
                return bytesToHex(data);
            case NONE:
            default:
                return new String(data, StandardCharsets.ISO_8859_1);
        }
    }

    private static String stripWhitespace(String s) {
        return s.replaceAll("\\s", "");
    }

    private static byte[] hexToBytes(String hex) throws CryptoException {
        String clean = hex.replaceAll("\\s", "");
        if (clean.length() % 2 != 0) {
            throw new CryptoException("hex input has an odd number of digits");
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(clean.charAt(i * 2), 16);
            int lo = Character.digit(clean.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new CryptoException("hex input contains a non-hex character");
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
