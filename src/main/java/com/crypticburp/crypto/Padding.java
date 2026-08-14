package com.crypticburp.crypto;

import java.util.Arrays;

/**
 * The padding added to plaintext before a NoPadding cipher, or {@link #PKCS7} to
 * let the JCE provider do the standard padding for us.
 *
 * <p>The Tab/Space/Null options copy what some mobile apps do to their app-layer
 * ciphertext: pad up to the next block boundary with one fixed byte, then trim
 * that byte back off on the way out. A whole extra block gets added even when the
 * input already lines up with a block, which matches what those apps do.
 */
public enum Padding {
    NONE("None", null, false),
    TAB("Tab (0x09)", (byte) 0x09, false),
    SPACE("Space (0x20)", (byte) 0x20, false),
    NULL("Null (0x00)", (byte) 0x00, false),
    PKCS7("PKCS7", null, true);

    private final String displayName;
    private final Byte padByte;
    private final boolean pkcs7;

    Padding(String displayName, Byte padByte, boolean pkcs7) {
        this.displayName = displayName;
        this.padByte = padByte;
        this.pkcs7 = pkcs7;
    }

    public String displayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }

    /** Find one by its display name, ignoring case. Returns the fallback if nothing matches. */
    public static Padding fromDisplayName(String name, Padding fallback) {
        if (name != null) {
            for (Padding p : values()) {
                if (p.displayName.equalsIgnoreCase(name) || p.name().equalsIgnoreCase(name)) {
                    return p;
                }
            }
        }
        return fallback;
    }

    public boolean isPkcs7() {
        return pkcs7;
    }

    /** True when we add and remove this padding ourselves (Tab/Space/Null). */
    public boolean isManual() {
        return padByte != null;
    }

    public byte[] pad(byte[] data, int blockSize) {
        if (!isManual()) {
            return data;
        }
        int padLen = blockSize - (data.length % blockSize);
        if (padLen == 0) {
            padLen = blockSize;
        }
        byte[] out = Arrays.copyOf(data, data.length + padLen);
        Arrays.fill(out, data.length, out.length, padByte);
        return out;
    }

    public byte[] strip(byte[] data) {
        if (!isManual()) {
            return data;
        }
        int end = data.length;
        while (end > 0 && data[end - 1] == padByte) {
            end--;
        }
        return Arrays.copyOf(data, end);
    }
}
