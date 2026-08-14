package com.crypticburp.crypto;

/**
 * The cipher and mode, but without the padding. We add the padding to the
 * JCE transformation string later, per operation, based on the {@link Padding}.
 * That's what lets one config decrypt, for example, a Tab-padded query string and a
 * PKCS7-padded body using the same key.
 */
public enum CipherSpec {
    AES_CBC("AES/CBC", "AES", 16, Kind.BLOCK),
    AES_CTR("AES/CTR", "AES", 16, Kind.STREAM),
    AES_ECB("AES/ECB", "AES", 16, Kind.BLOCK_NO_IV),
    AES_GCM("AES/GCM", "AES", 16, Kind.AEAD),
    DES_CBC("DES/CBC", "DES", 8, Kind.BLOCK),
    DESEDE_CBC("DESede/CBC", "DESede", 8, Kind.BLOCK);

    private enum Kind { BLOCK, BLOCK_NO_IV, STREAM, AEAD }

    private final String base;
    private final String keyAlgorithm;
    private final int blockSize;
    private final Kind kind;

    CipherSpec(String base, String keyAlgorithm, int blockSize, Kind kind) {
        this.base = base;
        this.keyAlgorithm = keyAlgorithm;
        this.blockSize = blockSize;
        this.kind = kind;
    }

    public String displayName() {
        return base;
    }

    @Override
    public String toString() {
        return base;
    }

    /** Find one by its display name, ignoring case. Returns the fallback if nothing matches. */
    public static CipherSpec fromDisplayName(String name, CipherSpec fallback) {
        if (name != null) {
            for (CipherSpec c : values()) {
                if (c.base.equalsIgnoreCase(name) || c.name().equalsIgnoreCase(name)) {
                    return c;
                }
            }
        }
        return fallback;
    }

    public String keyAlgorithm() {
        return keyAlgorithm;
    }

    public int blockSize() {
        return blockSize;
    }

    public boolean usesIv() {
        return kind != Kind.BLOCK_NO_IV;
    }

    /** IV/nonce length in bytes: 12 for GCM's standard nonce, otherwise the block size. */
    public int ivLength() {
        return isAead() ? 12 : blockSize;
    }

    public boolean isAead() {
        return kind == Kind.AEAD;
    }

    /** Stream and GCM modes don't use block padding. */
    public boolean acceptsBlockPadding() {
        return kind == Kind.BLOCK || kind == Kind.BLOCK_NO_IV;
    }

    /** True when we have to add/remove the padding ourselves for this padding choice. */
    public boolean needsManualPadding(Padding padding) {
        return acceptsBlockPadding() && padding.isManual();
    }

    public String transformation(Padding padding) {
        if (acceptsBlockPadding() && padding.isPkcs7()) {
            return base + "/PKCS5Padding";
        }
        return base + "/NoPadding";
    }
}
