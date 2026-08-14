package com.crypticburp.config;

import com.crypticburp.crypto.Padding;

/**
 * Settings for one spot (query, request body, or response body): whether we touch
 * it, where the ciphertext is inside it, and which padding it uses. Keeping the
 * padding here, per spot, is what lets a single profile cover, for example, a Tab-padded
 * query and a PKCS7-padded body at the same time.
 */
public final class LocationConfig {

    private final boolean enabled;
    private final BodyType type;
    private final String field;
    private final Padding padding;

    public LocationConfig(boolean enabled, BodyType type, String field, Padding padding) {
        this.enabled = enabled;
        this.type = type;
        this.field = field == null ? "" : field;
        this.padding = padding;
    }

    public boolean enabled() {
        return enabled;
    }

    public BodyType type() {
        return type;
    }

    public String field() {
        return field;
    }

    public Padding padding() {
        return padding;
    }
}
