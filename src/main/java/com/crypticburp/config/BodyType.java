package com.crypticburp.config;

/**
 * Where to find the encrypted blob inside a request or response body.
 */
public enum BodyType {
    RAW("Raw"),
    JSON_FIELD("JSON field"),
    FORM_FIELD("Form field");

    private final String displayName;

    BodyType(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }

    public static BodyType fromDisplayName(String name) {
        if (name != null) {
            for (BodyType t : values()) {
                if (t.displayName.equalsIgnoreCase(name) || t.name().equalsIgnoreCase(name)) {
                    return t;
                }
            }
        }
        return RAW;
    }
}
