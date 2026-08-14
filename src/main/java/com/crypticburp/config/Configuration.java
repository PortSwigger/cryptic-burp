package com.crypticburp.config;

import com.crypticburp.crypto.CipherSpec;
import com.crypticburp.crypto.Encoding;
import com.crypticburp.crypto.IvMode;
import com.crypticburp.crypto.KeyFormat;
import com.crypticburp.crypto.Padding;
import com.crypticburp.util.Json;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A read-only copy of every setting. Converts to and from JSON so it can be saved
 * between restarts and stored in profile files you can edit.
 */
public final class Configuration {

    private final String targetHost;
    private final String targetPath;

    private final CipherSpec cipher;
    private final String key;
    private final String iv;
    private final KeyFormat keyFormat;
    private final boolean ivSameAsKey;
    private final IvMode ivMode;
    private final Encoding encoding;

    private final LocationConfig query;
    private final LocationConfig requestBody;
    private final LocationConfig responseBody;

    public Configuration(String targetHost, String targetPath, CipherSpec cipher, String key, String iv,
                         KeyFormat keyFormat, boolean ivSameAsKey, IvMode ivMode, Encoding encoding,
                         LocationConfig query, LocationConfig requestBody, LocationConfig responseBody) {
        this.targetHost = targetHost == null ? "" : targetHost;
        this.targetPath = targetPath == null ? "" : targetPath;
        this.cipher = cipher;
        this.key = key == null ? "" : key;
        this.iv = iv == null ? "" : iv;
        this.keyFormat = keyFormat;
        this.ivSameAsKey = ivSameAsKey;
        this.ivMode = ivMode == null ? IvMode.FIXED : ivMode;
        this.encoding = encoding;
        this.query = query;
        this.requestBody = requestBody;
        this.responseBody = responseBody;
    }

    public static Configuration defaults() {
        return new Configuration(
                "", "",
                CipherSpec.AES_CBC, "", "", KeyFormat.ASCII, true, IvMode.FIXED, Encoding.BASE64,
                new LocationConfig(true, BodyType.RAW, "", Padding.TAB),
                new LocationConfig(false, BodyType.RAW, "", Padding.PKCS7),
                new LocationConfig(true, BodyType.RAW, "", Padding.PKCS7));
    }

    public String targetHost() { return targetHost; }
    public String targetPath() { return targetPath; }
    public CipherSpec cipher() { return cipher; }
    public String key() { return key; }
    public String iv() { return iv; }
    public KeyFormat keyFormat() { return keyFormat; }
    public boolean ivSameAsKey() { return ivSameAsKey; }
    public IvMode ivMode() { return ivMode; }
    public Encoding encoding() { return encoding; }
    public LocationConfig query() { return query; }
    public LocationConfig requestBody() { return requestBody; }
    public LocationConfig responseBody() { return responseBody; }

    /**
     * Checks whether a request is in scope. The host has to match exactly
     * (ignoring case) and the path has to start with the path prefix, where a
     * trailing {@code *} means "anything after this". Empty filters match
     * everything.
     */
    public boolean hostPathMatches(String host, String pathWithoutQuery) {
        if (!targetHost.isEmpty()) {
            if (host == null || !host.equalsIgnoreCase(targetHost)) {
                return false;
            }
        }
        if (!targetPath.isEmpty()) {
            String prefix = targetPath.endsWith("*")
                    ? targetPath.substring(0, targetPath.length() - 1)
                    : targetPath;
            if (pathWithoutQuery == null || !pathWithoutQuery.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }

    public String toJson() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("targetHost", targetHost);
        m.put("targetPath", targetPath);
        m.put("cipher", cipher.displayName());
        m.put("key", key);
        m.put("iv", iv);
        m.put("keyFormat", keyFormat.displayName());
        m.put("ivSameAsKey", ivSameAsKey);
        m.put("ivMode", ivMode.displayName());
        m.put("encoding", encoding.displayName());
        m.put("query", locationToMap(query, false));
        m.put("requestBody", locationToMap(requestBody, true));
        m.put("responseBody", locationToMap(responseBody, true));
        return Json.write(m);
    }

    public static Configuration fromJson(String text) {
        Configuration d = defaults();
        Object parsed;
        try {
            parsed = Json.parse(text);
        } catch (RuntimeException e) {
            return d;
        }
        if (!(parsed instanceof Map)) {
            return d;
        }
        Map<?, ?> m = (Map<?, ?>) parsed;
        return new Configuration(
                str(m, "targetHost", d.targetHost),
                str(m, "targetPath", d.targetPath),
                CipherSpec.fromDisplayName(str(m, "cipher", null), d.cipher),
                str(m, "key", d.key),
                str(m, "iv", d.iv),
                KeyFormat.fromDisplayName(str(m, "keyFormat", null), d.keyFormat),
                bool(m, "ivSameAsKey", d.ivSameAsKey),
                IvMode.fromDisplayName(str(m, "ivMode", null), d.ivMode),
                Encoding.fromDisplayName(str(m, "encoding", null), d.encoding),
                locationFrom(m.get("query"), d.query),
                locationFrom(m.get("requestBody"), d.requestBody),
                locationFrom(m.get("responseBody"), d.responseBody));
    }

    private static Map<String, Object> locationToMap(LocationConfig loc, boolean withType) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", loc.enabled());
        if (withType) {
            m.put("type", loc.type().displayName());
            m.put("field", loc.field());
        }
        m.put("padding", loc.padding().displayName());
        return m;
    }

    private static LocationConfig locationFrom(Object node, LocationConfig d) {
        if (!(node instanceof Map)) {
            return d;
        }
        Map<?, ?> m = (Map<?, ?>) node;
        return new LocationConfig(
                bool(m, "enabled", d.enabled()),
                BodyType.fromDisplayName(str(m, "type", d.type().displayName())),
                str(m, "field", d.field()),
                Padding.fromDisplayName(str(m, "padding", null), d.padding()));
    }

    private static String str(Map<?, ?> m, String key, String fallback) {
        Object v = m.get(key);
        return v != null ? v.toString() : fallback;
    }

    private static boolean bool(Map<?, ?> m, String key, boolean fallback) {
        Object v = m.get(key);
        if (v instanceof Boolean) {
            return (Boolean) v;
        }
        if (v != null) {
            return Boolean.parseBoolean(v.toString());
        }
        return fallback;
    }
}
