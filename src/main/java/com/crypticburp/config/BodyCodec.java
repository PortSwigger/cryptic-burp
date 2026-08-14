package com.crypticburp.config;

import com.crypticburp.crypto.CryptoException;
import com.crypticburp.crypto.CryptoService;
import com.crypticburp.crypto.Padding;
import com.crypticburp.util.Json;
import com.crypticburp.util.JsonPretty;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds the ciphertext in a body and decrypts or encrypts it, based on the
 * {@link BodyType}: the whole body (RAW), one JSON string field, or one field in
 * URL-encoded form data.
 *
 * <p>The field handling doesn't pull in any libraries and assumes the ciphertext
 * is a plain string value (Base64 or hex). Nested structures aren't handled.
 */
public final class BodyCodec {

    private BodyCodec() {
    }

    public static String decryptBody(CryptoService crypto, String body, BodyType type,
                                     String field, Padding padding) throws CryptoException {
        return decryptBody(crypto, body, type, field, padding, false);
    }

    /**
     * Decrypt for viewing. If {@code pretty} is on, JSON plaintext gets
     * pretty-printed as long as that won't break re-encrypting it later. Anything
     * that isn't JSON comes back as-is.
     */
    public static String decryptBody(CryptoService crypto, String body, BodyType type,
                                     String field, Padding padding, boolean pretty) throws CryptoException {
        switch (type) {
            case RAW: {
                String plain = crypto.decrypt(body.trim(), padding);
                return pretty ? JsonPretty.format(plain) : plain;
            }
            case JSON_FIELD: {
                requireField(field);
                String value = jsonGet(body, field);
                if (value == null) {
                    throw new CryptoException("JSON field '" + field + "' not found");
                }
                String decrypted = crypto.decrypt(value, padding);
                String out = jsonSet(body, field, decrypted);
                return pretty ? JsonPretty.format(out) : out;
            }
            case FORM_FIELD: {
                requireField(field);
                return formTransform(crypto, body, field, padding, true, pretty);
            }
            default: {
                String plain = crypto.decrypt(body.trim(), padding);
                return pretty ? JsonPretty.format(plain) : plain;
            }
        }
    }

    public static String encryptBody(CryptoService crypto, String body, BodyType type,
                                     String field, Padding padding) throws CryptoException {
        switch (type) {
            case RAW:
                return crypto.encrypt(Json.minifyOrOriginal(body.trim()), padding);
            case JSON_FIELD: {
                requireField(field);
                String value = jsonGet(body, field);
                if (value == null) {
                    throw new CryptoException("JSON field '" + field + "' not found");
                }
                String encrypted = crypto.encrypt(Json.minifyOrOriginal(value), padding);
                return jsonSet(body, field, encrypted);
            }
            case FORM_FIELD: {
                requireField(field);
                return formTransform(crypto, body, field, padding, false, false);
            }
            default:
                return crypto.encrypt(Json.minifyOrOriginal(body.trim()), padding);
        }
    }

    private static void requireField(String field) throws CryptoException {
        if (field == null || field.isEmpty()) {
            throw new CryptoException("a field name is required for this body type");
        }
    }

    private static String formTransform(CryptoService crypto, String body, String field,
                                        Padding padding, boolean decrypt, boolean pretty) throws CryptoException {
        String[] pairs = body.split("&");
        boolean hit = false;
        for (int i = 0; i < pairs.length; i++) {
            int eq = pairs[i].indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = pairs[i].substring(0, eq);
            String value = pairs[i].substring(eq + 1);
            if (key.equals(field)) {
                String out;
                if (decrypt) {
                    out = crypto.decrypt(value, padding);
                    if (pretty) {
                        out = JsonPretty.format(out);
                    }
                } else {
                    out = crypto.encrypt(Json.minifyOrOriginal(value), padding);
                }
                pairs[i] = key + "=" + out;
                hit = true;
            }
        }
        if (!hit) {
            throw new CryptoException("form field '" + field + "' not found");
        }
        return String.join("&", pairs);
    }

    private static String jsonGet(String json, String field) {
        Matcher m = fieldPattern(field).matcher(json);
        return m.find() ? unescapeJson(m.group(1)) : null;
    }

    private static String jsonSet(String json, String field, String value) {
        Matcher m = fieldPattern(field).matcher(json);
        if (!m.find()) {
            return json;
        }
        // We splice the string in by hand instead of using appendReplacement, so
        // don't call quoteReplacement here. If we did, every backslash in the
        // value would get doubled up.
        String replacement = "\"" + field + "\":\"" + escapeJson(value) + "\"";
        return json.substring(0, m.start()) + replacement + json.substring(m.end());
    }

    private static Pattern fieldPattern(String field) {
        return Pattern.compile("\"" + Pattern.quote(field) + "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String unescapeJson(String s) {
        return s.replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
