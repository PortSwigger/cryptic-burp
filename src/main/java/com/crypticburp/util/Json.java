package com.crypticburp.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A tiny JSON reader and writer, no libraries needed, used for profile files and
 * saved settings.
 *
 * <p>{@link #parse(String)} gives you back a {@link Map} for an object, a
 * {@link List} for an array, or a {@link String}, {@link Long}/{@link Double},
 * {@link Boolean}, or {@code null}, and throws {@link IllegalArgumentException} if
 * the input is broken. {@link #write(Object)} prints those same types back out
 * with two-space indenting.
 */
public final class Json {

    private static final String INDENT = "  ";

    private Json() {
    }

    public static Object parse(String text) {
        return new P(text).parseTop();
    }

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value, 0);
        return sb.toString();
    }

    /** Write it all on one line with no extra spaces. */
    public static String writeCompact(Object value) {
        StringBuilder sb = new StringBuilder();
        writeCompactValue(sb, value);
        return sb.toString();
    }

    /**
     * If {@code text} is valid JSON, hand it back minified (all the extra spacing
     * stripped out). If it isn't, hand it back as-is. We use this to squash edited
     * plaintext down to compact form before encrypting, no matter how it looked on
     * screen.
     */
    public static String minifyOrOriginal(String text) {
        if (text == null) {
            return null;
        }
        String trimmed = text.trim();
        if (trimmed.isEmpty()) {
            return text;
        }
        char first = trimmed.charAt(0);
        if (first != '{' && first != '[') {
            return text;
        }
        try {
            return writeCompact(parse(trimmed));
        } catch (RuntimeException e) {
            return text;
        }
    }

    private static void writeCompactValue(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            writeString(sb, (String) v);
        } else if (v instanceof Boolean) {
            sb.append(v.toString());
        } else if (v instanceof Number) {
            sb.append(numberToString((Number) v));
        } else if (v instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) v;
            sb.append('{');
            int i = 0;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (i++ > 0) {
                    sb.append(',');
                }
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                writeCompactValue(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List) {
            List<?> list = (List<?>) v;
            sb.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                writeCompactValue(sb, list.get(i));
            }
            sb.append(']');
        } else {
            writeString(sb, v.toString());
        }
    }

    private static void writeValue(StringBuilder sb, Object v, int depth) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            writeString(sb, (String) v);
        } else if (v instanceof Boolean) {
            sb.append(v.toString());
        } else if (v instanceof Number) {
            sb.append(numberToString((Number) v));
        } else if (v instanceof Map) {
            writeObject(sb, (Map<?, ?>) v, depth);
        } else if (v instanceof List) {
            writeArray(sb, (List<?>) v, depth);
        } else {
            writeString(sb, v.toString());
        }
    }

    private static String numberToString(Number n) {
        double d = n.doubleValue();
        if (d == Math.floor(d) && !Double.isInfinite(d) && Math.abs(d) < 1e15) {
            return Long.toString((long) d);
        }
        return n.toString();
    }

    private static void writeObject(StringBuilder sb, Map<?, ?> map, int depth) {
        if (map.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append('{');
        int idx = 0;
        for (Map.Entry<?, ?> e : map.entrySet()) {
            newline(sb, depth + 1);
            writeString(sb, String.valueOf(e.getKey()));
            sb.append(": ");
            writeValue(sb, e.getValue(), depth + 1);
            if (++idx < map.size()) {
                sb.append(',');
            }
        }
        newline(sb, depth);
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, List<?> list, int depth) {
        if (list.isEmpty()) {
            sb.append("[]");
            return;
        }
        sb.append('[');
        for (int i = 0; i < list.size(); i++) {
            newline(sb, depth + 1);
            writeValue(sb, list.get(i), depth + 1);
            if (i + 1 < list.size()) {
                sb.append(',');
            }
        }
        newline(sb, depth);
        sb.append(']');
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    private static void newline(StringBuilder sb, int depth) {
        sb.append('\n');
        for (int i = 0; i < depth; i++) {
            sb.append(INDENT);
        }
    }

    private static final class P {
        private final String s;
        private int i;

        P(String s) {
            this.s = s;
        }

        Object parseTop() {
            skip();
            Object v = parseValue();
            skip();
            if (i < s.length()) {
                throw err("trailing content");
            }
            return v;
        }

        private Object parseValue() {
            skip();
            char c = peek();
            switch (c) {
                case '{': return parseObject();
                case '[': return parseArray();
                case '"': return parseString();
                case 't':
                case 'f': return parseBool();
                case 'n': return parseNull();
                default: return parseNumber();
            }
        }

        private Map<String, Object> parseObject() {
            LinkedHashMap<String, Object> m = new LinkedHashMap<>();
            i++;
            skip();
            if (peek() == '}') {
                i++;
                return m;
            }
            while (true) {
                skip();
                if (peek() != '"') {
                    throw err("expected key");
                }
                String key = parseString();
                skip();
                if (peek() != ':') {
                    throw err("expected ':'");
                }
                i++;
                m.put(key, parseValue());
                skip();
                char c = peek();
                if (c == ',') {
                    i++;
                } else if (c == '}') {
                    i++;
                    break;
                } else {
                    throw err("expected ',' or '}'");
                }
            }
            return m;
        }

        private List<Object> parseArray() {
            ArrayList<Object> a = new ArrayList<>();
            i++;
            skip();
            if (peek() == ']') {
                i++;
                return a;
            }
            while (true) {
                a.add(parseValue());
                skip();
                char c = peek();
                if (c == ',') {
                    i++;
                } else if (c == ']') {
                    i++;
                    break;
                } else {
                    throw err("expected ',' or ']'");
                }
            }
            return a;
        }

        private String parseString() {
            StringBuilder sb = new StringBuilder();
            i++;
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (i >= s.length()) {
                        break;
                    }
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'u':
                            if (i + 4 > s.length()) {
                                throw err("bad unicode escape");
                            }
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                            break;
                        default: throw err("bad escape");
                    }
                } else {
                    sb.append(c);
                }
            }
            throw err("unterminated string");
        }

        private Object parseBool() {
            if (s.startsWith("true", i)) {
                i += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", i)) {
                i += 5;
                return Boolean.FALSE;
            }
            throw err("bad literal");
        }

        private Object parseNull() {
            if (s.startsWith("null", i)) {
                i += 4;
                return null;
            }
            throw err("bad literal");
        }

        private Object parseNumber() {
            int start = i;
            while (i < s.length() && "-+.eE0123456789".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            String token = s.substring(start, i);
            if (token.isEmpty()) {
                throw err("unexpected character");
            }
            try {
                if (token.contains(".") || token.contains("e") || token.contains("E")) {
                    return Double.parseDouble(token);
                }
                return Long.parseLong(token);
            } catch (NumberFormatException e) {
                throw err("bad number: " + token);
            }
        }

        private char peek() {
            if (i >= s.length()) {
                throw err("unexpected end");
            }
            return s.charAt(i);
        }

        private void skip() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        private IllegalArgumentException err(String msg) {
            return new IllegalArgumentException("JSON parse error at index " + i + ": " + msg);
        }
    }
}
