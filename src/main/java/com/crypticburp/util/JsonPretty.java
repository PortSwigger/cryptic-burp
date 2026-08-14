package com.crypticburp.util;

/**
 * A small JSON pretty-printer with no libraries behind it.
 *
 * <p>It parses the whole input as JSON first, and only if that works does it print
 * it back out with two-space indenting. If the input isn't valid JSON, you get the
 * original text back untouched, so form data, opaque blobs, error messages, and
 * text that happens to have matching brackets but isn't JSON never get mangled.
 *
 * <p>Strings, numbers, and literals are copied straight from the source, so the
 * values and their escaping stay exactly the same. Only the spacing between things
 * changes.
 */
public final class JsonPretty {

    private static final String INDENT = "  ";

    private JsonPretty() {
    }

    public static String format(String input) {
        if (input == null) {
            return null;
        }
        String trimmed = input.trim();
        if (trimmed.isEmpty()) {
            return input;
        }
        char first = trimmed.charAt(0);
        if (first != '{' && first != '[') {
            return input;
        }
        try {
            Parser parser = new Parser(trimmed);
            StringBuilder out = new StringBuilder(trimmed.length() + 32);
            parser.parseValue(out, 0);
            parser.skipWhitespace();
            if (!parser.atEnd()) {
                return input;
            }
            return out.toString();
        } catch (RuntimeException e) {
            return input;
        }
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return i >= s.length();
        }

        void skipWhitespace() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        private char peek() {
            if (i >= s.length()) {
                throw new IllegalStateException("unexpected end");
            }
            return s.charAt(i);
        }

        void parseValue(StringBuilder out, int depth) {
            skipWhitespace();
            char c = peek();
            switch (c) {
                case '{':
                    parseObject(out, depth);
                    break;
                case '[':
                    parseArray(out, depth);
                    break;
                case '"':
                    parseString(out);
                    break;
                default:
                    parseScalar(out);
                    break;
            }
        }

        private void parseObject(StringBuilder out, int depth) {
            i++; // eat the '{'
            skipWhitespace();
            if (!atEnd() && peek() == '}') {
                i++;
                out.append("{}");
                return;
            }
            out.append('{');
            while (true) {
                newline(out, depth + 1);
                skipWhitespace();
                if (peek() != '"') {
                    throw new IllegalStateException("expected key");
                }
                parseString(out);
                skipWhitespace();
                if (peek() != ':') {
                    throw new IllegalStateException("expected ':'");
                }
                i++;
                out.append(": ");
                parseValue(out, depth + 1);
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    i++;
                    out.append(',');
                } else if (c == '}') {
                    i++;
                    break;
                } else {
                    throw new IllegalStateException("expected ',' or '}'");
                }
            }
            newline(out, depth);
            out.append('}');
        }

        private void parseArray(StringBuilder out, int depth) {
            i++; // eat the '['
            skipWhitespace();
            if (!atEnd() && peek() == ']') {
                i++;
                out.append("[]");
                return;
            }
            out.append('[');
            while (true) {
                newline(out, depth + 1);
                parseValue(out, depth + 1);
                skipWhitespace();
                char c = peek();
                if (c == ',') {
                    i++;
                    out.append(',');
                } else if (c == ']') {
                    i++;
                    break;
                } else {
                    throw new IllegalStateException("expected ',' or ']'");
                }
            }
            newline(out, depth);
            out.append(']');
        }

        private void parseString(StringBuilder out) {
            int start = i;
            i++; // eat the opening quote
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == '\\') {
                    i += 2;
                } else if (c == '"') {
                    i++;
                    out.append(s, start, i);
                    return;
                } else {
                    i++;
                }
            }
            throw new IllegalStateException("unterminated string");
        }

        private void parseScalar(StringBuilder out) {
            int start = i;
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ',' || c == '}' || c == ']' || Character.isWhitespace(c)) {
                    break;
                }
                i++;
            }
            String token = s.substring(start, i);
            if (!isValidLiteral(token)) {
                throw new IllegalStateException("invalid token: " + token);
            }
            out.append(token);
        }

        private static boolean isValidLiteral(String token) {
            if (token.equals("true") || token.equals("false") || token.equals("null")) {
                return true;
            }
            return token.matches("-?(?:0|[1-9]\\d*)(?:\\.\\d+)?(?:[eE][+-]?\\d+)?");
        }
    }

    private static void newline(StringBuilder out, int depth) {
        out.append('\n');
        for (int d = 0; d < depth; d++) {
            out.append(INDENT);
        }
    }
}
