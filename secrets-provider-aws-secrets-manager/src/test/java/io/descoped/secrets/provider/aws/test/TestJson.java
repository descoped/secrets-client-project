package io.descoped.secrets.provider.aws.test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A small JSON reader for the fake's requests: objects, arrays, strings, numbers, literals. Test code only. */
final class TestJson {

    private final String text;
    private int pos;

    private TestJson(String text) {
        this.text = text;
    }

    static Object parse(String text) {
        TestJson reader = new TestJson(text);
        Object value = reader.value();
        reader.space();
        if (reader.pos != text.length()) {
            throw new IllegalArgumentException("Content after the value");
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> object(String text) {
        return (Map<String, Object>) parse(text);
    }

    private void space() {
        while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
            pos++;
        }
    }

    private Object value() {
        space();
        char c = text.charAt(pos);
        if (c == '{') {
            return obj();
        }
        if (c == '[') {
            return arr();
        }
        if (c == '"') {
            return str();
        }
        int start = pos;
        while (pos < text.length() && ",}] \n\r\t".indexOf(text.charAt(pos)) < 0) {
            pos++;
        }
        String literal = text.substring(start, pos);
        return switch (literal) {
            case "true" -> Boolean.TRUE;
            case "false" -> Boolean.FALSE;
            case "null" -> null;
            default -> Double.parseDouble(literal);
        };
    }

    private Map<String, Object> obj() {
        Map<String, Object> map = new LinkedHashMap<>();
        pos++;
        space();
        if (text.charAt(pos) == '}') {
            pos++;
            return map;
        }
        while (true) {
            space();
            String key = str();
            space();
            expect(':');
            map.put(key, value());
            space();
            if (text.charAt(pos) == '}') {
                pos++;
                return map;
            }
            expect(',');
        }
    }

    private List<Object> arr() {
        List<Object> list = new ArrayList<>();
        pos++;
        space();
        if (text.charAt(pos) == ']') {
            pos++;
            return list;
        }
        while (true) {
            list.add(value());
            space();
            if (text.charAt(pos) == ']') {
                pos++;
                return list;
            }
            expect(',');
        }
    }

    private String str() {
        expect('"');
        StringBuilder out = new StringBuilder();
        while (true) {
            char c = text.charAt(pos++);
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char e = text.charAt(pos++);
            switch (e) {
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                    pos += 4;
                }
                default -> out.append(e);
            }
        }
    }

    private void expect(char c) {
        if (text.charAt(pos) != c) {
            throw new IllegalArgumentException("Expected '" + c + "' at " + pos);
        }
        pos++;
    }

    /** {@code value} as a JSON string literal, escaped as AWS escapes. */
    static String quote(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }
}
