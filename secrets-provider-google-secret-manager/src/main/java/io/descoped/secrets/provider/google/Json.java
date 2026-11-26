package io.descoped.secrets.provider.google;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A strict JSON reader (RFC 8259) over a segment, for the few response shapes this provider reads. It copies nothing:
 * strings and numbers are spans of the segment, so a secret in a string is decoded by the caller straight from the
 * segment into guarded memory ({@link Codec#unescape}). Only object keys, which are never secret, are put on the heap.
 * Errors never quote the input.
 */
final class Json {

    /** Nesting deeper than this is refused. */
    private static final int MAX_DEPTH = 32;

    /** A JSON value. */
    sealed interface Node permits Obj, Arr, Str, Num, Lit {
    }

    /** An object; its keys are unique. */
    record Obj(Map<String, Node> fields) implements Node {

        /** The field {@code name} if it is a string, else {@code null}. */
        Str string(String name) {
            return fields.get(name) instanceof Str s ? s : null;
        }

        /** The field {@code name} if it is an object, else {@code null}. */
        Obj object(String name) {
            return fields.get(name) instanceof Obj o ? o : null;
        }
    }

    /** An array. */
    record Arr(List<Node> elements) implements Node {
    }

    /** A string: its content between the quotes, still escaped, at {@code [start, end)}. */
    record Str(long start, long end) implements Node {

        /** The escaped content, a slice of {@code json}. */
        MemorySegment raw(MemorySegment json) {
            return json.asSlice(start, end - start);
        }
    }

    /** A number at {@code [start, end)}. */
    record Num(long start, long end) implements Node {
    }

    /** {@code true}, {@code false} or {@code null}. */
    record Lit(String value) implements Node {
    }

    private final MemorySegment json;
    private long pos;

    private Json(MemorySegment json) {
        this.json = json;
    }

    /**
     * Parses {@code json}, which must hold exactly one value (surrounded by whitespace at most).
     *
     * @throws Codec.MalformedException if it is not valid JSON
     */
    static Node parse(MemorySegment json) throws Codec.MalformedException {
        Json reader = new Json(json);
        reader.skipWhitespace();
        Node node = reader.value(0);
        reader.skipWhitespace();
        if (reader.pos != json.byteSize()) {
            throw new Codec.MalformedException("JSON: content after the value");
        }
        return node;
    }

    /**
     * A string that is not secret, as a Java string.
     *
     * @throws Codec.MalformedException if an escape is invalid
     */
    static String text(MemorySegment json, Str str) throws Codec.MalformedException {
        MemorySegment raw = str.raw(json);
        byte[] bytes = new byte[Math.toIntExact(Codec.unescapedLength(raw))];
        Codec.unescape(raw, MemorySegment.ofArray(bytes));
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** A number that is not secret, as a Java string. */
    static String text(MemorySegment json, Num num) {
        return new String(json.asSlice(num.start(), num.end() - num.start()).toArray(ValueLayout.JAVA_BYTE),
                StandardCharsets.US_ASCII);
    }

    private byte peek() throws Codec.MalformedException {
        if (pos >= json.byteSize()) {
            throw new Codec.MalformedException("JSON: unexpected end");
        }
        return json.get(ValueLayout.JAVA_BYTE, pos);
    }

    private void expect(char c) throws Codec.MalformedException {
        if (peek() != c) {
            throw new Codec.MalformedException("JSON: unexpected character");
        }
        pos++;
    }

    private void skipWhitespace() {
        while (pos < json.byteSize()) {
            byte b = json.get(ValueLayout.JAVA_BYTE, pos);
            if (b != ' ' && b != '\t' && b != '\n' && b != '\r') {
                return;
            }
            pos++;
        }
    }

    private Node value(int depth) throws Codec.MalformedException {
        if (depth > MAX_DEPTH) {
            throw new Codec.MalformedException("JSON: nested too deep");
        }
        return switch (peek()) {
            case '{' -> object(depth);
            case '[' -> array(depth);
            case '"' -> string();
            case 't' -> literal("true");
            case 'f' -> literal("false");
            case 'n' -> literal("null");
            default -> number();
        };
    }

    private Obj object(int depth) throws Codec.MalformedException {
        expect('{');
        Map<String, Node> fields = new LinkedHashMap<>();
        skipWhitespace();
        if (peek() == '}') {
            pos++;
            return new Obj(fields);
        }
        while (true) {
            skipWhitespace();
            String key = text(json, string());
            skipWhitespace();
            expect(':');
            skipWhitespace();
            if (fields.put(key, value(depth + 1)) != null) {
                throw new Codec.MalformedException("JSON: duplicate key");
            }
            skipWhitespace();
            if (peek() == '}') {
                pos++;
                return new Obj(fields);
            }
            expect(',');
        }
    }

    private Arr array(int depth) throws Codec.MalformedException {
        expect('[');
        List<Node> elements = new ArrayList<>();
        skipWhitespace();
        if (peek() == ']') {
            pos++;
            return new Arr(elements);
        }
        while (true) {
            skipWhitespace();
            elements.add(value(depth + 1));
            skipWhitespace();
            if (peek() == ']') {
                pos++;
                return new Arr(elements);
            }
            expect(',');
        }
    }

    private Str string() throws Codec.MalformedException {
        expect('"');
        long start = pos;
        while (true) {
            byte b = peek();
            if (b == '"') {
                pos++;
                return new Str(start, pos - 1);
            }
            if ((b & 0xFF) < 0x20) {
                throw new Codec.MalformedException("JSON: control character in a string");
            }
            // An escape is checked when the string is decoded; here it only must not end the string.
            pos += b == '\\' ? 2 : 1;
        }
    }

    private Lit literal(String word) throws Codec.MalformedException {
        for (int i = 0; i < word.length(); i++) {
            expect(word.charAt(i));
        }
        return new Lit(word);
    }

    private Num number() throws Codec.MalformedException {
        long start = pos;
        if (peek() == '-') {
            pos++;
        }
        if (peek() == '0') {
            pos++;
        } else {
            digits();
        }
        if (pos < json.byteSize() && peek() == '.') {
            pos++;
            digits();
        }
        if (pos < json.byteSize() && (peek() == 'e' || peek() == 'E')) {
            pos++;
            if (peek() == '+' || peek() == '-') {
                pos++;
            }
            digits();
        }
        return new Num(start, pos);
    }

    private void digits() throws Codec.MalformedException {
        if (!isDigit(peek())) {
            throw new Codec.MalformedException("JSON: unexpected character");
        }
        while (pos < json.byteSize() && isDigit(json.get(ValueLayout.JAVA_BYTE, pos))) {
            pos++;
        }
    }

    private static boolean isDigit(byte b) {
        return b >= '0' && b <= '9';
    }
}
