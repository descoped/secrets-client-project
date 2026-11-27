package io.descoped.secrets.api.http;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A JSON reader (RFC 8259, strict about structure and escapes; bytes above 0x7F are not checked as UTF-8) over a
 * segment, for the few response shapes the providers read. It copies nothing:
 * strings and numbers are spans of the segment, so a secret in a string is decoded by the caller straight from the
 * segment into guarded memory ({@link Codec#unescape}). Only object keys, which are never secret, are put on the heap.
 * Errors never quote the input.
 */
public final class Json {

    /** Nesting deeper than this is refused. */
    private static final int MAX_DEPTH = 32;

    /** A JSON value. */
    public sealed interface Node permits Obj, Arr, Str, Num, Lit {
    }

    /**
     * An object; its keys are unique.
     *
     * @param fields the fields by name
     */
    public record Obj(Map<String, Node> fields) implements Node {

        /**
         * The field {@code name} if it is a string.
         *
         * @param name the field's name
         * @return the string, or {@code null} if it is absent or not a string
         */
        public Str string(String name) {
            return fields.get(name) instanceof Str s ? s : null;
        }

        /**
         * The field {@code name} if it is an object.
         *
         * @param name the field's name
         * @return the object, or {@code null} if it is absent or not an object
         */
        public Obj object(String name) {
            return fields.get(name) instanceof Obj o ? o : null;
        }
    }

    /**
     * An array.
     *
     * @param elements the elements in order
     */
    public record Arr(List<Node> elements) implements Node {
    }

    /**
     * A string: its content between the quotes, still escaped, at {@code [start, end)}.
     *
     * @param start the offset of the first byte after the opening quote
     * @param end   the offset of the closing quote
     */
    public record Str(long start, long end) implements Node {

        /**
         * The escaped content, a slice of {@code json}.
         *
         * @param json the JSON this string was parsed from
         * @return the slice
         */
        public MemorySegment raw(MemorySegment json) {
            return json.asSlice(start, end - start);
        }
    }

    /**
     * A number at {@code [start, end)}.
     *
     * @param start the offset of its first character
     * @param end   the offset after its last character
     */
    public record Num(long start, long end) implements Node {
    }

    /**
     * {@code true}, {@code false} or {@code null}.
     *
     * @param value the literal
     */
    public record Lit(String value) implements Node {
    }

    private final MemorySegment json;
    private long pos;

    private Json(MemorySegment json) {
        this.json = json;
    }

    /**
     * Parses {@code json}, which must hold exactly one value (surrounded by whitespace at most).
     *
     * @param json the JSON, in place
     * @return the value; strings and numbers refer back to {@code json}
     * @throws Codec.MalformedException if it is not valid JSON
     */
    public static Node parse(MemorySegment json) throws Codec.MalformedException {
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
     * @param json the JSON {@code str} was parsed from
     * @param str  the string
     * @return the unescaped text
     * @throws Codec.MalformedException if an escape is invalid
     */
    public static String text(MemorySegment json, Str str) throws Codec.MalformedException {
        MemorySegment raw = str.raw(json);
        byte[] bytes = new byte[Math.toIntExact(Codec.unescapedLength(raw))];
        Codec.unescape(raw, MemorySegment.ofArray(bytes));
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * A number that is not secret, as a Java string.
     *
     * @param json the JSON {@code num} was parsed from
     * @param num  the number
     * @return its text
     */
    public static String text(MemorySegment json, Num num) {
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
