package io.descoped.secrets.provider.google;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.zip.CRC32C;

/**
 * Encodings applied to secrets, from native memory to native memory: Base64, JSON string escapes, form encoding, and
 * CRC32C. Nothing here copies a byte to the Java heap; every method also works on heap segments, for values that are
 * not secret.
 */
final class Codec {

    private static final byte[] BASE64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".getBytes(
                    java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] HEX = "0123456789ABCDEF".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private Codec() {
    }

    /** A value that is not valid in its encoding. Never names the value. */
    static final class MalformedException extends Exception {
        @java.io.Serial
        private static final long serialVersionUID = 1L;

        MalformedException(String what) {
            super(what, null, false, false);
        }
    }

    private static byte get(MemorySegment segment, long index) {
        return segment.get(ValueLayout.JAVA_BYTE, index);
    }

    private static void put(MemorySegment segment, long index, int value) {
        segment.set(ValueLayout.JAVA_BYTE, index, (byte) value);
    }

    // Base64 (RFC 4648, standard alphabet, with padding)

    static long base64EncodedLength(long length) {
        return (length + 2) / 3 * 4;
    }

    /** Writes {@code src} as Base64 into {@code dst} at {@code offset}; returns the offset after it. */
    static long base64Encode(MemorySegment src, MemorySegment dst, long offset) {
        long n = src.byteSize();
        long out = offset;
        long i = 0;
        for (; i + 3 <= n; i += 3) {
            int bits = (get(src, i) & 0xFF) << 16 | (get(src, i + 1) & 0xFF) << 8 | get(src, i + 2) & 0xFF;
            put(dst, out++, BASE64[bits >>> 18 & 0x3F]);
            put(dst, out++, BASE64[bits >>> 12 & 0x3F]);
            put(dst, out++, BASE64[bits >>> 6 & 0x3F]);
            put(dst, out++, BASE64[bits & 0x3F]);
        }
        long rest = n - i;
        if (rest > 0) {
            int bits = (get(src, i) & 0xFF) << 16 | (rest == 2 ? (get(src, i + 1) & 0xFF) << 8 : 0);
            put(dst, out++, BASE64[bits >>> 18 & 0x3F]);
            put(dst, out++, BASE64[bits >>> 12 & 0x3F]);
            put(dst, out++, rest == 2 ? BASE64[bits >>> 6 & 0x3F] : '=');
            put(dst, out++, '=');
        }
        return out;
    }

    private static int base64Value(byte b) {
        if (b >= 'A' && b <= 'Z') {
            return b - 'A';
        }
        if (b >= 'a' && b <= 'z') {
            return b - 'a' + 26;
        }
        if (b >= '0' && b <= '9') {
            return b - '0' + 52;
        }
        if (b == '+') {
            return 62;
        }
        if (b == '/') {
            return 63;
        }
        return -1;
    }

    /**
     * The number of bytes {@code src} decodes to: Base64 with or without padding, no line breaks.
     *
     * @throws MalformedException if it is not Base64
     */
    static long base64DecodedLength(MemorySegment src) throws MalformedException {
        long n = src.byteSize();
        long padding = 0;
        if (n > 0 && get(src, n - 1) == '=') {
            padding = n > 1 && get(src, n - 2) == '=' ? 2 : 1;
            if (n % 4 != 0) {
                throw new MalformedException("Base64 padding");
            }
        }
        long data = n - padding;
        for (long i = 0; i < data; i++) {
            if (base64Value(get(src, i)) < 0) {
                throw new MalformedException("Base64 character");
            }
        }
        long rest = data % 4;
        if (rest == 1) {
            throw new MalformedException("Base64 length");
        }
        return data / 4 * 3 + (rest == 0 ? 0 : rest - 1);
    }

    /** Decodes {@code src}, checked by {@link #base64DecodedLength(MemorySegment)}, into {@code dst}. */
    static void base64Decode(MemorySegment src, MemorySegment dst) {
        long out = 0;
        int bits = 0;
        int count = 0;
        long n = src.byteSize();
        for (long i = 0; i < n; i++) {
            int value = base64Value(get(src, i));
            if (value < 0) {
                break;
            }
            bits = bits << 6 | value;
            if (++count == 4) {
                put(dst, out++, bits >>> 16);
                put(dst, out++, bits >>> 8);
                put(dst, out++, bits);
                bits = 0;
                count = 0;
            }
        }
        if (count == 3) {
            put(dst, out++, bits >>> 10);
            put(dst, out, bits >>> 2);
        } else if (count == 2) {
            put(dst, out, bits >>> 4);
        }
    }

    // JSON string escapes (RFC 8259)

    /**
     * The length in UTF-8 bytes of the JSON string content {@code src} (between the quotes) once unescaped.
     *
     * @throws MalformedException if an escape is invalid
     */
    static long unescapedLength(MemorySegment src) throws MalformedException {
        return unescape(src, null);
    }

    /**
     * Unescapes the JSON string content {@code src} into {@code dst} (as UTF-8), or only measures it when {@code dst}
     * is {@code null}; returns the length.
     *
     * @throws MalformedException if an escape is invalid
     */
    static long unescape(MemorySegment src, MemorySegment dst) throws MalformedException {
        return new Unescaper(src, dst).run();
    }

    /** Walks a JSON string's content once, writing (or only counting) the unescaped bytes. */
    private static final class Unescaper {
        private final MemorySegment src;
        private final MemorySegment dst;
        private long in;
        private long out;

        Unescaper(MemorySegment src, MemorySegment dst) {
            this.src = src;
            this.dst = dst;
        }

        long run() throws MalformedException {
            long n = src.byteSize();
            while (in < n) {
                byte b = get(src, in);
                if (b == '\\') {
                    escape();
                } else {
                    emit(b);
                    in++;
                }
            }
            return out;
        }

        private void emit(int b) {
            if (dst != null) {
                put(dst, out, b);
            }
            out++;
        }

        private void escape() throws MalformedException {
            if (in + 1 >= src.byteSize()) {
                throw new MalformedException("JSON escape");
            }
            byte e = get(src, in + 1);
            if (e == 'u') {
                unicode();
            } else {
                emit(simpleEscape(e));
                in += 2;
            }
        }

        private void unicode() throws MalformedException {
            int cp = hex4(src, in + 2);
            in += 6;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (in + 6 > src.byteSize() || get(src, in) != '\\' || get(src, in + 1) != 'u') {
                    throw new MalformedException("JSON surrogate");
                }
                int low = hex4(src, in + 2);
                if (low < 0xDC00 || low > 0xDFFF) {
                    throw new MalformedException("JSON surrogate");
                }
                cp = 0x10000 + (cp - 0xD800 << 10) + (low - 0xDC00);
                in += 6;
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                throw new MalformedException("JSON surrogate");
            }
            out = putUtf8(dst, out, cp);
        }

        private static int simpleEscape(byte e) throws MalformedException {
            return switch (e) {
                case '"', '\\', '/' -> e;
                case 'b' -> '\b';
                case 'f' -> '\f';
                case 'n' -> '\n';
                case 'r' -> '\r';
                case 't' -> '\t';
                default -> throw new MalformedException("JSON escape");
            };
        }

        private static int hex4(MemorySegment src, long at) throws MalformedException {
            if (at + 4 > src.byteSize()) {
                throw new MalformedException("JSON escape");
            }
            int value = 0;
            for (int k = 0; k < 4; k++) {
                int digit = Character.digit(get(src, at + k), 16);
                if (digit < 0) {
                    throw new MalformedException("JSON escape");
                }
                value = value << 4 | digit;
            }
            return value;
        }

        private static int utf8Length(int cp) {
            if (cp < 0x80) {
                return 1;
            }
            if (cp < 0x800) {
                return 2;
            }
            return cp < 0x10000 ? 3 : 4;
        }

        private static long putUtf8(MemorySegment dst, long out, int cp) {
            int length = utf8Length(cp);
            if (dst != null) {
                switch (length) {
                    case 1 -> put(dst, out, cp);
                    case 2 -> {
                        put(dst, out, 0xC0 | cp >> 6);
                        put(dst, out + 1, 0x80 | cp & 0x3F);
                    }
                    case 3 -> {
                        put(dst, out, 0xE0 | cp >> 12);
                        put(dst, out + 1, 0x80 | cp >> 6 & 0x3F);
                        put(dst, out + 2, 0x80 | cp & 0x3F);
                    }
                    default -> {
                        put(dst, out, 0xF0 | cp >> 18);
                        put(dst, out + 1, 0x80 | cp >> 12 & 0x3F);
                        put(dst, out + 2, 0x80 | cp >> 6 & 0x3F);
                        put(dst, out + 3, 0x80 | cp & 0x3F);
                    }
                }
            }
            return out + length;
        }
    }

    // application/x-www-form-urlencoded

    private static boolean unreserved(byte b) {
        return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '.'
                || b == '_' || b == '~';
    }

    /** The length of {@code src} percent-encoded. */
    static long formEncodedLength(MemorySegment src) {
        long length = 0;
        for (long i = 0; i < src.byteSize(); i++) {
            length += unreserved(get(src, i)) ? 1 : 3;
        }
        return length;
    }

    /** Writes {@code src} percent-encoded into {@code dst} at {@code offset}; returns the offset after it. */
    static long formEncode(MemorySegment src, MemorySegment dst, long offset) {
        long out = offset;
        for (long i = 0; i < src.byteSize(); i++) {
            byte b = get(src, i);
            if (unreserved(b)) {
                put(dst, out++, b);
            } else {
                put(dst, out++, '%');
                put(dst, out++, HEX[b >> 4 & 0xF]);
                put(dst, out++, HEX[b & 0xF]);
            }
        }
        return out;
    }

    /** The CRC32C of {@code value}, read in place. */
    static long crc32c(MemorySegment value) {
        CRC32C crc = new CRC32C();
        if (value.isNative()) {
            crc.update(value.asByteBuffer());
        } else {
            crc.update(value.toArray(ValueLayout.JAVA_BYTE));
        }
        return crc.getValue();
    }

    /** Copies bytes that are not secret into {@code dst} at {@code offset}; returns the offset after them. */
    static long putBytes(MemorySegment dst, long offset, byte[] bytes) {
        MemorySegment.copy(bytes, 0, dst, ValueLayout.JAVA_BYTE, offset, bytes.length);
        return offset + bytes.length;
    }

    /** Copies {@code src} into {@code dst} at {@code offset}; returns the offset after it. */
    static long putSegment(MemorySegment dst, long offset, MemorySegment src) {
        MemorySegment.copy(src, 0, dst, offset, src.byteSize());
        return offset + src.byteSize();
    }
}
