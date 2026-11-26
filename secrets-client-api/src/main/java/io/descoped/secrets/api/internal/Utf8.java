package io.descoped.secrets.api.internal;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Arrays;

/**
 * UTF-8 between off-heap memory and {@code char} arrays, without the JDK's charset coders: they copy direct buffers
 * to heap arrays of their own, which nobody wipes. Strict: overlong forms, surrogates and code points above U+10FFFF
 * are malformed, and so is an unpaired surrogate in the chars.
 */
public final class Utf8 {

    private Utf8() {
    }

    /** Thrown for malformed input. Says nothing about the input. */
    public static final class MalformedException extends Exception {
        private static final long serialVersionUID = 1L;

        MalformedException() {
            super(null, null, false, false);
        }
    }

    /**
     * Decodes {@code bytes} into a new array of exactly the right length.
     *
     * @throws MalformedException if the bytes are not valid UTF-8; nothing has been allocated then
     */
    public static char[] decode(MemorySegment bytes) throws MalformedException {
        int length = Math.toIntExact(scan(bytes, null));
        char[] chars = new char[length];
        try {
            scan(bytes, chars);
        } catch (MalformedException e) {
            // Not reached, the first pass validated the input; but never leave a partial copy behind.
            Arrays.fill(chars, '\0');
            throw e;
        }
        return chars;
    }

    /**
     * Validates {@code bytes}, and decodes them into {@code out} unless it is {@code null}.
     *
     * @return the number of chars
     */
    private static long scan(MemorySegment bytes, char[] out) throws MalformedException {
        long size = bytes.byteSize();
        long i = 0;
        int n = 0;
        while (i < size) {
            int b0 = at(bytes, i);
            if (b0 < 0x80) {
                if (out != null) {
                    out[n] = (char) b0;
                }
                n++;
                i++;
                continue;
            }
            int count;
            int min;
            int max = 0xBF;
            int codePoint;
            if (b0 >= 0xC2 && b0 <= 0xDF) {
                count = 1;
                min = 0x80;
                codePoint = b0 & 0x1F;
            } else if (b0 >= 0xE0 && b0 <= 0xEF) {
                count = 2;
                min = b0 == 0xE0 ? 0xA0 : 0x80;
                max = b0 == 0xED ? 0x9F : 0xBF;
                codePoint = b0 & 0x0F;
            } else if (b0 >= 0xF0 && b0 <= 0xF4) {
                count = 3;
                min = b0 == 0xF0 ? 0x90 : 0x80;
                max = b0 == 0xF4 ? 0x8F : 0xBF;
                codePoint = b0 & 0x07;
            } else {
                throw new MalformedException();
            }
            // The continuation bytes are at i + 1 .. i + count.
            if (i + count >= size) {
                throw new MalformedException();
            }
            for (int k = 1; k <= count; k++) {
                int b = at(bytes, i + k);
                int low = k == 1 ? min : 0x80;
                int high = k == 1 ? max : 0xBF;
                if (b < low || b > high) {
                    throw new MalformedException();
                }
                codePoint = codePoint << 6 | b & 0x3F;
            }
            if (codePoint >= 0x10000) {
                if (out != null) {
                    out[n] = Character.highSurrogate(codePoint);
                    out[n + 1] = Character.lowSurrogate(codePoint);
                }
                n += 2;
            } else {
                if (out != null) {
                    out[n] = (char) codePoint;
                }
                n++;
            }
            i += count + 1;
        }
        return n;
    }

    private static int at(MemorySegment bytes, long index) {
        return bytes.get(ValueLayout.JAVA_BYTE, index) & 0xFF;
    }

    /**
     * The number of bytes {@code chars} encode to.
     *
     * @throws MalformedException if {@code chars} has an unpaired surrogate
     */
    public static long encodedLength(char[] chars) throws MalformedException {
        long length = 0;
        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];
            if (c < 0x80) {
                length += 1;
            } else if (c < 0x800) {
                length += 2;
            } else if (Character.isHighSurrogate(c)) {
                if (i + 1 >= chars.length || !Character.isLowSurrogate(chars[i + 1])) {
                    throw new MalformedException();
                }
                length += 4;
                i++;
            } else if (Character.isLowSurrogate(c)) {
                throw new MalformedException();
            } else {
                length += 3;
            }
        }
        return length;
    }

    /**
     * Encodes {@code chars}, which {@link #encodedLength(char[])} has validated, into {@code out}, which is exactly
     * that long.
     */
    public static void encode(char[] chars, MemorySegment out) {
        long o = 0;
        for (int i = 0; i < chars.length; i++) {
            int c = chars[i];
            if (Character.isHighSurrogate(chars[i])) {
                c = Character.toCodePoint(chars[i], chars[i + 1]);
                i++;
            }
            if (c < 0x80) {
                put(out, o++, c);
            } else if (c < 0x800) {
                put(out, o++, 0xC0 | c >> 6);
                put(out, o++, 0x80 | c & 0x3F);
            } else if (c < 0x10000) {
                put(out, o++, 0xE0 | c >> 12);
                put(out, o++, 0x80 | c >> 6 & 0x3F);
                put(out, o++, 0x80 | c & 0x3F);
            } else {
                put(out, o++, 0xF0 | c >> 18);
                put(out, o++, 0x80 | c >> 12 & 0x3F);
                put(out, o++, 0x80 | c >> 6 & 0x3F);
                put(out, o++, 0x80 | c & 0x3F);
            }
        }
    }

    private static void put(MemorySegment out, long index, int b) {
        out.set(ValueLayout.JAVA_BYTE, index, (byte) b);
    }
}
