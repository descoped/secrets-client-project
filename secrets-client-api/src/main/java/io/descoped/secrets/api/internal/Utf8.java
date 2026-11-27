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
     * Whether {@code bytes} are valid UTF-8, read in place.
     *
     * @param bytes the bytes
     * @return {@code true} if they are valid UTF-8
     */
    public static boolean isValid(MemorySegment bytes) {
        try {
            scan(bytes, null);
            return true;
        } catch (MalformedException _) {
            return false;
        }
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
            int lead = at(bytes, i);
            int count = continuations(lead);
            // The continuation bytes are at i + 1 .. i + count.
            if (i + count >= size) {
                throw new MalformedException();
            }
            n += put(out, n, codePoint(bytes, i, lead, count));
            i += count + 1;
        }
        return n;
    }

    /** The code point of the sequence at {@code i}: {@code lead} and {@code count} continuation bytes. */
    private static int codePoint(MemorySegment bytes, long i, int lead, int count) throws MalformedException {
        if (count == 0) {
            return lead;
        }
        int codePoint = lead & (0x3F >> count);
        for (int k = 1; k <= count; k++) {
            int b = at(bytes, i + k);
            int min = k == 1 ? secondMin(lead) : 0x80;
            int max = k == 1 ? secondMax(lead) : 0xBF;
            if (b < min || b > max) {
                throw new MalformedException();
            }
            codePoint = codePoint << 6 | b & 0x3F;
        }
        return codePoint;
    }

    /** The number of continuation bytes after {@code lead}. */
    private static int continuations(int lead) throws MalformedException {
        if (lead < 0x80) {
            return 0;
        }
        if (lead >= 0xC2 && lead <= 0xDF) {
            return 1;
        }
        if (lead >= 0xE0 && lead <= 0xEF) {
            return 2;
        }
        if (lead >= 0xF0 && lead <= 0xF4) {
            return 3;
        }
        throw new MalformedException();
    }

    /** The lowest second byte after {@code lead}: higher after E0 and F0, which rules out overlong forms. */
    private static int secondMin(int lead) {
        return switch (lead) {
            case 0xE0 -> 0xA0;
            case 0xF0 -> 0x90;
            default -> 0x80;
        };
    }

    /** The highest second byte after {@code lead}: lower after ED (no surrogates) and F4 (nothing above U+10FFFF). */
    private static int secondMax(int lead) {
        return switch (lead) {
            case 0xED -> 0x9F;
            case 0xF4 -> 0x8F;
            default -> 0xBF;
        };
    }

    /** Puts {@code codePoint} at {@code out[n]} unless {@code out} is {@code null}; returns how many chars it takes. */
    private static int put(char[] out, int n, int codePoint) {
        if (codePoint < 0x10000) {
            if (out != null) {
                out[n] = (char) codePoint;
            }
            return 1;
        }
        if (out != null) {
            out[n] = Character.highSurrogate(codePoint);
            out[n + 1] = Character.lowSurrogate(codePoint);
        }
        return 2;
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
        int i = 0;
        while (i < chars.length) {
            char c = chars[i];
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= chars.length || !Character.isLowSurrogate(chars[i + 1])) {
                    throw new MalformedException();
                }
                length += 4;
                i += 2;
                continue;
            }
            if (Character.isLowSurrogate(c)) {
                throw new MalformedException();
            }
            if (c < 0x80) {
                length += 1;
            } else if (c < 0x800) {
                length += 2;
            } else {
                length += 3;
            }
            i++;
        }
        return length;
    }

    /**
     * Encodes {@code chars}, which {@link #encodedLength(char[])} has validated, into {@code out}, which is exactly
     * that long.
     */
    public static void encode(char[] chars, MemorySegment out) {
        long o = 0;
        int i = 0;
        while (i < chars.length) {
            int c = chars[i];
            if (Character.isHighSurrogate(chars[i])) {
                c = Character.toCodePoint(chars[i], chars[i + 1]);
                i += 2;
            } else {
                i++;
            }
            o = encode(c, out, o);
        }
    }

    /** Writes {@code c} as UTF-8 at {@code out[o]}; returns the offset after it. */
    private static long encode(int c, MemorySegment out, long o) {
        if (c < 0x80) {
            put(out, o, c);
            return o + 1;
        }
        if (c < 0x800) {
            put(out, o, 0xC0 | c >> 6);
            put(out, o + 1, 0x80 | c & 0x3F);
            return o + 2;
        }
        if (c < 0x10000) {
            put(out, o, 0xE0 | c >> 12);
            put(out, o + 1, 0x80 | c >> 6 & 0x3F);
            put(out, o + 2, 0x80 | c & 0x3F);
            return o + 3;
        }
        put(out, o, 0xF0 | c >> 18);
        put(out, o + 1, 0x80 | c >> 12 & 0x3F);
        put(out, o + 2, 0x80 | c >> 6 & 0x3F);
        put(out, o + 3, 0x80 | c & 0x3F);
        return o + 4;
    }

    private static void put(MemorySegment out, long index, int b) {
        out.set(ValueLayout.JAVA_BYTE, index, (byte) b);
    }
}
