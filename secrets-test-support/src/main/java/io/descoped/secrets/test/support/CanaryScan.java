package io.descoped.secrets.test.support;

import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Searches a file for copies of a canary: fragments of {@value #FRAGMENT} bytes of every form a copy could take,
 * found in one pass with a rolling hash.
 */
public final class CanaryScan {

    /** The length of the fragments searched for, in bytes. */
    public static final int FRAGMENT = 24;

    private static final long BASE = 1_000_003L;

    /** A fragment and the encoding it comes from. Compared by identity: fragments are only ever looked up by hash. */
    private static final class Pattern {
        private final String encoding;
        private final byte[] bytes;

        Pattern(String encoding, byte[] bytes) {
            this.encoding = encoding;
            this.bytes = bytes;
        }

        String encoding() {
            return encoding;
        }

        byte[] bytes() {
            return bytes;
        }
    }

    /**
     * A copy of the canary in the file.
     *
     * @param encoding the form it was found in: {@code ascii}, {@code utf-16le}, {@code utf-16be}, {@code hex},
     *                 {@code HEX}, {@code base64} or {@code base64url}
     * @param offset   where in the file
     */
    public record Finding(String encoding, long offset) {
    }

    private final Map<Long, List<Pattern>> patterns = new HashMap<>();
    private final long power;

    private CanaryScan(List<Pattern> all) {
        for (Pattern pattern : all) {
            patterns.computeIfAbsent(hash(pattern.bytes(), 0), h -> new ArrayList<>()).add(pattern);
        }
        long p = 1;
        for (int i = 1; i < FRAGMENT; i++) {
            p *= BASE;
        }
        this.power = p;
    }

    /**
     * A scan for {@code canary}, which must be ASCII and at least {@value #FRAGMENT} bytes long.
     *
     * @param canary the canary
     * @return the scan
     */
    public static CanaryScan of(byte[] canary) {
        if (canary.length < FRAGMENT) {
            throw new IllegalArgumentException("The canary is shorter than a fragment");
        }
        List<Pattern> all = new ArrayList<>();
        fragments(all, "ascii", canary, 1);
        String text = new String(canary, StandardCharsets.US_ASCII);
        fragments(all, "utf-16le", text.getBytes(StandardCharsets.UTF_16LE), 2);
        fragments(all, "utf-16be", text.getBytes(StandardCharsets.UTF_16BE), 2);
        String hex = HexFormat.of().formatHex(canary);
        fragments(all, "hex", hex.getBytes(StandardCharsets.US_ASCII), 1);
        fragments(all, "HEX", hex.toUpperCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII), 1);
        for (int k = 0; k < 3; k++) {
            byte[] tail = Arrays.copyOfRange(canary, k, canary.length);
            fragments(all, "base64", trimmed(Base64.getEncoder().withoutPadding().encode(tail)), 1);
            fragments(all, "base64url", trimmed(Base64.getUrlEncoder().withoutPadding().encode(tail)), 1);
        }
        return new CanaryScan(all);
    }

    /** Base64 without its last 4 characters, which depend on what follows the value in a longer payload. */
    private static byte[] trimmed(byte[] encoded) {
        return Arrays.copyOf(encoded, encoded.length - 4);
    }

    /** Fragments from the start, the middle and the end of {@code encoded}, at multiples of {@code unit}. */
    private static void fragments(List<Pattern> all, String encoding, byte[] encoded, int unit) {
        Set<Integer> starts = new LinkedHashSet<>();
        starts.add(0);
        starts.add((encoded.length - FRAGMENT) / 2 / unit * unit);
        starts.add((encoded.length - FRAGMENT) / unit * unit);
        for (int start : starts) {
            all.add(new Pattern(encoding, Arrays.copyOfRange(encoded, start, start + FRAGMENT)));
        }
    }

    /**
     * Searches {@code file}.
     *
     * @param file the file, for example a heap dump
     * @return every copy found, at most one per encoding and offset
     * @throws IOException if the file cannot be read
     */
    public List<Finding> scan(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file)) {
            long size = channel.size();
            List<Finding> findings = new ArrayList<>();
            long start = 0;
            // Mapped in windows that overlap by a fragment, so that no fragment straddles a window unseen.
            long window = 1L << 30;
            while (start < size) {
                long length = Math.min(window, size - start);
                MappedByteBuffer buffer = channel.map(FileChannel.MapMode.READ_ONLY, start, length);
                scan(buffer, start, findings);
                if (start + length >= size) {
                    break;
                }
                start += length - (FRAGMENT - 1);
            }
            return findings;
        }
    }

    private void scan(MappedByteBuffer buffer, long base, List<Finding> findings) {
        int length = buffer.limit();
        if (length < FRAGMENT) {
            return;
        }
        long h = 0;
        for (int i = 0; i < FRAGMENT; i++) {
            h = h * BASE + (buffer.get(i) & 0xFF);
        }
        for (int i = 0; ; i++) {
            check(buffer, i, h, base, findings);
            if (i + FRAGMENT >= length) {
                return;
            }
            h = (h - (buffer.get(i) & 0xFF) * power) * BASE + (buffer.get(i + FRAGMENT) & 0xFF);
        }
    }

    /** Records every fragment whose hash is {@code h} and that is at {@code buffer[i]}. */
    private void check(MappedByteBuffer buffer, int i, long h, long base, List<Finding> findings) {
        List<Pattern> candidates = patterns.get(h);
        if (candidates == null) {
            return;
        }
        for (Pattern pattern : candidates) {
            Finding finding = new Finding(pattern.encoding(), base + i);
            if (matches(buffer, i, pattern.bytes()) && !findings.contains(finding)) {
                findings.add(finding);
            }
        }
    }

    private static boolean matches(MappedByteBuffer buffer, int at, byte[] pattern) {
        for (int k = 0; k < pattern.length; k++) {
            if (buffer.get(at + k) != pattern[k]) {
                return false;
            }
        }
        return true;
    }

    private static long hash(byte[] bytes, int from) {
        long h = 0;
        for (int i = from; i < from + FRAGMENT; i++) {
            h = h * BASE + (bytes[i] & 0xFF);
        }
        return h;
    }
}
